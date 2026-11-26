-- Background tasks for the agent mailbox (o-core#2367).
--
-- An assistant that supports the MCP Tasks extension gives work with post_task and then follows the
-- task itself (tasks/get), instead of having to remember to call read_replies. A task is the existing
-- `task` message; its outcome is the `result` message that replies to it. Nothing new is stored except
-- when the dispatcher withdraws a task (tasks/cancel).
--
-- Every function here is server-only (service_role), like the rest of the mailbox: anon and
-- authenticated have no EXECUTE, so a browser can never call them.

-- When the agent that gave a task withdrew it. A withdrawn task is never delivered to a worker that has
-- not fetched it yet, and a worker that already has it cannot send a result for it.
ALTER TABLE mailbox.messages ADD COLUMN withdrawn_at TIMESTAMPTZ;

-- Messages addressed to an agent: as 20261107174512_mailbox_project_handover.sql, plus withdrawn tasks are skipped.
CREATE OR REPLACE FUNCTION public.mailbox_inbox(p_connection UUID, p_kinds TEXT[], p_limit INTEGER)
RETURNS TABLE (id UUID, user_id UUID, from_connection UUID, from_name TEXT, kind TEXT, reply_to UUID,
               ephemeral_public_key TEXT, nonce TEXT, ciphertext TEXT, created_at TIMESTAMPTZ)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT m.id, m.user_id, m.from_connection, f.agent_name, m.kind, m.reply_to,
         encode(m.ephemeral_public_key, 'hex'), encode(m.nonce, 'hex'), encode(m.ciphertext, 'hex'), m.created_at
    FROM mailbox.messages m JOIN mailbox.connections f ON f.id = m.from_connection
   WHERE m.to_connection = p_connection AND m.read_at IS NULL AND m.withdrawn_at IS NULL
     AND (p_kinds IS NULL OR m.kind = ANY (p_kinds))
     AND (m.bridge_group_id IS NULL
          OR (mailbox.project_share_org(m.bridge_group_id, m.from_connection) IS NOT NULL
              AND mailbox.project_share_org(m.bridge_group_id, m.to_connection) IS NOT NULL))
   ORDER BY m.created_at
   LIMIT least(greatest(p_limit, 1), 50)
$$;

-- Where a task this agent gave has got to: when it was given and expires, whether the worker has fetched
-- it, whether it was withdrawn, whether its worker has since been disconnected (so it can never be
-- answered), whether a shared project is holding it back, and the worker's sealed result once one has
-- arrived. Nothing for a task this agent did not give (or any message that is not a task), so one agent
-- can never read another's. A result that came through a shared project is held exactly as the inbox
-- holds it. A task withdrawn before it was fetched is marked read at the same instant (see
-- mailbox_withdraw_task), so `fetched_at` reports a fetch only when the read came first.
CREATE FUNCTION public.mailbox_task_state(p_connection UUID, p_task UUID)
RETURNS TABLE (created_at TIMESTAMPTZ, delete_after TIMESTAMPTZ, fetched_at TIMESTAMPTZ, withdrawn_at TIMESTAMPTZ,
               worker_stopped BOOLEAN, held BOOLEAN,
               result_id UUID, result_user_id UUID, result_from UUID, result_from_name TEXT,
               result_ephemeral_public_key TEXT, result_nonce TEXT, result_ciphertext TEXT, result_created_at TIMESTAMPTZ)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT t.created_at, t.delete_after,
         CASE WHEN t.withdrawn_at IS NULL OR t.read_at < t.withdrawn_at THEN t.read_at END,
         t.withdrawn_at,
         w.stopped_at IS NOT NULL,
         t.bridge_group_id IS NOT NULL
           AND (mailbox.project_share_org(t.bridge_group_id, t.from_connection) IS NULL
                OR mailbox.project_share_org(t.bridge_group_id, t.to_connection) IS NULL),
         r.id, r.user_id, r.from_connection, f.agent_name,
         encode(r.ephemeral_public_key, 'hex'), encode(r.nonce, 'hex'), encode(r.ciphertext, 'hex'), r.created_at
    FROM mailbox.messages t
    JOIN mailbox.connections w ON w.id = t.to_connection
    LEFT JOIN LATERAL (
      SELECT x.* FROM mailbox.messages x
       WHERE x.reply_to = t.id AND x.kind = 'result' AND x.to_connection = p_connection
         AND (x.bridge_group_id IS NULL
              OR (mailbox.project_share_org(x.bridge_group_id, x.from_connection) IS NOT NULL
                  AND mailbox.project_share_org(x.bridge_group_id, x.to_connection) IS NOT NULL))
       ORDER BY x.created_at
       LIMIT 1
    ) r ON true
    LEFT JOIN mailbox.connections f ON f.id = r.from_connection
   WHERE t.id = p_task AND t.from_connection = p_connection AND t.kind = 'task'
$$;

-- Withdraw a task this agent gave. 'withdrawn' (now or earlier), 'answered' when a result already arrived
-- (too late: the task stays answered), or 'not_found' for a task this agent did not give.
-- The task row is locked first, and the trigger below locks the same row before a result is stored, so a
-- withdrawal and a result can never both succeed. A task the worker has not fetched is also marked read,
-- so it stops counting toward the worker's unread limit and is purged with read mail.
CREATE FUNCTION public.mailbox_withdraw_task(p_connection UUID, p_task UUID)
RETURNS TEXT LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  v_found BOOLEAN;
BEGIN
  SELECT true INTO v_found FROM mailbox.messages
   WHERE id = p_task AND from_connection = p_connection AND kind = 'task' FOR UPDATE;
  IF v_found IS NULL THEN
    RETURN 'not_found';
  END IF;
  IF EXISTS (SELECT 1 FROM mailbox.messages WHERE reply_to = p_task AND kind = 'result') THEN
    RETURN 'answered';
  END IF;
  UPDATE mailbox.messages
     SET withdrawn_at = coalesce(withdrawn_at, now()), read_at = coalesce(read_at, now())
   WHERE id = p_task AND from_connection = p_connection AND kind = 'task';
  RETURN 'withdrawn';
END;
$$;

-- Whether a task addressed to this agent was withdrawn by the agent that gave it. False for anything
-- not addressed to this agent.
CREATE FUNCTION public.mailbox_task_withdrawn(p_connection UUID, p_task UUID)
RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT coalesce((SELECT m.withdrawn_at IS NOT NULL FROM mailbox.messages m
                    WHERE m.id = p_task AND m.to_connection = p_connection AND m.kind = 'task'), false)
$$;

-- No result is stored for a withdrawn task, whichever send function stores it. The task row is locked
-- for share, so this waits for a withdrawal in progress and then sees it.
CREATE FUNCTION mailbox.refuse_result_to_withdrawn_task()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = '' AS $$
DECLARE
  v_withdrawn TIMESTAMPTZ;
BEGIN
  SELECT withdrawn_at INTO v_withdrawn FROM mailbox.messages WHERE id = NEW.reply_to FOR SHARE;
  IF v_withdrawn IS NOT NULL THEN
    RAISE EXCEPTION 'task_withdrawn' USING ERRCODE = 'P0001';
  END IF;
  RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION mailbox.refuse_result_to_withdrawn_task() FROM PUBLIC, anon, authenticated;
CREATE TRIGGER messages_refuse_result_to_withdrawn_task
  BEFORE INSERT ON mailbox.messages
  FOR EACH ROW WHEN (NEW.kind = 'result' AND NEW.reply_to IS NOT NULL)
  EXECUTE FUNCTION mailbox.refuse_result_to_withdrawn_task();

DO $$
DECLARE f TEXT;
BEGIN
  FOREACH f IN ARRAY ARRAY[
    'mailbox_inbox(uuid, text[], integer)', 'mailbox_task_state(uuid, uuid)',
    'mailbox_withdraw_task(uuid, uuid)', 'mailbox_task_withdrawn(uuid, uuid)'
  ] LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION public.%s FROM PUBLIC, anon, authenticated', f);
    EXECUTE format('GRANT EXECUTE ON FUNCTION public.%s TO service_role', f);
  END LOOP;
END $$;
