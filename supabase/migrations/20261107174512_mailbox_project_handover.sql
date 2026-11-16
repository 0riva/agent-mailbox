-- Agents of two companies in one shared project pass work to each other (o-core#2142).
--
-- Until now an agent could only reach agents on the same Oriva account (mailbox_peers,
-- mailbox_post). This adds a second, separate path, leaving the first untouched:
--   * a member shares one of their agents into a shared project (a bridge group) for their company,
--     and can withdraw it at any time;
--   * an agent shared into a project can reach the other agents shared into that SAME project, and no
--     agent outside it;
--   * every handover is tagged with its project, and both companies can see the project's activity
--     (who sent which kind of message to whom, and when) — never the message, which stays sealed to
--     the receiving agent exactly as before;
--   * either company can stop all handovers in the project; while any stop stands, nothing crosses.
-- Like the rest of the mailbox, the tables are reachable only through these server functions, which
-- only the service role may call.

-- 1. Tables ---------------------------------------------------------------------------------------
ALTER TABLE mailbox.messages
  ADD COLUMN IF NOT EXISTS bridge_group_id UUID REFERENCES oriva_bridge.bridge_groups (id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_mailbox_messages_bridge_group ON mailbox.messages (bridge_group_id, created_at DESC)
  WHERE bridge_group_id IS NOT NULL;
COMMENT ON COLUMN mailbox.messages.bridge_group_id IS 'The shared project a cross-company handover went through; NULL between agents on one account.';

CREATE TABLE mailbox.project_agents (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  bridge_group_id  UUID NOT NULL REFERENCES oriva_bridge.bridge_groups (id) ON DELETE CASCADE,
  connection_id    UUID NOT NULL REFERENCES mailbox.connections (id) ON DELETE CASCADE,
  organization_id  UUID NOT NULL REFERENCES oriva_bridge.organizations (id) ON DELETE CASCADE,
  shared_by        UUID NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  shared_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  withdrawn_at     TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_mailbox_project_agents_active ON mailbox.project_agents (bridge_group_id, connection_id) WHERE withdrawn_at IS NULL;
CREATE INDEX idx_mailbox_project_agents_connection ON mailbox.project_agents (connection_id);
CREATE INDEX idx_mailbox_project_agents_org ON mailbox.project_agents (organization_id);
CREATE INDEX idx_mailbox_project_agents_shared_by ON mailbox.project_agents (shared_by);
COMMENT ON TABLE mailbox.project_agents IS 'An agent shared into a shared project for one company: it may take work from, and give work to, the other agents shared into that project.';

CREATE TABLE mailbox.project_stops (
  bridge_group_id  UUID NOT NULL REFERENCES oriva_bridge.bridge_groups (id) ON DELETE CASCADE,
  organization_id  UUID NOT NULL REFERENCES oriva_bridge.organizations (id) ON DELETE CASCADE,
  stopped_by       UUID NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  stopped_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (bridge_group_id, organization_id)
);
CREATE INDEX idx_mailbox_project_stops_org ON mailbox.project_stops (organization_id);
CREATE INDEX idx_mailbox_project_stops_stopped_by ON mailbox.project_stops (stopped_by);
COMMENT ON TABLE mailbox.project_stops IS 'A company has stopped all agent handovers in a shared project. While any row stands for a project, nothing crosses.';

ALTER TABLE mailbox.project_agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE mailbox.project_stops  ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON mailbox.project_agents, mailbox.project_stops FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON mailbox.project_agents, mailbox.project_stops TO service_role;

-- 2. Helpers --------------------------------------------------------------------------------------
-- The company an agent is shared into a project for — only while the share stands, the agent is
-- connected, its owner is still in that company, that company is still in the project, and no
-- company has stopped handovers there. NULL otherwise.
CREATE FUNCTION mailbox.project_share_org(p_group UUID, p_connection UUID)
RETURNS UUID LANGUAGE sql STABLE SECURITY INVOKER SET search_path = '' AS $$
  SELECT pa.organization_id
    FROM mailbox.project_agents pa
    JOIN mailbox.connections c ON c.id = pa.connection_id AND c.stopped_at IS NULL
    JOIN oriva_bridge.organization_members om
      ON om.organization_id = pa.organization_id AND om.user_id = c.user_id AND om.deleted_at IS NULL
    JOIN oriva_bridge.organization_group_memberships ogm
      ON ogm.organization_id = pa.organization_id AND ogm.bridge_group_id = pa.bridge_group_id
     AND ogm.status = 'active' AND ogm.deleted_at IS NULL
    JOIN oriva_bridge.organizations o ON o.id = pa.organization_id AND o.deleted_at IS NULL
    JOIN oriva_bridge.bridge_groups g ON g.id = pa.bridge_group_id AND g.deleted_at IS NULL
   WHERE pa.bridge_group_id = p_group AND pa.connection_id = p_connection AND pa.withdrawn_at IS NULL
     -- A stop counts while the company that placed it is still in the project; one that left cannot block it for ever.
     AND NOT EXISTS (SELECT 1 FROM mailbox.project_stops s
                       JOIN oriva_bridge.organization_group_memberships sm
                         ON sm.organization_id = s.organization_id AND sm.bridge_group_id = s.bridge_group_id
                        AND sm.status = 'active' AND sm.deleted_at IS NULL
                      WHERE s.bridge_group_id = p_group)
   LIMIT 1
$$;
REVOKE ALL ON FUNCTION mailbox.project_share_org(UUID, UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION mailbox.project_share_org(UUID, UUID) TO service_role;

-- The companies a person belongs to that are active in a project.
CREATE FUNCTION mailbox.member_orgs_in_project(p_user UUID, p_group UUID)
RETURNS SETOF UUID LANGUAGE sql STABLE SECURITY INVOKER SET search_path = '' AS $$
  SELECT om.organization_id
    FROM oriva_bridge.organization_members om
    JOIN oriva_bridge.organization_group_memberships ogm
      ON ogm.organization_id = om.organization_id AND ogm.bridge_group_id = p_group
     AND ogm.status = 'active' AND ogm.deleted_at IS NULL
    JOIN oriva_bridge.organizations o ON o.id = om.organization_id AND o.deleted_at IS NULL
    JOIN oriva_bridge.bridge_groups g ON g.id = p_group AND g.deleted_at IS NULL
   WHERE om.user_id = p_user AND om.deleted_at IS NULL
$$;
REVOKE ALL ON FUNCTION mailbox.member_orgs_in_project(UUID, UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION mailbox.member_orgs_in_project(UUID, UUID) TO service_role;

-- 3. What an agent can reach across companies -----------------------------------------------------
-- One row per (agent, project): the other agents shared into a project this agent is shared into,
-- on other accounts (agents on the same account are reached through mailbox_peers already).
CREATE FUNCTION public.mailbox_project_peers(p_connection UUID)
RETURNS TABLE (id UUID, role TEXT, agent_name TEXT, public_key TEXT, project_id UUID, project_name TEXT, company_name TEXT)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT p.id, p.role, p.agent_name, encode(p.public_key, 'hex'), g.id, g.name::TEXT, o.name::TEXT
    FROM mailbox.connections me
    JOIN mailbox.project_agents mine ON mine.connection_id = me.id AND mine.withdrawn_at IS NULL
    JOIN mailbox.project_agents theirs ON theirs.bridge_group_id = mine.bridge_group_id AND theirs.withdrawn_at IS NULL
    JOIN mailbox.connections p ON p.id = theirs.connection_id AND p.user_id <> me.user_id
    JOIN oriva_bridge.bridge_groups g ON g.id = mine.bridge_group_id AND g.deleted_at IS NULL
    JOIN oriva_bridge.organizations o ON o.id = theirs.organization_id
   WHERE me.id = p_connection AND me.stopped_at IS NULL
     AND mailbox.project_share_org(mine.bridge_group_id, me.id) IS NOT NULL
     AND mailbox.project_share_org(theirs.bridge_group_id, p.id) IS NOT NULL
   ORDER BY g.name, p.created_at
$$;

-- 4. Handing work across ----------------------------------------------------------------------------
CREATE FUNCTION public.mailbox_post_in_project(
  p_id UUID, p_from UUID, p_to UUID, p_project UUID, p_kind TEXT, p_reply_to UUID,
  p_ephemeral_public_key TEXT, p_nonce TEXT, p_ciphertext TEXT, p_size INTEGER
) RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  v_sender UUID;
  v_receiver UUID;
BEGIN
  SELECT user_id INTO v_sender FROM mailbox.connections WHERE id = p_from AND stopped_at IS NULL;
  SELECT user_id INTO v_receiver FROM mailbox.connections WHERE id = p_to AND stopped_at IS NULL;
  IF v_sender IS NULL OR v_receiver IS NULL OR v_sender = v_receiver THEN
    RAISE EXCEPTION 'project_handover_refused' USING HINT = 'Sender and receiver must be active agents on different accounts.';
  END IF;
  -- Shared against a stop on the same project (mailbox_project_stop takes it exclusively), so a send cannot
  -- slip in while a stop is being placed.
  PERFORM pg_advisory_xact_lock_shared(hashtextextended('mailbox_project:' || p_project::text, 0));
  IF mailbox.project_share_org(p_project, p_from) IS NULL OR mailbox.project_share_org(p_project, p_to) IS NULL THEN
    RAISE EXCEPTION 'project_handover_refused' USING HINT = 'Both agents must be shared into this project, and handovers must not be stopped.';
  END IF;
  -- A reply answers a message the replying agent received, in this same project.
  IF p_reply_to IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM mailbox.messages WHERE id = p_reply_to AND to_connection = p_from AND from_connection = p_to AND bridge_group_id = p_project
  ) THEN
    RAISE EXCEPTION 'reply_to is not a message this agent received in this project';
  END IF;
  -- Another company's account may leave at most 2 MB unread with an agent: it cannot fill the inbox the
  -- agent's own account uses (mailbox_post counts only same-account mail).
  IF (SELECT coalesce(sum(size_bytes), 0) FROM mailbox.messages
       WHERE to_connection = p_to AND read_at IS NULL AND bridge_group_id IS NOT NULL AND user_id = v_sender) + p_size > 2097152 THEN
    RAISE EXCEPTION 'mailbox_full' USING HINT = 'This agent already has 2 MB of unread messages from your account.';
  END IF;
  -- user_id is the SENDER's account: it is what the sender sealed into the message (crypto.ts messageAad).
  INSERT INTO mailbox.messages (id, user_id, from_connection, to_connection, kind, reply_to, ephemeral_public_key, nonce, ciphertext, size_bytes, bridge_group_id)
  VALUES (p_id, v_sender, p_from, p_to, p_kind, p_reply_to, decode(p_ephemeral_public_key, 'hex'), decode(p_nonce, 'hex'),
          decode(p_ciphertext, 'hex'), p_size, p_project);
END;
$$;

-- Messages addressed to an agent. Unchanged for same-account mail. A message that came through a project is
-- delivered only while both agents can still reach each other there: a stop, a withdrawal or a departure holds
-- what is already queued (it is delivered if the project opens again, or expires unread).
CREATE OR REPLACE FUNCTION public.mailbox_inbox(p_connection UUID, p_kinds TEXT[], p_limit INTEGER)
RETURNS TABLE (id UUID, user_id UUID, from_connection UUID, from_name TEXT, kind TEXT, reply_to UUID,
               ephemeral_public_key TEXT, nonce TEXT, ciphertext TEXT, created_at TIMESTAMPTZ)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT m.id, m.user_id, m.from_connection, f.agent_name, m.kind, m.reply_to,
         encode(m.ephemeral_public_key, 'hex'), encode(m.nonce, 'hex'), encode(m.ciphertext, 'hex'), m.created_at
    FROM mailbox.messages m JOIN mailbox.connections f ON f.id = m.from_connection
   WHERE m.to_connection = p_connection AND m.read_at IS NULL
     AND (p_kinds IS NULL OR m.kind = ANY (p_kinds))
     AND (m.bridge_group_id IS NULL
          OR (mailbox.project_share_org(m.bridge_group_id, m.from_connection) IS NOT NULL
              AND mailbox.project_share_org(m.bridge_group_id, m.to_connection) IS NOT NULL))
   ORDER BY m.created_at
   LIMIT least(greatest(p_limit, 1), 50)
$$;

-- The same-account send, unchanged except that mail from other companies no longer counts toward its 20 MB.
CREATE OR REPLACE FUNCTION public.mailbox_post(
  p_id UUID, p_from UUID, p_to UUID, p_kind TEXT, p_reply_to UUID,
  p_ephemeral_public_key TEXT, p_nonce TEXT, p_ciphertext TEXT, p_size INTEGER
) RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  v_user UUID;
BEGIN
  SELECT f.user_id INTO v_user
    FROM mailbox.connections f JOIN mailbox.connections t ON t.user_id = f.user_id
   WHERE f.id = p_from AND t.id = p_to AND f.stopped_at IS NULL AND t.stopped_at IS NULL;
  IF v_user IS NULL THEN RAISE EXCEPTION 'sender and receiver must be active agents on the same account'; END IF;
  IF p_reply_to IS NOT NULL AND NOT EXISTS (SELECT 1 FROM mailbox.messages WHERE id = p_reply_to AND user_id = v_user) THEN
    RAISE EXCEPTION 'reply_to is not a message on this account';
  END IF;
  IF (SELECT coalesce(sum(size_bytes), 0) FROM mailbox.messages WHERE to_connection = p_to AND read_at IS NULL AND bridge_group_id IS NULL) + p_size > 20971520 THEN
    RAISE EXCEPTION 'mailbox_full' USING HINT = 'The receiving agent has 20 MB of unread messages.';
  END IF;
  INSERT INTO mailbox.messages (id, user_id, from_connection, to_connection, kind, reply_to, ephemeral_public_key, nonce, ciphertext, size_bytes)
  VALUES (p_id, v_user, p_from, p_to, p_kind, p_reply_to, decode(p_ephemeral_public_key, 'hex'), decode(p_nonce, 'hex'),
          decode(p_ciphertext, 'hex'), p_size);
END;
$$;

-- 3: where messages addressed to this agent came from — the project, and the sender's company in force
-- when each was sent — so another company's message is labelled from the message, not from today's sharing.
CREATE FUNCTION public.mailbox_message_origins(p_connection UUID, p_ids UUID[])
RETURNS TABLE (id UUID, project_name TEXT, company_name TEXT)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT m.id, g.name::TEXT, o.name::TEXT
    FROM mailbox.messages m
    JOIN oriva_bridge.bridge_groups g ON g.id = m.bridge_group_id
    LEFT JOIN LATERAL (SELECT pa.organization_id FROM mailbox.project_agents pa
                        WHERE pa.connection_id = m.from_connection AND pa.bridge_group_id = m.bridge_group_id AND pa.shared_at <= m.created_at
                        ORDER BY pa.shared_at DESC LIMIT 1) s ON TRUE
    LEFT JOIN oriva_bridge.organizations o ON o.id = s.organization_id
   WHERE m.to_connection = p_connection AND m.id = ANY (p_ids) AND m.bridge_group_id IS NOT NULL
$$;

-- Which project a message addressed to this agent came through (NULL: same account, or not theirs).
CREATE FUNCTION public.mailbox_message_project(p_connection UUID, p_id UUID)
RETURNS UUID LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT m.bridge_group_id FROM mailbox.messages m WHERE m.id = p_id AND m.to_connection = p_connection
$$;

-- 5. What a member sees and does on the project page ------------------------------------------------
-- NULL when the person is not in any company active in the project.
CREATE FUNCTION public.mailbox_project_overview(p_user_id UUID, p_group UUID)
RETURNS JSONB LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM mailbox.member_orgs_in_project(p_user_id, p_group)) THEN NULL ELSE jsonb_build_object(
    'myCompanies', coalesce((SELECT jsonb_agg(jsonb_build_object('id', o.id, 'name', o.name) ORDER BY o.name)
                               FROM oriva_bridge.organizations o WHERE o.id IN (SELECT mailbox.member_orgs_in_project(p_user_id, p_group))), '[]'::jsonb),
    'myAgents', coalesce((SELECT jsonb_agg(jsonb_build_object('id', c.id, 'name', c.agent_name, 'role', c.role,
                              'sharedFor', (SELECT pa.organization_id FROM mailbox.project_agents pa
                                             WHERE pa.connection_id = c.id AND pa.bridge_group_id = p_group AND pa.withdrawn_at IS NULL))
                              ORDER BY c.created_at)
                            FROM mailbox.connections c WHERE c.user_id = p_user_id AND c.stopped_at IS NULL), '[]'::jsonb),
    'shared', coalesce((SELECT jsonb_agg(jsonb_build_object('agentId', c.id, 'agent', c.agent_name, 'role', c.role,
                            'company', o.name, 'companyId', o.id, 'sharedAt', pa.shared_at, 'mine', c.user_id = p_user_id)
                            ORDER BY o.name, c.agent_name)
                          FROM mailbox.project_agents pa
                          JOIN mailbox.connections c ON c.id = pa.connection_id AND c.stopped_at IS NULL
                          JOIN oriva_bridge.organizations o ON o.id = pa.organization_id
                         WHERE pa.bridge_group_id = p_group AND pa.withdrawn_at IS NULL), '[]'::jsonb),
    'stops', coalesce((SELECT jsonb_agg(jsonb_build_object('companyId', o.id, 'company', o.name, 'stoppedAt', s.stopped_at) ORDER BY s.stopped_at)
                         FROM mailbox.project_stops s JOIN oriva_bridge.organizations o ON o.id = s.organization_id
                        WHERE s.bridge_group_id = p_group), '[]'::jsonb),
    'activity', coalesce((SELECT jsonb_agg(row_to_json(a)::jsonb ORDER BY a."sentAt" DESC) FROM (
                            SELECT f.agent_name AS "from", fo.name AS "fromCompany", t.agent_name AS "to", tor.name AS "toCompany",
                                   m.kind, m.created_at AS "sentAt", m.read_at AS "readAt"
                              FROM mailbox.messages m
                              LEFT JOIN mailbox.connections f ON f.id = m.from_connection
                              JOIN mailbox.connections t ON t.id = m.to_connection
                              -- The share in force when the message was sent (an agent can be shared, withdrawn and shared again).
                              LEFT JOIN LATERAL (SELECT pa.organization_id FROM mailbox.project_agents pa
                                                  WHERE pa.connection_id = m.from_connection AND pa.bridge_group_id = p_group AND pa.shared_at <= m.created_at
                                                  ORDER BY pa.shared_at DESC LIMIT 1) fpa ON TRUE
                              LEFT JOIN oriva_bridge.organizations fo ON fo.id = fpa.organization_id
                              LEFT JOIN LATERAL (SELECT pa.organization_id FROM mailbox.project_agents pa
                                                  WHERE pa.connection_id = m.to_connection AND pa.bridge_group_id = p_group AND pa.shared_at <= m.created_at
                                                  ORDER BY pa.shared_at DESC LIMIT 1) tpa ON TRUE
                              LEFT JOIN oriva_bridge.organizations tor ON tor.id = tpa.organization_id
                             WHERE m.bridge_group_id = p_group
                             ORDER BY m.created_at DESC LIMIT 100) a), '[]'::jsonb)
  ) END
$$;

-- Share one of your agents into a project for one of your companies in it.
CREATE FUNCTION public.mailbox_share_agent(p_user_id UUID, p_connection UUID, p_group UUID, p_org UUID)
RETURNS TEXT LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM mailbox.connections WHERE id = p_connection AND user_id = p_user_id AND stopped_at IS NULL) THEN
    RETURN 'not_your_agent';
  END IF;
  IF p_org NOT IN (SELECT mailbox.member_orgs_in_project(p_user_id, p_group)) THEN
    RETURN 'not_in_project';
  END IF;
  IF EXISTS (SELECT 1 FROM mailbox.project_agents WHERE bridge_group_id = p_group AND connection_id = p_connection AND withdrawn_at IS NULL) THEN
    RETURN 'already_shared';
  END IF;
  BEGIN
    INSERT INTO mailbox.project_agents (bridge_group_id, connection_id, organization_id, shared_by)
    VALUES (p_group, p_connection, p_org, p_user_id);
  EXCEPTION WHEN unique_violation THEN
    RETURN 'already_shared';  -- a second click that landed at the same moment
  END;
  RETURN 'shared';
END;
$$;

-- Withdraw one of your agents from a project. Anything it was sent and has not read stays sealed to it.
CREATE FUNCTION public.mailbox_withdraw_agent(p_user_id UUID, p_connection UUID, p_group UUID)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  v_count INTEGER;
BEGIN
  UPDATE mailbox.project_agents pa SET withdrawn_at = now()
    FROM mailbox.connections c
   WHERE pa.connection_id = c.id AND c.user_id = p_user_id
     AND pa.connection_id = p_connection AND pa.bridge_group_id = p_group AND pa.withdrawn_at IS NULL;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count = 1;
END;
$$;

-- Stop (or resume) all agent handovers in a project, for one of your companies in it.
CREATE FUNCTION public.mailbox_project_stop(p_user_id UUID, p_group UUID, p_org UUID, p_stop BOOLEAN)
RETURNS TEXT LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  IF p_org NOT IN (SELECT mailbox.member_orgs_in_project(p_user_id, p_group)) THEN
    RETURN 'not_in_project';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('mailbox_project:' || p_group::text, 0));
  IF p_stop THEN
    INSERT INTO mailbox.project_stops (bridge_group_id, organization_id, stopped_by)
    VALUES (p_group, p_org, p_user_id) ON CONFLICT DO NOTHING;
    RETURN 'stopped';
  END IF;
  DELETE FROM mailbox.project_stops WHERE bridge_group_id = p_group AND organization_id = p_org;
  RETURN 'resumed';
END;
$$;

-- 6. Only the server may call any of this --------------------------------------------------------------
DO $$
DECLARE f TEXT;
BEGIN
  FOREACH f IN ARRAY ARRAY[
    'public.mailbox_project_peers(uuid)',
    'public.mailbox_post_in_project(uuid, uuid, uuid, uuid, text, uuid, text, text, text, integer)',
    'public.mailbox_message_project(uuid, uuid)',
    'public.mailbox_message_origins(uuid, uuid[])',
    'public.mailbox_inbox(uuid, text[], integer)',
    'public.mailbox_post(uuid, uuid, uuid, text, uuid, text, text, text, integer)',
    'public.mailbox_project_overview(uuid, uuid)',
    'public.mailbox_share_agent(uuid, uuid, uuid, uuid)',
    'public.mailbox_withdraw_agent(uuid, uuid, uuid)',
    'public.mailbox_project_stop(uuid, uuid, uuid, boolean)'
  ] LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC, anon, authenticated', f);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role', f);
  END LOOP;
END $$;

NOTIFY pgrst, 'reload schema';
