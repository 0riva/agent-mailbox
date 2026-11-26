-- Contract test for 20261126000328_mailbox_tasks.sql (o-core#2367).
-- Runs in one rolled-back transaction via scripts/test-mailbox-tasks.mjs, which places the mailbox
-- migrations and this one at the marker.

DROP SCHEMA IF EXISTS mailbox CASCADE;
DO $$
DECLARE f regprocedure;
BEGIN
  FOR f IN SELECT p.oid::regprocedure FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'public' AND p.proname LIKE 'mailbox\_%' LOOP
    EXECUTE format('DROP FUNCTION %s', f);
  END LOOP;
END $$;

--@@MIGRATION@@

CREATE TEMP TABLE tk_results (name text PRIMARY KEY, ok boolean);  -- NULL reports as false

-- One account: a dispatcher (c1), a worker (c2) and a second dispatcher (c4) that must not see c1's tasks.
INSERT INTO auth.users (id, instance_id, aud, role, email, created_at, updated_at) VALUES
  ('02367000-0000-4000-8000-00000000000a', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'tasks-a@example.invalid', now(), now());
INSERT INTO mailbox.clients (client_id, client_name, redirect_uris) VALUES ('test-2367', 'Test', ARRAY['https://example.org/cb']);
INSERT INTO mailbox.connections (id, user_id, client_id, agent_name, role, public_key) VALUES
  ('02367000-0000-4000-8000-0000000000c1', '02367000-0000-4000-8000-00000000000a', 'test-2367', 'Claude', 'dispatcher', decode(repeat('11', 32), 'hex')),
  ('02367000-0000-4000-8000-0000000000c2', '02367000-0000-4000-8000-00000000000a', 'test-2367', 'Grok Bot', 'worker', decode(repeat('12', 32), 'hex')),
  ('02367000-0000-4000-8000-0000000000c4', '02367000-0000-4000-8000-00000000000a', 'test-2367', 'Other lead', 'dispatcher', decode(repeat('14', 32), 'hex'));

CREATE FUNCTION pg_temp.post(p_id UUID, p_from UUID, p_to UUID, p_kind TEXT, p_reply UUID) RETURNS VOID LANGUAGE sql AS $$
  SELECT public.mailbox_post(p_id, p_from, p_to, p_kind, p_reply, repeat('aa', 32), repeat('bb', 12), repeat('cc', 40), 24)
$$;

-- d1: a task from Claude to Grok Bot.
SELECT pg_temp.post('02367000-0000-4000-8000-0000000000d1', '02367000-0000-4000-8000-0000000000c1', '02367000-0000-4000-8000-0000000000c2', 'task', NULL);

INSERT INTO tk_results SELECT 't1_giver_sees_a_waiting_task',
  (SELECT count(*) = 1 AND bool_and(result_id IS NULL AND fetched_at IS NULL AND withdrawn_at IS NULL AND delete_after > created_at)
     FROM public.mailbox_task_state('02367000-0000-4000-8000-0000000000c1', '02367000-0000-4000-8000-0000000000d1'));
INSERT INTO tk_results SELECT 't2_another_agent_sees_nothing',
  NOT EXISTS (SELECT 1 FROM public.mailbox_task_state('02367000-0000-4000-8000-0000000000c4', '02367000-0000-4000-8000-0000000000d1'));
INSERT INTO tk_results SELECT 't3_the_worker_cannot_read_it_as_a_giver',
  NOT EXISTS (SELECT 1 FROM public.mailbox_task_state('02367000-0000-4000-8000-0000000000c2', '02367000-0000-4000-8000-0000000000d1'));

-- The worker fetches d1 and answers it with d2.
SELECT public.mailbox_mark_read('02367000-0000-4000-8000-0000000000c2', ARRAY['02367000-0000-4000-8000-0000000000d1']::uuid[]);
INSERT INTO tk_results SELECT 't4_fetch_is_seen',
  (SELECT fetched_at IS NOT NULL AND result_id IS NULL
     FROM public.mailbox_task_state('02367000-0000-4000-8000-0000000000c1', '02367000-0000-4000-8000-0000000000d1'));
SELECT pg_temp.post('02367000-0000-4000-8000-0000000000d2', '02367000-0000-4000-8000-0000000000c2', '02367000-0000-4000-8000-0000000000c1', 'result', '02367000-0000-4000-8000-0000000000d1');
INSERT INTO tk_results SELECT 't5_result_arrives_sealed',
  (SELECT result_id = '02367000-0000-4000-8000-0000000000d2' AND result_from = '02367000-0000-4000-8000-0000000000c2'
          AND result_from_name = 'Grok Bot' AND result_ciphertext = repeat('cc', 40) AND result_nonce = repeat('bb', 12)
     FROM public.mailbox_task_state('02367000-0000-4000-8000-0000000000c1', '02367000-0000-4000-8000-0000000000d1'));
INSERT INTO tk_results SELECT 't6_too_late_to_withdraw_an_answered_task',
  public.mailbox_withdraw_task('02367000-0000-4000-8000-0000000000c1', '02367000-0000-4000-8000-0000000000d1') = 'answered'
  AND (SELECT withdrawn_at IS NULL FROM mailbox.messages WHERE id = '02367000-0000-4000-8000-0000000000d1');

-- d3: a task withdrawn before Grok Bot fetches it.
SELECT pg_temp.post('02367000-0000-4000-8000-0000000000d3', '02367000-0000-4000-8000-0000000000c1', '02367000-0000-4000-8000-0000000000c2', 'task', NULL);
INSERT INTO tk_results SELECT 't7_withdraw_by_another_agent_refused',
  public.mailbox_withdraw_task('02367000-0000-4000-8000-0000000000c4', '02367000-0000-4000-8000-0000000000d3') = 'not_found'
  AND (SELECT withdrawn_at IS NULL FROM mailbox.messages WHERE id = '02367000-0000-4000-8000-0000000000d3');
INSERT INTO tk_results SELECT 't8_withdraw_unknown_task_not_found',
  public.mailbox_withdraw_task('02367000-0000-4000-8000-0000000000c1', '02367000-0000-4000-8000-0000000000ff') = 'not_found';
INSERT INTO tk_results SELECT 't9_withdraw_succeeds',
  public.mailbox_withdraw_task('02367000-0000-4000-8000-0000000000c1', '02367000-0000-4000-8000-0000000000d3') = 'withdrawn';
INSERT INTO tk_results SELECT 't10_withdrawn_task_never_delivered',
  NOT EXISTS (SELECT 1 FROM public.mailbox_inbox('02367000-0000-4000-8000-0000000000c2', ARRAY['task'], 50)
               WHERE id = '02367000-0000-4000-8000-0000000000d3');
INSERT INTO tk_results SELECT 't11_giver_sees_it_withdrawn',
  (SELECT withdrawn_at IS NOT NULL AND result_id IS NULL
     FROM public.mailbox_task_state('02367000-0000-4000-8000-0000000000c1', '02367000-0000-4000-8000-0000000000d3'));
INSERT INTO tk_results SELECT 't12_worker_is_told_it_was_withdrawn',
  public.mailbox_task_withdrawn('02367000-0000-4000-8000-0000000000c2', '02367000-0000-4000-8000-0000000000d3')
  AND NOT public.mailbox_task_withdrawn('02367000-0000-4000-8000-0000000000c2', '02367000-0000-4000-8000-0000000000d1')
  AND NOT public.mailbox_task_withdrawn('02367000-0000-4000-8000-0000000000c4', '02367000-0000-4000-8000-0000000000d3');

-- Withdrawing twice keeps the first moment.
CREATE TEMP TABLE tk_first AS SELECT withdrawn_at FROM mailbox.messages WHERE id = '02367000-0000-4000-8000-0000000000d3';
SELECT pg_sleep(0.01);
INSERT INTO tk_results SELECT 't13_withdraw_is_idempotent',
  public.mailbox_withdraw_task('02367000-0000-4000-8000-0000000000c1', '02367000-0000-4000-8000-0000000000d3') = 'withdrawn'
  AND (SELECT m.withdrawn_at = f.withdrawn_at FROM mailbox.messages m, tk_first f WHERE m.id = '02367000-0000-4000-8000-0000000000d3');

-- d4: an ordinary unread task still arrives (the inbox change only skips withdrawn ones).
SELECT pg_temp.post('02367000-0000-4000-8000-0000000000d4', '02367000-0000-4000-8000-0000000000c1', '02367000-0000-4000-8000-0000000000c2', 'task', NULL);
INSERT INTO tk_results SELECT 't14_ordinary_task_still_delivered',
  EXISTS (SELECT 1 FROM public.mailbox_inbox('02367000-0000-4000-8000-0000000000c2', ARRAY['task'], 50)
           WHERE id = '02367000-0000-4000-8000-0000000000d4');

-- The browser roles can call none of it.
INSERT INTO tk_results SELECT 't15_server_only',
  NOT has_function_privilege('anon', 'public.mailbox_task_state(uuid, uuid)', 'EXECUTE')
  AND NOT has_function_privilege('authenticated', 'public.mailbox_task_state(uuid, uuid)', 'EXECUTE')
  AND NOT has_function_privilege('anon', 'public.mailbox_withdraw_task(uuid, uuid)', 'EXECUTE')
  AND NOT has_function_privilege('authenticated', 'public.mailbox_withdraw_task(uuid, uuid)', 'EXECUTE')
  AND NOT has_function_privilege('anon', 'public.mailbox_task_withdrawn(uuid, uuid)', 'EXECUTE')
  AND NOT has_function_privilege('authenticated', 'public.mailbox_task_withdrawn(uuid, uuid)', 'EXECUTE')
  AND NOT has_function_privilege('authenticated', 'public.mailbox_inbox(uuid, text[], integer)', 'EXECUTE')
  AND has_function_privilege('service_role', 'public.mailbox_task_state(uuid, uuid)', 'EXECUTE')
  AND has_function_privilege('service_role', 'public.mailbox_withdraw_task(uuid, uuid)', 'EXECUTE');

-- A result to a withdrawn task is refused in the database, whichever path sends it (the race the app check cannot close).
CREATE FUNCTION pg_temp.result_refused(p_id UUID, p_task UUID) RETURNS BOOLEAN LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_temp.post(p_id, '02367000-0000-4000-8000-0000000000c2', '02367000-0000-4000-8000-0000000000c1', 'result', p_task);
  RETURN false;
EXCEPTION WHEN others THEN
  RETURN SQLERRM LIKE '%task_withdrawn%';
END;
$$;
-- Sibling subqueries share one snapshot, so each send runs in its own statement and its effect is read in the next.
CREATE TEMP TABLE tk_sends AS SELECT
  pg_temp.result_refused('02367000-0000-4000-8000-0000000000e9', '02367000-0000-4000-8000-0000000000d3') AS withdrawn_refused;
ALTER TABLE tk_sends ADD COLUMN live_refused BOOLEAN;
UPDATE tk_sends SET live_refused = pg_temp.result_refused('02367000-0000-4000-8000-0000000000ea', '02367000-0000-4000-8000-0000000000d4');
INSERT INTO tk_results SELECT 't16_result_to_withdrawn_task_refused',
  (SELECT withdrawn_refused FROM tk_sends)
  AND NOT EXISTS (SELECT 1 FROM mailbox.messages WHERE id = '02367000-0000-4000-8000-0000000000e9');
INSERT INTO tk_results SELECT 't16b_result_to_live_task_still_stored',
  (SELECT NOT live_refused FROM tk_sends)
  AND EXISTS (SELECT 1 FROM mailbox.messages WHERE id = '02367000-0000-4000-8000-0000000000ea');

-- A task withdrawn before it was fetched stops counting toward the worker's unread limit, and is not reported as fetched.
INSERT INTO tk_results SELECT 't17_withdrawn_unfetched_task_frees_the_limit',
  (SELECT read_at IS NOT NULL AND read_at = withdrawn_at AND delete_after <= read_at + interval '7 days'
     FROM mailbox.messages WHERE id = '02367000-0000-4000-8000-0000000000d3')
  AND (SELECT fetched_at IS NULL FROM public.mailbox_task_state('02367000-0000-4000-8000-0000000000c1', '02367000-0000-4000-8000-0000000000d3'));

-- d7: a task whose worker is then disconnected can never be answered.
SELECT pg_temp.post('02367000-0000-4000-8000-0000000000d7', '02367000-0000-4000-8000-0000000000c1', '02367000-0000-4000-8000-0000000000c2', 'task', NULL);
INSERT INTO tk_results SELECT 't18a_live_worker_not_stopped',
  (SELECT NOT worker_stopped AND NOT held FROM public.mailbox_task_state('02367000-0000-4000-8000-0000000000c1', '02367000-0000-4000-8000-0000000000d7'));
SELECT public.mailbox_stop('02367000-0000-4000-8000-00000000000a', '02367000-0000-4000-8000-0000000000c2');
INSERT INTO tk_results SELECT 't18_disconnected_worker_is_reported',
  (SELECT worker_stopped FROM public.mailbox_task_state('02367000-0000-4000-8000-0000000000c1', '02367000-0000-4000-8000-0000000000d7'));

-- d8: a task to another company's agent in a shared project is held while a company has stopped handovers there.
INSERT INTO auth.users (id, instance_id, aud, role, email, created_at, updated_at) VALUES
  ('02367000-0000-4000-8000-00000000000b', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'tasks-b@example.invalid', now(), now());
INSERT INTO oriva_bridge.organizations (id, name, slug) VALUES
  ('02367000-0000-4000-8000-0000000000f1', 'Acme', 'test-2367-acme'),
  ('02367000-0000-4000-8000-0000000000f2', 'Bolt', 'test-2367-bolt');
INSERT INTO oriva_bridge.organization_members (organization_id, user_id, role) VALUES
  ('02367000-0000-4000-8000-0000000000f1', '02367000-0000-4000-8000-00000000000a', 'owner'),
  ('02367000-0000-4000-8000-0000000000f2', '02367000-0000-4000-8000-00000000000b', 'owner');
INSERT INTO oriva_bridge.bridge_groups (id, name, created_by_org_id, created_by_user_id) VALUES
  ('02367000-0000-4000-8000-0000000000e1', 'Spring launch', '02367000-0000-4000-8000-0000000000f1', '02367000-0000-4000-8000-00000000000a');
INSERT INTO oriva_bridge.organization_group_memberships (organization_id, bridge_group_id, role, status, joined_at) VALUES
  ('02367000-0000-4000-8000-0000000000f1', '02367000-0000-4000-8000-0000000000e1', 'owner', 'active', now()),
  ('02367000-0000-4000-8000-0000000000f2', '02367000-0000-4000-8000-0000000000e1', 'participant', 'active', now());
INSERT INTO mailbox.connections (id, user_id, client_id, agent_name, role, public_key) VALUES
  ('02367000-0000-4000-8000-0000000000c5', '02367000-0000-4000-8000-00000000000b', 'test-2367', 'Bolt builder', 'worker', decode(repeat('15', 32), 'hex'));
SELECT public.mailbox_share_agent('02367000-0000-4000-8000-00000000000a', '02367000-0000-4000-8000-0000000000c1', '02367000-0000-4000-8000-0000000000e1', '02367000-0000-4000-8000-0000000000f1');
SELECT public.mailbox_share_agent('02367000-0000-4000-8000-00000000000b', '02367000-0000-4000-8000-0000000000c5', '02367000-0000-4000-8000-0000000000e1', '02367000-0000-4000-8000-0000000000f2');
SELECT public.mailbox_post_in_project('02367000-0000-4000-8000-0000000000d8', '02367000-0000-4000-8000-0000000000c1', '02367000-0000-4000-8000-0000000000c5',
  '02367000-0000-4000-8000-0000000000e1', 'task', NULL, repeat('aa', 32), repeat('bb', 12), repeat('cc', 40), 24);
INSERT INTO tk_results SELECT 't19a_open_project_not_held',
  (SELECT NOT held FROM public.mailbox_task_state('02367000-0000-4000-8000-0000000000c1', '02367000-0000-4000-8000-0000000000d8'));
SELECT public.mailbox_project_stop('02367000-0000-4000-8000-00000000000b', '02367000-0000-4000-8000-0000000000e1', '02367000-0000-4000-8000-0000000000f2', true);
INSERT INTO tk_results SELECT 't19_stopped_project_holds_the_task',
  (SELECT held FROM public.mailbox_task_state('02367000-0000-4000-8000-0000000000c1', '02367000-0000-4000-8000-0000000000d8'));

SELECT name || '=' || coalesce(ok, false)::text FROM tk_results ORDER BY name;
