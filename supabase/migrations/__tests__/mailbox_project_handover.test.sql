-- Contract test for 20261107174512_mailbox_project_handover.sql (o-core#2142).
-- Runs in one rolled-back transaction via scripts/test-mailbox-project-handover.mjs, which places
-- the mailbox migrations and this one at the marker.

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

CREATE TEMP TABLE ph_results (name text PRIMARY KEY, ok boolean);
CREATE TEMP TABLE ph_scratch (k text PRIMARY KEY, v text);

-- Acme (A, A2), Bolt (B) and Crow (C). Project G: Acme + Bolt. Project H: Acme + Crow.
INSERT INTO auth.users (id, instance_id, aud, role, email, created_at, updated_at) VALUES
  ('02142000-0000-4000-8000-00000000000a', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'a@acme.example', now(), now()),
  ('02142000-0000-4000-8000-0000000000a2', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'a2@acme.example', now(), now()),
  ('02142000-0000-4000-8000-00000000000b', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'b@bolt.example', now(), now()),
  ('02142000-0000-4000-8000-00000000000c', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'c@crow.example', now(), now());
INSERT INTO oriva_bridge.organizations (id, name, slug) VALUES
  ('02142000-0000-4000-8000-0000000000f1', 'Acme', 'test-2142-acme'),
  ('02142000-0000-4000-8000-0000000000f2', 'Bolt', 'test-2142-bolt'),
  ('02142000-0000-4000-8000-0000000000f3', 'Crow', 'test-2142-crow');
INSERT INTO oriva_bridge.organization_members (organization_id, user_id, role) VALUES
  ('02142000-0000-4000-8000-0000000000f1', '02142000-0000-4000-8000-00000000000a', 'owner'),
  ('02142000-0000-4000-8000-0000000000f1', '02142000-0000-4000-8000-0000000000a2', 'member'),
  ('02142000-0000-4000-8000-0000000000f2', '02142000-0000-4000-8000-00000000000b', 'owner'),
  ('02142000-0000-4000-8000-0000000000f3', '02142000-0000-4000-8000-00000000000c', 'owner');
INSERT INTO oriva_bridge.bridge_groups (id, name, created_by_org_id, created_by_user_id) VALUES
  ('02142000-0000-4000-8000-0000000000e1', 'Spring launch', '02142000-0000-4000-8000-0000000000f1', '02142000-0000-4000-8000-00000000000a'),
  ('02142000-0000-4000-8000-0000000000e2', 'Crow audit', '02142000-0000-4000-8000-0000000000f1', '02142000-0000-4000-8000-00000000000a');
INSERT INTO oriva_bridge.organization_group_memberships (organization_id, bridge_group_id, role, status, joined_at) VALUES
  ('02142000-0000-4000-8000-0000000000f1', '02142000-0000-4000-8000-0000000000e1', 'owner', 'active', now()),
  ('02142000-0000-4000-8000-0000000000f2', '02142000-0000-4000-8000-0000000000e1', 'participant', 'active', now()),
  ('02142000-0000-4000-8000-0000000000f1', '02142000-0000-4000-8000-0000000000e2', 'owner', 'active', now()),
  ('02142000-0000-4000-8000-0000000000f3', '02142000-0000-4000-8000-0000000000e2', 'participant', 'active', now());

INSERT INTO mailbox.clients (client_id, client_name, redirect_uris) VALUES ('test-2142', 'Claude', ARRAY['https://claude.ai/api/mcp/auth_callback']);
INSERT INTO mailbox.connections (id, user_id, client_id, agent_name, role, public_key) VALUES
  ('02142000-0000-4000-8000-0000000000c1', '02142000-0000-4000-8000-00000000000a', 'test-2142', 'Acme planner', 'dispatcher', decode(repeat('11', 32), 'hex')),
  ('02142000-0000-4000-8000-0000000000c2', '02142000-0000-4000-8000-00000000000a', 'test-2142', 'Acme helper', 'worker', decode(repeat('12', 32), 'hex')),
  ('02142000-0000-4000-8000-0000000000c3', '02142000-0000-4000-8000-00000000000b', 'test-2142', 'Bolt builder', 'worker', decode(repeat('13', 32), 'hex')),
  ('02142000-0000-4000-8000-0000000000c4', '02142000-0000-4000-8000-00000000000c', 'test-2142', 'Crow checker', 'worker', decode(repeat('14', 32), 'hex'));

-- t1: sharing — your own agent, for a company of yours that is in the project.
INSERT INTO ph_results SELECT 't1_share_own_agent',
  public.mailbox_share_agent('02142000-0000-4000-8000-00000000000a', '02142000-0000-4000-8000-0000000000c1', '02142000-0000-4000-8000-0000000000e1', '02142000-0000-4000-8000-0000000000f1') = 'shared'
  AND public.mailbox_share_agent('02142000-0000-4000-8000-00000000000b', '02142000-0000-4000-8000-0000000000c3', '02142000-0000-4000-8000-0000000000e1', '02142000-0000-4000-8000-0000000000f2') = 'shared'
  AND public.mailbox_share_agent('02142000-0000-4000-8000-00000000000c', '02142000-0000-4000-8000-0000000000c4', '02142000-0000-4000-8000-0000000000e2', '02142000-0000-4000-8000-0000000000f3') = 'shared';
INSERT INTO ph_results SELECT 't1b_share_refusals',
  public.mailbox_share_agent('02142000-0000-4000-8000-00000000000a', '02142000-0000-4000-8000-0000000000c3', '02142000-0000-4000-8000-0000000000e1', '02142000-0000-4000-8000-0000000000f1') = 'not_your_agent'
  AND public.mailbox_share_agent('02142000-0000-4000-8000-00000000000c', '02142000-0000-4000-8000-0000000000c4', '02142000-0000-4000-8000-0000000000e1', '02142000-0000-4000-8000-0000000000f3') = 'not_in_project'
  AND public.mailbox_share_agent('02142000-0000-4000-8000-00000000000a', '02142000-0000-4000-8000-0000000000c1', '02142000-0000-4000-8000-0000000000e1', '02142000-0000-4000-8000-0000000000f3') = 'not_in_project'
  AND public.mailbox_share_agent('02142000-0000-4000-8000-00000000000a', '02142000-0000-4000-8000-0000000000c1', '02142000-0000-4000-8000-0000000000e1', '02142000-0000-4000-8000-0000000000f1') = 'already_shared';

-- t2: Acme's agent reaches Bolt's agent in the shared project — and nobody in a project it is not shared into.
INSERT INTO ph_results SELECT 't2_peer_in_shared_project',
  (SELECT count(*) = 1 AND bool_and(id = '02142000-0000-4000-8000-0000000000c3' AND project_name = 'Spring launch' AND company_name = 'Bolt')
     FROM public.mailbox_project_peers('02142000-0000-4000-8000-0000000000c1'));
INSERT INTO ph_results SELECT 't2b_peer_symmetry',
  (SELECT count(*) = 1 AND bool_and(id = '02142000-0000-4000-8000-0000000000c1' AND company_name = 'Acme')
     FROM public.mailbox_project_peers('02142000-0000-4000-8000-0000000000c3'));
INSERT INTO ph_results SELECT 't2c_unshared_agent_reaches_nobody',
  NOT EXISTS (SELECT 1 FROM public.mailbox_project_peers('02142000-0000-4000-8000-0000000000c2'))
  AND NOT EXISTS (SELECT 1 FROM public.mailbox_project_peers('02142000-0000-4000-8000-0000000000c4'));

-- t3: a task crosses inside the project, tagged with it and with the sender's account.
SELECT public.mailbox_post_in_project('02142000-0000-4000-8000-0000000000d1', '02142000-0000-4000-8000-0000000000c1', '02142000-0000-4000-8000-0000000000c3',
  '02142000-0000-4000-8000-0000000000e1', 'task', NULL, repeat('aa', 32), repeat('bb', 12), repeat('cc', 40), 24);
INSERT INTO ph_results SELECT 't3_task_crosses_in_project',
  (SELECT bridge_group_id = '02142000-0000-4000-8000-0000000000e1' AND user_id = '02142000-0000-4000-8000-00000000000a' AND to_connection = '02142000-0000-4000-8000-0000000000c3'
     FROM mailbox.messages WHERE id = '02142000-0000-4000-8000-0000000000d1')
  AND public.mailbox_message_project('02142000-0000-4000-8000-0000000000c3', '02142000-0000-4000-8000-0000000000d1') = '02142000-0000-4000-8000-0000000000e1'
  AND public.mailbox_message_project('02142000-0000-4000-8000-0000000000c4', '02142000-0000-4000-8000-0000000000d1') IS NULL;

-- t4: no crossing outside the project: to an agent not shared there, through a project the sender is not shared into, or within one account.
CREATE FUNCTION pg_temp.refused(p_from uuid, p_to uuid, p_group uuid, p_reply uuid DEFAULT NULL) RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
  PERFORM public.mailbox_post_in_project(gen_random_uuid(), p_from, p_to, p_group, CASE WHEN p_reply IS NULL THEN 'task' ELSE 'result' END, p_reply,
    repeat('aa', 32), repeat('bb', 12), repeat('cc', 40), 24);
  RETURN false;
EXCEPTION WHEN raise_exception THEN
  RETURN true;
END $$;
INSERT INTO ph_results SELECT 't4_no_crossing_outside_project',
  pg_temp.refused('02142000-0000-4000-8000-0000000000c1', '02142000-0000-4000-8000-0000000000c4', '02142000-0000-4000-8000-0000000000e1')
  AND pg_temp.refused('02142000-0000-4000-8000-0000000000c1', '02142000-0000-4000-8000-0000000000c4', '02142000-0000-4000-8000-0000000000e2')
  AND pg_temp.refused('02142000-0000-4000-8000-0000000000c1', '02142000-0000-4000-8000-0000000000c2', '02142000-0000-4000-8000-0000000000e1');

-- t5: the worker answers the task it received, in the same project; a made-up reply is refused.
SELECT public.mailbox_post_in_project('02142000-0000-4000-8000-0000000000d2', '02142000-0000-4000-8000-0000000000c3', '02142000-0000-4000-8000-0000000000c1',
  '02142000-0000-4000-8000-0000000000e1', 'result', '02142000-0000-4000-8000-0000000000d1', repeat('aa', 32), repeat('bb', 12), repeat('cc', 40), 24);
INSERT INTO ph_results SELECT 't5_reply_in_project',
  EXISTS (SELECT 1 FROM mailbox.messages WHERE id = '02142000-0000-4000-8000-0000000000d2' AND reply_to = '02142000-0000-4000-8000-0000000000d1' AND user_id = '02142000-0000-4000-8000-00000000000b')
  AND pg_temp.refused('02142000-0000-4000-8000-0000000000c3', '02142000-0000-4000-8000-0000000000c1', '02142000-0000-4000-8000-0000000000e1', gen_random_uuid())
  AND pg_temp.refused('02142000-0000-4000-8000-0000000000c1', '02142000-0000-4000-8000-0000000000c3', '02142000-0000-4000-8000-0000000000e1', '02142000-0000-4000-8000-0000000000d1');

-- t6: both companies see the handover on the project page — who, which company, which kind — and an outsider sees nothing.
INSERT INTO ph_scratch SELECT 'acme', public.mailbox_project_overview('02142000-0000-4000-8000-0000000000a2', '02142000-0000-4000-8000-0000000000e1')::text;
INSERT INTO ph_scratch SELECT 'bolt', public.mailbox_project_overview('02142000-0000-4000-8000-00000000000b', '02142000-0000-4000-8000-0000000000e1')::text;
INSERT INTO ph_results SELECT 't6_both_companies_see_activity',
  (SELECT bool_and(jsonb_array_length(v::jsonb -> 'activity') = 2
                   AND EXISTS (SELECT 1 FROM jsonb_array_elements(v::jsonb -> 'activity') e
                                WHERE e ->> 'from' = 'Acme planner' AND e ->> 'fromCompany' = 'Acme' AND e ->> 'to' = 'Bolt builder' AND e ->> 'toCompany' = 'Bolt' AND e ->> 'kind' = 'task')
                   AND jsonb_array_length(v::jsonb -> 'shared') = 2)
     FROM ph_scratch WHERE k IN ('acme', 'bolt'))
  AND public.mailbox_project_overview('02142000-0000-4000-8000-00000000000c', '02142000-0000-4000-8000-0000000000e1') IS NULL;
INSERT INTO ph_results SELECT 't6b_activity_never_carries_the_message',
  (SELECT NOT (v LIKE '%ciphertext%' OR v LIKE '%cccccc%') FROM ph_scratch WHERE k = 'acme');

-- t7: either company stops all handovers; nothing crosses until that company resumes.
-- (A mutating call and the checks on its effect go in separate statements: one statement shares one snapshot.)
INSERT INTO ph_scratch SELECT 'stop', public.mailbox_project_stop('02142000-0000-4000-8000-00000000000b', '02142000-0000-4000-8000-0000000000e1', '02142000-0000-4000-8000-0000000000f2', true);
INSERT INTO ph_results SELECT 't7_stop_blocks_everything',
  (SELECT v = 'stopped' FROM ph_scratch WHERE k = 'stop')
  AND NOT EXISTS (SELECT 1 FROM public.mailbox_project_peers('02142000-0000-4000-8000-0000000000c1'))
  AND pg_temp.refused('02142000-0000-4000-8000-0000000000c1', '02142000-0000-4000-8000-0000000000c3', '02142000-0000-4000-8000-0000000000e1');
INSERT INTO ph_results SELECT 't7b_outsider_cannot_stop_or_resume',
  public.mailbox_project_stop('02142000-0000-4000-8000-00000000000c', '02142000-0000-4000-8000-0000000000e1', '02142000-0000-4000-8000-0000000000f2', false) = 'not_in_project'
  AND public.mailbox_project_stop('02142000-0000-4000-8000-00000000000c', '02142000-0000-4000-8000-0000000000e1', '02142000-0000-4000-8000-0000000000f3', true) = 'not_in_project'
  AND EXISTS (SELECT 1 FROM mailbox.project_stops WHERE bridge_group_id = '02142000-0000-4000-8000-0000000000e1');
INSERT INTO ph_scratch SELECT 'resume', public.mailbox_project_stop('02142000-0000-4000-8000-00000000000b', '02142000-0000-4000-8000-0000000000e1', '02142000-0000-4000-8000-0000000000f2', false);
INSERT INTO ph_results SELECT 't7c_resume_reopens',
  (SELECT v = 'resumed' FROM ph_scratch WHERE k = 'resume')
  AND EXISTS (SELECT 1 FROM public.mailbox_project_peers('02142000-0000-4000-8000-0000000000c1'));

-- t8: a company that leaves the project, or a person who leaves their company, takes their agent out of reach.
UPDATE oriva_bridge.organization_group_memberships SET status = 'suspended'
 WHERE organization_id = '02142000-0000-4000-8000-0000000000f2' AND bridge_group_id = '02142000-0000-4000-8000-0000000000e1';
INSERT INTO ph_results SELECT 't8_company_out_of_project',
  NOT EXISTS (SELECT 1 FROM public.mailbox_project_peers('02142000-0000-4000-8000-0000000000c1'))
  AND pg_temp.refused('02142000-0000-4000-8000-0000000000c1', '02142000-0000-4000-8000-0000000000c3', '02142000-0000-4000-8000-0000000000e1');
UPDATE oriva_bridge.organization_group_memberships SET status = 'active'
 WHERE organization_id = '02142000-0000-4000-8000-0000000000f2' AND bridge_group_id = '02142000-0000-4000-8000-0000000000e1';
UPDATE oriva_bridge.organization_members SET deleted_at = now()
 WHERE organization_id = '02142000-0000-4000-8000-0000000000f2' AND user_id = '02142000-0000-4000-8000-00000000000b';
INSERT INTO ph_results SELECT 't8b_person_out_of_company',
  NOT EXISTS (SELECT 1 FROM public.mailbox_project_peers('02142000-0000-4000-8000-0000000000c1'));
UPDATE oriva_bridge.organization_members SET deleted_at = NULL
 WHERE organization_id = '02142000-0000-4000-8000-0000000000f2' AND user_id = '02142000-0000-4000-8000-00000000000b';

-- t9: withdrawing an agent takes it out of reach; only its owner can withdraw it.
INSERT INTO ph_scratch SELECT 'withdraw_other', public.mailbox_withdraw_agent('02142000-0000-4000-8000-00000000000a', '02142000-0000-4000-8000-0000000000c3', '02142000-0000-4000-8000-0000000000e1')::text;
INSERT INTO ph_scratch SELECT 'withdraw_own', public.mailbox_withdraw_agent('02142000-0000-4000-8000-00000000000b', '02142000-0000-4000-8000-0000000000c3', '02142000-0000-4000-8000-0000000000e1')::text;
INSERT INTO ph_results SELECT 't9_withdraw',
  (SELECT v = 'false' FROM ph_scratch WHERE k = 'withdraw_other')
  AND (SELECT v = 'true' FROM ph_scratch WHERE k = 'withdraw_own')
  AND NOT EXISTS (SELECT 1 FROM public.mailbox_project_peers('02142000-0000-4000-8000-0000000000c1'))
  AND pg_temp.refused('02142000-0000-4000-8000-0000000000c1', '02142000-0000-4000-8000-0000000000c3', '02142000-0000-4000-8000-0000000000e1');

-- t10: a stopped agent is out of reach and cannot send.
UPDATE mailbox.connections SET stopped_at = now() WHERE id = '02142000-0000-4000-8000-0000000000c4';
INSERT INTO ph_results SELECT 't10_stopped_agent_out_of_reach',
  public.mailbox_share_agent('02142000-0000-4000-8000-00000000000c', '02142000-0000-4000-8000-0000000000c4', '02142000-0000-4000-8000-0000000000e2', '02142000-0000-4000-8000-0000000000f3') = 'not_your_agent';

-- t11: only the server can call any of it, and no browser role can read the new tables.
INSERT INTO ph_results SELECT 't11_server_only',
  (SELECT bool_and(NOT has_function_privilege('anon', f, 'EXECUTE') AND NOT has_function_privilege('authenticated', f, 'EXECUTE') AND has_function_privilege('service_role', f, 'EXECUTE'))
     FROM unnest(ARRAY[
       'public.mailbox_project_peers(uuid)', 'public.mailbox_post_in_project(uuid, uuid, uuid, uuid, text, uuid, text, text, text, integer)',
       'public.mailbox_message_project(uuid, uuid)', 'public.mailbox_project_overview(uuid, uuid)', 'public.mailbox_share_agent(uuid, uuid, uuid, uuid)',
       'public.mailbox_withdraw_agent(uuid, uuid, uuid)', 'public.mailbox_project_stop(uuid, uuid, uuid, boolean)']) f)
  AND NOT has_table_privilege('authenticated', 'mailbox.project_agents', 'SELECT')
  AND NOT has_table_privilege('anon', 'mailbox.project_stops', 'SELECT');

-- Review fixes (o-core#2142). Bolt's builder is shared again for what follows.
SELECT public.mailbox_share_agent('02142000-0000-4000-8000-00000000000b', '02142000-0000-4000-8000-0000000000c3', '02142000-0000-4000-8000-0000000000e1', '02142000-0000-4000-8000-0000000000f2');
SELECT public.mailbox_post_in_project('02142000-0000-4000-8000-0000000000d3', '02142000-0000-4000-8000-0000000000c1', '02142000-0000-4000-8000-0000000000c3',
  '02142000-0000-4000-8000-0000000000e1', 'task', NULL, repeat('aa', 32), repeat('bb', 12), repeat('cc', 40), 24);

-- t12: a stop holds mail already queued; resuming releases it.
SELECT public.mailbox_project_stop('02142000-0000-4000-8000-00000000000b', '02142000-0000-4000-8000-0000000000e1', '02142000-0000-4000-8000-0000000000f2', true);
INSERT INTO ph_results SELECT 't12_stop_holds_queued_mail',
  NOT EXISTS (SELECT 1 FROM public.mailbox_inbox('02142000-0000-4000-8000-0000000000c3', NULL, 50) WHERE id = '02142000-0000-4000-8000-0000000000d3');
SELECT public.mailbox_project_stop('02142000-0000-4000-8000-00000000000b', '02142000-0000-4000-8000-0000000000e1', '02142000-0000-4000-8000-0000000000f2', false);
INSERT INTO ph_results SELECT 't12b_resume_releases_it',
  EXISTS (SELECT 1 FROM public.mailbox_inbox('02142000-0000-4000-8000-0000000000c3', NULL, 50) WHERE id = '02142000-0000-4000-8000-0000000000d3');

-- t13: a message's project and sending company come from the message, even after the sender is withdrawn.
SELECT public.mailbox_withdraw_agent('02142000-0000-4000-8000-00000000000a', '02142000-0000-4000-8000-0000000000c1', '02142000-0000-4000-8000-0000000000e1');
INSERT INTO ph_results SELECT 't13_origin_from_the_message',
  (SELECT project_name = 'Spring launch' AND company_name = 'Acme'
     FROM public.mailbox_message_origins('02142000-0000-4000-8000-0000000000c3', ARRAY['02142000-0000-4000-8000-0000000000d3'::uuid]))
  AND NOT EXISTS (SELECT 1 FROM public.mailbox_message_origins('02142000-0000-4000-8000-0000000000c4', ARRAY['02142000-0000-4000-8000-0000000000d3'::uuid]));
SELECT public.mailbox_share_agent('02142000-0000-4000-8000-00000000000a', '02142000-0000-4000-8000-0000000000c1', '02142000-0000-4000-8000-0000000000e1', '02142000-0000-4000-8000-0000000000f1');

-- t14: one company's account may leave at most 2 MB unread with another company's agent.
INSERT INTO mailbox.messages (id, user_id, from_connection, to_connection, kind, ephemeral_public_key, nonce, ciphertext, size_bytes, bridge_group_id)
SELECT gen_random_uuid(), '02142000-0000-4000-8000-00000000000a', '02142000-0000-4000-8000-0000000000c1', '02142000-0000-4000-8000-0000000000c3', 'note',
       decode(repeat('aa', 32), 'hex'), decode(repeat('bb', 12), 'hex'), decode(repeat('00', 204816), 'hex'), 204800, '02142000-0000-4000-8000-0000000000e1'
  FROM generate_series(1, 10);
CREATE FUNCTION pg_temp.big_refused() RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
  PERFORM public.mailbox_post_in_project(gen_random_uuid(), '02142000-0000-4000-8000-0000000000c1', '02142000-0000-4000-8000-0000000000c3',
    '02142000-0000-4000-8000-0000000000e1', 'note', NULL, repeat('aa', 32), repeat('bb', 12), repeat('00', 100016), 100000);
  RETURN false;
EXCEPTION WHEN raise_exception THEN
  RETURN SQLERRM = 'mailbox_full';
END $$;
INSERT INTO ph_results SELECT 't14b_cap_refuses_over_2mb', pg_temp.big_refused();
DELETE FROM mailbox.messages WHERE size_bytes = 204800;

-- t15: a deleted project reaches nobody, and nothing can be shared or stopped in it.
UPDATE oriva_bridge.bridge_groups SET deleted_at = now() WHERE id = '02142000-0000-4000-8000-0000000000e1';
INSERT INTO ph_results SELECT 't15_deleted_project',
  NOT EXISTS (SELECT 1 FROM public.mailbox_project_peers('02142000-0000-4000-8000-0000000000c1'))
  AND public.mailbox_project_stop('02142000-0000-4000-8000-00000000000b', '02142000-0000-4000-8000-0000000000e1', '02142000-0000-4000-8000-0000000000f2', true) = 'not_in_project'
  AND public.mailbox_project_overview('02142000-0000-4000-8000-00000000000a', '02142000-0000-4000-8000-0000000000e1') IS NULL;
UPDATE oriva_bridge.bridge_groups SET deleted_at = NULL WHERE id = '02142000-0000-4000-8000-0000000000e1';

-- t16: a stop by a company that has since left the project no longer blocks the others.
INSERT INTO auth.users (id, instance_id, aud, role, email, created_at, updated_at) VALUES
  ('02142000-0000-4000-8000-00000000000d', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'd@dove.example', now(), now());
INSERT INTO oriva_bridge.organizations (id, name, slug) VALUES ('02142000-0000-4000-8000-0000000000f4', 'Dove', 'test-2142-dove');
INSERT INTO oriva_bridge.organization_members (organization_id, user_id, role) VALUES ('02142000-0000-4000-8000-0000000000f4', '02142000-0000-4000-8000-00000000000d', 'owner');
INSERT INTO oriva_bridge.organization_group_memberships (organization_id, bridge_group_id, role, status, joined_at) VALUES ('02142000-0000-4000-8000-0000000000f4', '02142000-0000-4000-8000-0000000000e1', 'participant', 'active', now());
SELECT public.mailbox_project_stop('02142000-0000-4000-8000-00000000000d', '02142000-0000-4000-8000-0000000000e1', '02142000-0000-4000-8000-0000000000f4', true);
INSERT INTO ph_results SELECT 't16_stop_holds_while_its_company_is_in',
  NOT EXISTS (SELECT 1 FROM public.mailbox_project_peers('02142000-0000-4000-8000-0000000000c1'));
UPDATE oriva_bridge.organization_group_memberships SET deleted_at = now() WHERE organization_id = '02142000-0000-4000-8000-0000000000f4';
INSERT INTO ph_results SELECT 't16b_stop_lapses_when_its_company_leaves',
  EXISTS (SELECT 1 FROM public.mailbox_project_peers('02142000-0000-4000-8000-0000000000c1'));

-- t17: a reply must answer the agent that sent the message; the same-account send is unaffected by project mail.
-- Acme's planner received d2 from Bolt's builder; answering it to a DIFFERENT Bolt agent is refused.
INSERT INTO mailbox.connections (id, user_id, client_id, agent_name, role, public_key) VALUES
  ('02142000-0000-4000-8000-0000000000c5', '02142000-0000-4000-8000-00000000000b', 'test-2142', 'Bolt lead', 'dispatcher', decode(repeat('15', 32), 'hex'));
SELECT public.mailbox_share_agent('02142000-0000-4000-8000-00000000000b', '02142000-0000-4000-8000-0000000000c5', '02142000-0000-4000-8000-0000000000e1', '02142000-0000-4000-8000-0000000000f2');
INSERT INTO ph_results SELECT 't17_reply_goes_to_the_sender',
  pg_temp.refused('02142000-0000-4000-8000-0000000000c1', '02142000-0000-4000-8000-0000000000c5', '02142000-0000-4000-8000-0000000000e1', '02142000-0000-4000-8000-0000000000d2');
SELECT public.mailbox_post('02142000-0000-4000-8000-0000000000d4', '02142000-0000-4000-8000-0000000000c1', '02142000-0000-4000-8000-0000000000c2',
  'task', NULL, repeat('aa', 32), repeat('bb', 12), repeat('cc', 40), 24);
INSERT INTO ph_results SELECT 't17b_same_account_send_unchanged',
  EXISTS (SELECT 1 FROM mailbox.messages WHERE id = '02142000-0000-4000-8000-0000000000d4' AND bridge_group_id IS NULL AND user_id = '02142000-0000-4000-8000-00000000000a');

SELECT name || '=' || coalesce(ok, false)::text FROM ph_results ORDER BY name;
