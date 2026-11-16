-- Contract test for 20261023201527_agent_mailbox.sql + 20261023202708_agent_mailbox_tighten.sql (o-core#2069).
-- Runs in one rolled-back transaction via scripts/test-agent-mailbox.mjs, which seals a real
-- message with apps/web/lib/mailbox/crypto.ts and passes the bytes in as psql variables.

-- The migrations create their objects without IF NOT EXISTS, so remove any copy already applied to
-- this database (a local run, a rebuilt database) first. All inside the rolled-back transaction.
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

CREATE TEMP TABLE mb_results (name text PRIMARY KEY, ok boolean);  -- NULL reports as false
GRANT ALL ON mb_results TO anon, authenticated, service_role;

-- One client account with a dispatcher (Claude) and a worker (Grok Bot).
INSERT INTO auth.users (id, instance_id, aud, role, email, created_at, updated_at) VALUES
  ('02069000-0000-4000-8000-00000000000a', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'mailbox-a@example.invalid', now(), now()),
  ('02069000-0000-4000-8000-00000000000b', '00000000-0000-0000-0000-000000000000', 'authenticated', 'authenticated', 'mailbox-b@example.invalid', now(), now());

INSERT INTO mailbox.clients (client_id, client_name, redirect_uris) VALUES
  ('test-claude', 'Claude', ARRAY['https://claude.ai/api/mcp/auth_callback']),
  ('test-grok', 'Grok Bot', ARRAY['https://example.org/callback']);

INSERT INTO mailbox.connections (id, user_id, client_id, agent_name, role, public_key, wrapped_private_key, wrapped_private_key_refresh, access_token_hash, refresh_token_hash, access_expires_at) VALUES
  ('02069000-0000-4000-8000-0000000000c1', '02069000-0000-4000-8000-00000000000a', 'test-claude', 'Claude', 'dispatcher',
   decode(:'dispatcher_pub', 'hex'), decode(:'dispatcher_wrapped', 'hex'), decode(:'dispatcher_wrapped_refresh', 'hex'), decode(:'dispatcher_access_hash', 'hex'), decode(:'dispatcher_refresh_hash', 'hex'), now() + interval '1 hour'),
  ('02069000-0000-4000-8000-0000000000c2', '02069000-0000-4000-8000-00000000000a', 'test-grok', 'Grok Bot', 'worker',
   decode(:'worker_pub', 'hex'), decode(:'worker_wrapped', 'hex'), decode(:'worker_wrapped_refresh', 'hex'), decode(:'worker_access_hash', 'hex'), decode(:'worker_refresh_hash', 'hex'), now() + interval '1 hour');
-- A third agent that has been stopped: no keys, no tokens.
INSERT INTO mailbox.connections (id, user_id, client_id, agent_name, role, public_key, stopped_at) VALUES
  ('02069000-0000-4000-8000-0000000000c3', '02069000-0000-4000-8000-00000000000a', 'test-grok', 'Old bot', 'worker', decode(:'worker_pub', 'hex'), now());

-- A task from Claude to Grok Bot, sealed to Grok Bot's public key by the real library.
INSERT INTO mailbox.messages (id, user_id, from_connection, to_connection, kind, ephemeral_public_key, nonce, ciphertext, size_bytes) VALUES
  (:'message_id', '02069000-0000-4000-8000-00000000000a', '02069000-0000-4000-8000-0000000000c1', '02069000-0000-4000-8000-0000000000c2', 'task',
   decode(:'eph_pub', 'hex'), decode(:'nonce', 'hex'), decode(:'ciphertext', 'hex'), :'size_bytes'::int);

-- t1: the stored message is not plain text — the marker appears nowhere in the row.
INSERT INTO mb_results SELECT 't1_ciphertext_holds_no_plaintext',
  (SELECT position(convert_to(:'marker', 'UTF8') IN ciphertext) = 0
      AND position(convert_to(:'marker', 'UTF8') IN ephemeral_public_key || nonce) = 0
     FROM mailbox.messages WHERE id = :'message_id');

-- t2: no column anywhere in the schema stores a private key or a token in the clear: every
-- secret-bearing column is the wrapped key or a 32-byte hash.
INSERT INTO mb_results SELECT 't2_no_secret_in_the_clear',
  NOT EXISTS (SELECT 1 FROM mailbox.connections
               WHERE position(decode(:'worker_private', 'hex') IN coalesce(wrapped_private_key, ''::bytea) || coalesce(wrapped_private_key_refresh, ''::bytea)) > 0
                  OR position(convert_to(:'worker_refresh', 'UTF8') IN coalesce(access_token_hash, ''::bytea) || coalesce(refresh_token_hash, ''::bytea)) > 0
                  OR position(convert_to(:'worker_access', 'UTF8') IN coalesce(access_token_hash, ''::bytea) || coalesce(refresh_token_hash, ''::bytea)) > 0
                  OR position(decode(:'dispatcher_private', 'hex') IN coalesce(wrapped_private_key, ''::bytea)) > 0);

-- t3: the message body columns are binary, never text a query could read as words.
INSERT INTO mb_results SELECT 't3_body_columns_are_binary',
  (SELECT bool_and(data_type = 'bytea') FROM information_schema.columns
    WHERE table_schema = 'mailbox' AND table_name = 'messages'
      AND column_name IN ('ciphertext', 'nonce', 'ephemeral_public_key'))
  AND NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = 'mailbox' AND data_type IN ('text', 'character varying', 'jsonb', 'json')
                     AND column_name NOT IN ('client_id', 'client_name', 'redirect_uris', 'role', 'redirect_uri', 'code_challenge', 'agent_name', 'kind', 'key'));

-- t4: members and visitors have no way in — no table privilege, no schema usage.
INSERT INTO mb_results SELECT 't4_only_the_server_can_reach_it',
  NOT EXISTS (SELECT 1 FROM pg_tables t, (VALUES ('anon'), ('authenticated')) r(role)
               WHERE t.schemaname = 'mailbox'
                 AND (has_table_privilege(r.role, format('mailbox.%I', t.tablename), 'SELECT')
                   OR has_table_privilege(r.role, format('mailbox.%I', t.tablename), 'INSERT')
                   OR has_table_privilege(r.role, format('mailbox.%I', t.tablename), 'UPDATE')
                   OR has_table_privilege(r.role, format('mailbox.%I', t.tablename), 'DELETE')))
  AND NOT has_schema_privilege('anon', 'mailbox', 'USAGE')
  AND NOT has_schema_privilege('authenticated', 'mailbox', 'USAGE')
  AND has_table_privilege('service_role', 'mailbox.messages', 'SELECT')
  AND NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace, (VALUES ('anon'), ('authenticated')) r(role)
                   WHERE n.nspname = 'mailbox' AND has_function_privilege(r.role, p.oid, 'EXECUTE'));

-- t5: row-level security is on for every table, so a grant added by mistake still reads nothing.
INSERT INTO mb_results SELECT 't5_rls_on_everywhere',
  (SELECT bool_and(c.relrowsecurity) AND count(*) = 6
     FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'mailbox' AND c.relkind = 'r');

-- t6: a signed-in member cannot read the mailbox, even their own.
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claims', '{"sub":"02069000-0000-4000-8000-00000000000a","role":"authenticated"}', true);
DO $$
BEGIN
  PERFORM 1 FROM mailbox.messages;
  INSERT INTO mb_results VALUES ('t6_member_cannot_read', false);
EXCEPTION WHEN insufficient_privilege THEN
  INSERT INTO mb_results VALUES ('t6_member_cannot_read', true);
END $$;
RESET ROLE;

-- t7: roles are only the two the design allows.
DO $$
BEGIN
  UPDATE mailbox.connections SET role = 'admin' WHERE id = '02069000-0000-4000-8000-0000000000c2';
  INSERT INTO mb_results VALUES ('t7_role_is_constrained', false);
EXCEPTION WHEN check_violation THEN
  INSERT INTO mb_results VALUES ('t7_role_is_constrained', true);
END $$;

-- t8: a stopped connection must have lost its key and tokens.
DO $$
BEGIN
  UPDATE mailbox.connections SET stopped_at = now() WHERE id = '02069000-0000-4000-8000-0000000000c2';
  INSERT INTO mb_results VALUES ('t8_stop_requires_key_gone', false);
EXCEPTION WHEN check_violation THEN
  INSERT INTO mb_results VALUES ('t8_stop_requires_key_gone', true);
END $$;

-- t20: purge drops a registration nobody connected within 7 days, and keeps one in use.
INSERT INTO mailbox.clients (client_id, client_name, redirect_uris, created_at) VALUES ('test-stale', 'Stale', ARRAY['https://example.org/cb'], now() - interval '8 days');
UPDATE mailbox.clients SET created_at = now() - interval '8 days' WHERE client_id = 'test-claude';
CREATE TEMP TABLE mb_purge20 AS SELECT mailbox.purge();
INSERT INTO mb_results SELECT 't20_purge_unused_clients',
  NOT EXISTS (SELECT 1 FROM mailbox.clients WHERE client_id = 'test-stale')
  AND EXISTS (SELECT 1 FROM mailbox.clients WHERE client_id = 'test-claude');

-- t9: purge removes only what is past its delete_after.
INSERT INTO mailbox.messages (id, user_id, from_connection, to_connection, kind, ephemeral_public_key, nonce, ciphertext, size_bytes, read_at, delete_after) VALUES
  (gen_random_uuid(), '02069000-0000-4000-8000-00000000000a', '02069000-0000-4000-8000-0000000000c2', '02069000-0000-4000-8000-0000000000c1', 'result',
   decode(:'eph_pub', 'hex'), decode(:'nonce', 'hex'), decode(:'ciphertext', 'hex'), :'size_bytes'::int, now() - interval '8 days', now() - interval '1 day');
-- purge runs in its own statement: sibling subqueries share one snapshot and would not see its deletes.
CREATE TEMP TABLE mb_purged AS SELECT mailbox.purge() AS n;
INSERT INTO mb_results SELECT 't9_purge_removes_only_expired',
  (SELECT n FROM mb_purged) = 1
  AND EXISTS (SELECT 1 FROM mailbox.messages WHERE id = :'message_id')
  AND (SELECT count(*) FROM mailbox.messages WHERE user_id = '02069000-0000-4000-8000-00000000000a') = 1;

-- t10: the rate limit allows up to the limit, then refuses.
INSERT INTO mb_results SELECT 't10_rate_limit_counts',
  (SELECT bool_and(ok) FROM (SELECT mailbox.hit_rate_limit('02069000-0000-4000-8000-0000000000c1', 3) AS ok FROM generate_series(1, 3)) s)
  AND NOT mailbox.hit_rate_limit('02069000-0000-4000-8000-0000000000c1', 3);

-- t12: reading a message brings its deletion forward to 7 days after it was read.
UPDATE mailbox.messages SET read_at = now() WHERE id = :'message_id';
INSERT INTO mb_results SELECT 't12_read_message_deleted_within_7_days',
  (SELECT delete_after <= read_at + interval '7 days' AND delete_after < created_at + interval '30 days'
     FROM mailbox.messages WHERE id = :'message_id');

-- t13: nothing can be queued for (or from) a stopped agent.
DO $$
BEGIN
  INSERT INTO mailbox.messages (id, user_id, from_connection, to_connection, kind, ephemeral_public_key, nonce, ciphertext, size_bytes)
  SELECT gen_random_uuid(), user_id, from_connection, '02069000-0000-4000-8000-0000000000c3', kind, ephemeral_public_key, nonce, ciphertext, size_bytes
    FROM mailbox.messages WHERE kind = 'task' LIMIT 1;
  INSERT INTO mb_results VALUES ('t13_stopped_agent_gets_nothing', false);
EXCEPTION WHEN check_violation THEN
  INSERT INTO mb_results VALUES ('t13_stopped_agent_gets_nothing', true);
END $$;

-- t14: the recorded size must match the ciphertext.
DO $$
BEGIN
  INSERT INTO mailbox.messages (id, user_id, from_connection, to_connection, kind, ephemeral_public_key, nonce, ciphertext, size_bytes)
  SELECT gen_random_uuid(), user_id, from_connection, to_connection, kind, ephemeral_public_key, nonce, ciphertext, size_bytes + 1
    FROM mailbox.messages WHERE kind = 'task' LIMIT 1;
  INSERT INTO mb_results VALUES ('t14_size_matches_ciphertext', false);
EXCEPTION WHEN check_violation THEN
  INSERT INTO mb_results VALUES ('t14_size_matches_ciphertext', true);
END $$;

-- t15: sign-in return addresses are https, or http only on a loopback address.
DO $$
BEGIN
  INSERT INTO mailbox.clients (client_id, client_name, redirect_uris) VALUES ('test-loopback', 'Local', ARRAY['http://127.0.0.1:18787/callback', 'http://localhost:8787/cb']);
  BEGIN
    INSERT INTO mailbox.clients (client_id, client_name, redirect_uris) VALUES ('test-evil', 'Claude', ARRAY['https://ok.example', 'http://evil.example/cb']);
    INSERT INTO mb_results VALUES ('t15_redirects_https_or_loopback', false);
  EXCEPTION WHEN check_violation THEN
    INSERT INTO mb_results VALUES ('t15_redirects_https_or_loopback', true);
  END;
EXCEPTION WHEN check_violation THEN
  INSERT INTO mb_results VALUES ('t15_redirects_https_or_loopback', false);
END $$;

-- t17: the server's own role can do the whole write path the app needs — register a client,
-- connect an agent, queue a message, mark it read — not only the superuser this suite runs as.
SET LOCAL ROLE service_role;
DO $$
BEGIN
  INSERT INTO mailbox.clients (client_id, client_name, redirect_uris) VALUES ('test-service', 'Svc', ARRAY['https://example.org/cb']);
  INSERT INTO mailbox.connections (id, user_id, client_id, agent_name, role, public_key)
    SELECT '02069000-0000-4000-8000-0000000000c4', user_id, 'test-service', 'Svc agent', 'worker', public_key
      FROM mailbox.connections WHERE id = '02069000-0000-4000-8000-0000000000c2';
  INSERT INTO mailbox.messages (id, user_id, from_connection, to_connection, kind, ephemeral_public_key, nonce, ciphertext, size_bytes)
    SELECT gen_random_uuid(), user_id, from_connection, '02069000-0000-4000-8000-0000000000c4', kind, ephemeral_public_key, nonce, ciphertext, size_bytes
      FROM mailbox.messages WHERE kind = 'task' LIMIT 1;
  UPDATE mailbox.messages SET read_at = now() WHERE to_connection = '02069000-0000-4000-8000-0000000000c4';
  PERFORM mailbox.hit_rate_limit('02069000-0000-4000-8000-0000000000c4', 60);
  PERFORM mailbox.purge();
  INSERT INTO mb_results VALUES ('t17_service_role_write_path', true);
EXCEPTION WHEN OTHERS THEN
  RAISE WARNING 't17 failed: %', SQLERRM;
  INSERT INTO mb_results VALUES ('t17_service_role_write_path', false);
END $$;
RESET ROLE;

-- ── The server's door (20261023203732_agent_mailbox_rpc.sql), driven as service_role ──────────
-- t18: no browser role can call any mailbox function.
INSERT INTO mb_results SELECT 't18_rpcs_are_server_only',
  NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace, (VALUES ('anon'), ('authenticated')) r(role)
               WHERE n.nspname = 'public' AND p.proname LIKE 'mailbox\_%' AND has_function_privilege(r.role, p.oid, 'EXECUTE'))
  AND (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public' AND p.proname LIKE 'mailbox\_%' AND p.prosecdef) = 20
  AND (SELECT bool_and(has_function_privilege('service_role', p.oid, 'EXECUTE')) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public' AND p.proname LIKE 'mailbox\_%');

SET LOCAL ROLE service_role;
CREATE TEMP TABLE mb_rpc (name text PRIMARY KEY, v text);
DO $$
DECLARE
  v_id UUID; v_b UUID; v_r UUID; v_ok BOOLEAN; v_n INTEGER; v_row RECORD;
BEGIN
  PERFORM public.mailbox_register_client('rpc-claude', 'Claude', ARRAY['https://claude.ai/api/mcp/auth_callback']);
  -- A code for an unregistered redirect is refused.
  BEGIN
    PERFORM public.mailbox_create_code(repeat('ab', 32), 'rpc-claude', '02069000-0000-4000-8000-00000000000a', 'dispatcher', 'https://evil.example/cb', 'chal', 120);
    INSERT INTO mb_rpc VALUES ('bad_redirect_refused', 'false');
  EXCEPTION WHEN raise_exception THEN
    INSERT INTO mb_rpc VALUES ('bad_redirect_refused', 'true');
  END;
  PERFORM public.mailbox_create_code(repeat('cd', 32), 'rpc-claude', '02069000-0000-4000-8000-00000000000a', 'dispatcher', 'https://claude.ai/api/mcp/auth_callback', 'chal', 120);
  SELECT * INTO v_row FROM public.mailbox_take_code(repeat('cd', 32));
  INSERT INTO mb_rpc VALUES ('code_first_use', (v_row.client_id = 'rpc-claude' AND v_row.role = 'dispatcher' AND NOT v_row.expired)::text);
  SELECT count(*) INTO v_n FROM public.mailbox_take_code(repeat('cd', 32));
  INSERT INTO mb_rpc VALUES ('code_second_use', (v_n = 0)::text);

  v_id := public.mailbox_connect('02069000-0000-4000-8000-00000000000a', 'rpc-claude', 'dispatcher', repeat('11', 32),
            repeat('22', 76), repeat('33', 76), repeat('44', 32), repeat('55', 32), 3600);
  SELECT * INTO v_row FROM public.mailbox_by_access(repeat('44', 32));
  INSERT INTO mb_rpc VALUES ('by_access', (v_row.id = v_id AND v_row.agent_name = 'Claude' AND v_row.public_key = repeat('11', 32) AND NOT v_row.expired)::text);

  -- Refresh: the first swap with the current refresh token works; reusing it does not.
  v_ok := public.mailbox_rotate(repeat('55', 32), repeat('66', 76), repeat('77', 76), repeat('88', 32), repeat('99', 32), 3600);
  INSERT INTO mb_rpc VALUES ('rotate_once', v_ok::text);
  v_ok := public.mailbox_rotate(repeat('55', 32), repeat('66', 76), repeat('77', 76), repeat('aa', 32), repeat('bb', 32), 3600);
  INSERT INTO mb_rpc VALUES ('rotate_reuse_refused', (NOT v_ok)::text);
  SELECT count(*) INTO v_n FROM public.mailbox_by_access(repeat('44', 32));
  INSERT INTO mb_rpc VALUES ('old_access_dead', (v_n = 0)::text);

  -- Messages between the two agents on the account (c2 is the worker from the fixtures).
  SELECT count(*) INTO v_n FROM public.mailbox_peers(v_id) WHERE id = '02069000-0000-4000-8000-0000000000c2';
  INSERT INTO mb_rpc VALUES ('peer_listed', (v_n = 1)::text);
  PERFORM public.mailbox_post('02069000-0000-4000-8000-0000000000d1', v_id, '02069000-0000-4000-8000-0000000000c2', 'task', NULL,
            repeat('12', 32), repeat('34', 12), repeat('56', 40), 24);
  SELECT count(*) INTO v_n FROM public.mailbox_inbox('02069000-0000-4000-8000-0000000000c2', ARRAY['task'], 10) WHERE id = '02069000-0000-4000-8000-0000000000d1';
  INSERT INTO mb_rpc VALUES ('inbox_has_it', (v_n = 1)::text);
  v_n := public.mailbox_mark_read('02069000-0000-4000-8000-0000000000c2', ARRAY['02069000-0000-4000-8000-0000000000d1'::uuid]);
  INSERT INTO mb_rpc VALUES ('marked_read', (v_n = 1)::text);
  SELECT count(*) INTO v_n FROM public.mailbox_inbox('02069000-0000-4000-8000-0000000000c2', NULL, 10) WHERE id = '02069000-0000-4000-8000-0000000000d1';
  INSERT INTO mb_rpc VALUES ('read_leaves_inbox', (v_n = 0)::text);
  -- The worker can find who sent it a task it already read; another agent cannot.
  SELECT count(*) INTO v_n FROM public.mailbox_message_sender('02069000-0000-4000-8000-0000000000c2', '02069000-0000-4000-8000-0000000000d1') WHERE from_connection = v_id;
  INSERT INTO mb_rpc VALUES ('sender_for_receiver', (v_n = 1)::text);
  SELECT count(*) INTO v_n FROM public.mailbox_message_sender(v_id, '02069000-0000-4000-8000-0000000000d1');
  INSERT INTO mb_rpc VALUES ('sender_hidden_from_others', (v_n = 0)::text);
  -- A real agent on ANOTHER account (B): it cannot be written to, seen, or used to read A's mail.
  v_b := public.mailbox_connect('02069000-0000-4000-8000-00000000000b', 'rpc-claude', 'worker', repeat('1b', 32),
           repeat('2b', 76), repeat('3b', 76), repeat('4b', 32), repeat('5b', 32), 3600);
  BEGIN
    PERFORM public.mailbox_post(gen_random_uuid(), v_id, v_b, 'task', NULL, repeat('12', 32), repeat('34', 12), repeat('56', 40), 24);
    INSERT INTO mb_rpc VALUES ('cross_account_refused', 'false');
  EXCEPTION WHEN raise_exception THEN
    INSERT INTO mb_rpc VALUES ('cross_account_refused', 'true');
  END;
  SELECT count(*) INTO v_n FROM public.mailbox_peers(v_id) WHERE id = v_b;
  INSERT INTO mb_rpc VALUES ('other_account_not_a_peer', (v_n = 0)::text);
  v_n := public.mailbox_mark_read(v_b, ARRAY['02069000-0000-4000-8000-0000000000d1'::uuid]);
  INSERT INTO mb_rpc VALUES ('stranger_cannot_mark_read', (v_n = 0)::text);
  SELECT count(*) INTO v_n FROM public.mailbox_message_sender(v_b, '02069000-0000-4000-8000-0000000000d1');
  INSERT INTO mb_rpc VALUES ('stranger_cannot_find_sender', (v_n = 0)::text);
  BEGIN
    PERFORM public.mailbox_post(gen_random_uuid(), v_b, v_b, 'note', '02069000-0000-4000-8000-0000000000d1', repeat('12', 32), repeat('34', 12), repeat('56', 40), 24);
    INSERT INTO mb_rpc VALUES ('reply_to_other_account_refused', 'false');
  EXCEPTION WHEN raise_exception THEN
    INSERT INTO mb_rpc VALUES ('reply_to_other_account_refused', 'true');
  END;
  -- Settings sees metadata only.
  INSERT INTO mb_rpc VALUES ('overview_no_contents',
    (SELECT position('5656' IN public.mailbox_overview('02069000-0000-4000-8000-00000000000a')::text) = 0
        AND jsonb_array_length(public.mailbox_overview('02069000-0000-4000-8000-00000000000a') -> 'agents') >= 2)::text);
  -- Stop: the agent is gone for every purpose.
  v_ok := public.mailbox_stop('02069000-0000-4000-8000-00000000000a', v_id);
  SELECT count(*) INTO v_n FROM public.mailbox_by_access(repeat('88', 32));
  INSERT INTO mb_rpc VALUES ('stop_kills_access', (v_ok AND v_n = 0)::text);
  SELECT count(*) INTO v_n FROM public.mailbox_by_refresh(repeat('99', 32));
  INSERT INTO mb_rpc VALUES ('stop_kills_refresh', (v_n = 0)::text);
  -- The owner renames their own agent; another account cannot, and a blank name is refused.
  v_ok := public.mailbox_rename('02069000-0000-4000-8000-00000000000a', '02069000-0000-4000-8000-0000000000c2', '  Grok Bot  ');
  INSERT INTO mb_rpc VALUES ('owner_renames', (v_ok AND (SELECT agent_name FROM mailbox.connections WHERE id = '02069000-0000-4000-8000-0000000000c2') = 'Grok Bot')::text);
  v_ok := public.mailbox_rename('02069000-0000-4000-8000-00000000000b', '02069000-0000-4000-8000-0000000000c2', 'Hijacked');
  INSERT INTO mb_rpc VALUES ('stranger_cannot_rename', (NOT v_ok)::text);
  BEGIN
    PERFORM public.mailbox_rename('02069000-0000-4000-8000-00000000000a', '02069000-0000-4000-8000-0000000000c2', '   ');
    INSERT INTO mb_rpc VALUES ('blank_name_refused', 'false');
  EXCEPTION WHEN raise_exception THEN
    INSERT INTO mb_rpc VALUES ('blank_name_refused', 'true');
  END;
  -- Another account cannot stop this one's agents.
  v_ok := public.mailbox_stop('02069000-0000-4000-8000-00000000000b', '02069000-0000-4000-8000-0000000000c2');
  INSERT INTO mb_rpc VALUES ('stranger_cannot_stop', (NOT v_ok)::text);

  -- A refresh token presented again after it was rotated away stops the connection.
  v_r := public.mailbox_connect('02069000-0000-4000-8000-00000000000a', 'rpc-claude', 'worker', repeat('1c', 32),
           repeat('2c', 76), repeat('3c', 76), repeat('a0', 32), repeat('a1', 32), 3600);
  v_ok := public.mailbox_rotate(repeat('a1', 32), repeat('2c', 76), repeat('3c', 76), repeat('a2', 32), repeat('a3', 32), 3600);
  INSERT INTO mb_rpc VALUES ('refresh_reuse_detected', (v_ok AND public.mailbox_refresh_reused(repeat('a1', 32)))::text);
  SELECT count(*) INTO v_n FROM public.mailbox_by_access(repeat('a2', 32));
  INSERT INTO mb_rpc VALUES ('refresh_reuse_stops_connection', (v_n = 0)::text);
  INSERT INTO mb_rpc VALUES ('unknown_refresh_not_reuse', (NOT public.mailbox_refresh_reused(repeat('ee', 32)))::text);

  -- A refresh token unused for 30 days is expired and cannot be rotated.
  v_r := public.mailbox_connect('02069000-0000-4000-8000-00000000000a', 'rpc-claude', 'worker', repeat('1d', 32),
           repeat('2d', 76), repeat('3d', 76), repeat('b0', 32), repeat('b1', 32), 3600);
  UPDATE mailbox.connections SET refresh_expires_at = now() - interval '1 day' WHERE id = v_r;
  SELECT * INTO v_row FROM public.mailbox_by_refresh(repeat('b1', 32));
  v_ok := public.mailbox_rotate(repeat('b1', 32), repeat('2d', 76), repeat('3d', 76), repeat('b2', 32), repeat('b3', 32), 3600);
  INSERT INTO mb_rpc VALUES ('expired_refresh_refused', (v_row.expired AND NOT v_ok)::text);

  -- 20 MB unread for one agent: the next message is refused.
  INSERT INTO mailbox.messages (id, user_id, from_connection, to_connection, kind, ephemeral_public_key, nonce, ciphertext, size_bytes)
  SELECT gen_random_uuid(), '02069000-0000-4000-8000-00000000000a', v_r, '02069000-0000-4000-8000-0000000000c2', 'task',
         decode(repeat('12', 32), 'hex'), decode(repeat('34', 12), 'hex'), decode(repeat('ab', 204816), 'hex'), 204800
    FROM generate_series(1, 103);
  BEGIN
    PERFORM public.mailbox_post(gen_random_uuid(), v_r, '02069000-0000-4000-8000-0000000000c2', 'task', NULL, repeat('12', 32), repeat('34', 12), repeat('56', 40), 24);
    INSERT INTO mb_rpc VALUES ('mailbox_full_refused', 'false');
  EXCEPTION WHEN raise_exception THEN
    INSERT INTO mb_rpc VALUES ('mailbox_full_refused', (SQLERRM = 'mailbox_full')::text);
  END;

  -- The name chosen on the Connect page rides on the code and becomes the connection's name.
  PERFORM public.mailbox_create_code(repeat('ce', 32), 'rpc-claude', '02069000-0000-4000-8000-00000000000a', 'worker', 'https://claude.ai/api/mcp/auth_callback', 'chal', 120, '  Grok Bot  ');
  SELECT * INTO v_row FROM public.mailbox_take_code(repeat('ce', 32));
  INSERT INTO mb_rpc VALUES ('code_carries_name', (v_row.agent_name = 'Grok Bot')::text);
  v_r := public.mailbox_connect('02069000-0000-4000-8000-00000000000a', 'rpc-claude', 'worker', repeat('e1', 32),
            repeat('e2', 76), repeat('e3', 76), repeat('e4', 32), repeat('e5', 32), 3600, v_row.agent_name);
  SELECT * INTO v_row FROM public.mailbox_by_access(repeat('e4', 32));
  INSERT INTO mb_rpc VALUES ('connect_uses_chosen_name', (v_row.id = v_r AND v_row.agent_name = 'Grok Bot')::text);
  BEGIN
    PERFORM public.mailbox_create_code(repeat('cf', 32), 'rpc-claude', '02069000-0000-4000-8000-00000000000a', 'worker', 'https://claude.ai/api/mcp/auth_callback', 'chal', 120, repeat('x', 101));
    INSERT INTO mb_rpc VALUES ('long_code_name_refused', 'false');
  EXCEPTION WHEN raise_exception THEN
    INSERT INTO mb_rpc VALUES ('long_code_name_refused', 'true');
  END;
  -- Requests counted by key: the limit holds, and another key has its own count.
  INSERT INTO mb_rpc VALUES ('request_limit', (public.mailbox_request_limit('register:k1', 2) AND public.mailbox_request_limit('register:k1', 2)
    AND NOT public.mailbox_request_limit('register:k1', 2) AND public.mailbox_request_limit('register:k2', 2))::text);
END $$;
RESET ROLE;
INSERT INTO mb_results SELECT 't19_rpc_' || name, v = 'true' FROM mb_rpc;

-- t16: a message must name its sender.
INSERT INTO mb_results SELECT 't16_sender_required',
  (SELECT is_nullable = 'NO' FROM information_schema.columns
    WHERE table_schema = 'mailbox' AND table_name = 'messages' AND column_name = 'from_connection');

SELECT 'stored_ciphertext=' || encode(ciphertext, 'hex') FROM mailbox.messages WHERE id = :'message_id';
SELECT 'stored_worker_wrapped=' || encode(wrapped_private_key, 'hex') FROM mailbox.connections WHERE id = '02069000-0000-4000-8000-0000000000c2';
SELECT 'stored_worker_access_hash=' || encode(access_token_hash, 'hex') FROM mailbox.connections WHERE id = '02069000-0000-4000-8000-0000000000c2';

-- t11: deleting the account removes its connections and messages.
DELETE FROM auth.users WHERE id = '02069000-0000-4000-8000-00000000000a';
INSERT INTO mb_results SELECT 't11_account_deletion_cascades',
  NOT EXISTS (SELECT 1 FROM mailbox.connections WHERE user_id = '02069000-0000-4000-8000-00000000000a')
  AND NOT EXISTS (SELECT 1 FROM mailbox.messages WHERE user_id = '02069000-0000-4000-8000-00000000000a');

-- Hand the stored bytes back so the runner can prove they cannot be opened without the token.
-- (Read before t11 deletes the account.)
SELECT name || '=' || coalesce(ok, false) FROM mb_results ORDER BY name;
