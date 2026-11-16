-- Agent mailbox: the server's door into the private `mailbox` schema (o-core#2069).
--
-- The `mailbox` schema is deliberately NOT exposed through the Data API (supabase/config.toml
-- [api] schemas), so the app reaches it only through these functions. Each one:
--   - lives in `public` (the exposed schema) but is callable by service_role ONLY — anon and
--     authenticated have EXECUTE revoked, so a browser can never call them;
--   - is SECURITY DEFINER with an empty search_path, and checks every relationship itself
--     (a connection belongs to the account, a message goes between two of that account's agents);
--   - takes and returns bytes as hex text (PostgREST carries JSON).
-- Encryption happens in the app (apps/web/lib/mailbox/crypto.ts); nothing here can open a message.

-- ── Hardening from the security review of slices 2–4 ──────────────────────────────────────────
-- A refresh token now expires 30 days after its last use, and the previous one is remembered as a
-- hash: presenting it again means it was copied, so the connection is stopped (reuse detection).
ALTER TABLE mailbox.connections ADD COLUMN refresh_expires_at TIMESTAMPTZ;
ALTER TABLE mailbox.connections ADD COLUMN previous_refresh_hash BYTEA UNIQUE
  CHECK (previous_refresh_hash IS NULL OR octet_length(previous_refresh_hash) = 32);

-- Request counts by a key that is not a connection (a hashed caller address for registration).
CREATE TABLE mailbox.request_limits (
  key           TEXT NOT NULL CHECK (char_length(key) BETWEEN 1 AND 200),
  window_start  TIMESTAMPTZ NOT NULL,
  hits          INTEGER NOT NULL DEFAULT 0 CHECK (hits >= 0),
  PRIMARY KEY (key, window_start)
);
ALTER TABLE mailbox.request_limits ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON mailbox.request_limits FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON mailbox.request_limits TO service_role;

-- purge also clears request windows older than a day, and clients nobody connected within 7 days.
CREATE OR REPLACE FUNCTION mailbox.purge()
RETURNS INTEGER LANGUAGE plpgsql SECURITY INVOKER SET search_path = '' AS $$
DECLARE
  v_messages INTEGER;
BEGIN
  DELETE FROM mailbox.messages WHERE delete_after < now();
  GET DIAGNOSTICS v_messages = ROW_COUNT;
  DELETE FROM mailbox.auth_codes WHERE expires_at < now();
  DELETE FROM mailbox.rate_limits WHERE window_start < now() - interval '1 day';
  DELETE FROM mailbox.request_limits WHERE window_start < now() - interval '1 day';
  DELETE FROM mailbox.clients c
   WHERE c.created_at < now() - interval '7 days'
     AND NOT EXISTS (SELECT 1 FROM mailbox.connections x WHERE x.client_id = c.client_id);
  RETURN v_messages;
END;
$$;

-- ── OAuth clients ───────────────────────────────────────────────────────────────────────────────
CREATE FUNCTION public.mailbox_register_client(p_client_id TEXT, p_name TEXT, p_redirect_uris TEXT[])
RETURNS VOID LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  INSERT INTO mailbox.clients (client_id, client_name, redirect_uris) VALUES (p_client_id, p_name, p_redirect_uris)
$$;

CREATE FUNCTION public.mailbox_client(p_client_id TEXT)
RETURNS TABLE (client_name TEXT, redirect_uris TEXT[]) LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT client_name, redirect_uris FROM mailbox.clients WHERE client_id = p_client_id
$$;

-- ── One-time sign-in codes ──────────────────────────────────────────────────────────────────────
CREATE FUNCTION public.mailbox_create_code(
  p_code_hash TEXT, p_client_id TEXT, p_user_id UUID, p_role TEXT, p_redirect_uri TEXT, p_challenge TEXT, p_ttl_seconds INTEGER
) RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  IF p_ttl_seconds NOT BETWEEN 30 AND 600 THEN RAISE EXCEPTION 'code lifetime out of range'; END IF;
  IF NOT EXISTS (SELECT 1 FROM mailbox.clients WHERE client_id = p_client_id AND p_redirect_uri = ANY (redirect_uris)) THEN
    RAISE EXCEPTION 'redirect_uri is not registered for this client';
  END IF;
  INSERT INTO mailbox.auth_codes (code_hash, client_id, user_id, role, redirect_uri, code_challenge, expires_at)
  VALUES (decode(p_code_hash, 'hex'), p_client_id, p_user_id, p_role, p_redirect_uri, p_challenge, now() + make_interval(secs => p_ttl_seconds));
END;
$$;

-- Returns the code's details and deletes it in the same statement, so a code works once.
CREATE FUNCTION public.mailbox_take_code(p_code_hash TEXT)
RETURNS TABLE (client_id TEXT, user_id UUID, role TEXT, redirect_uri TEXT, code_challenge TEXT, expired BOOLEAN)
LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  DELETE FROM mailbox.auth_codes c WHERE c.code_hash = decode(p_code_hash, 'hex')
  RETURNING c.client_id, c.user_id, c.role, c.redirect_uri, c.code_challenge, c.expires_at < now()
$$;

-- ── Connections ─────────────────────────────────────────────────────────────────────────────────
CREATE FUNCTION public.mailbox_connect(
  p_user_id UUID, p_client_id TEXT, p_role TEXT, p_public_key TEXT, p_wrapped TEXT, p_wrapped_refresh TEXT,
  p_access_hash TEXT, p_refresh_hash TEXT, p_access_ttl_seconds INTEGER
) RETURNS UUID LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  INSERT INTO mailbox.connections (user_id, client_id, agent_name, role, public_key, wrapped_private_key,
                                   wrapped_private_key_refresh, access_token_hash, refresh_token_hash, access_expires_at,
                                   refresh_expires_at)
  SELECT p_user_id, c.client_id, c.client_name, p_role, decode(p_public_key, 'hex'), decode(p_wrapped, 'hex'),
         decode(p_wrapped_refresh, 'hex'), decode(p_access_hash, 'hex'), decode(p_refresh_hash, 'hex'),
         now() + make_interval(secs => p_access_ttl_seconds), now() + interval '30 days'
    FROM mailbox.clients c WHERE c.client_id = p_client_id
  RETURNING id
$$;

-- The caller of every agent request: found by its access token's hash. A stopped connection has
-- no token hash, so it is never found.
CREATE FUNCTION public.mailbox_by_access(p_access_hash TEXT)
RETURNS TABLE (id UUID, user_id UUID, role TEXT, agent_name TEXT, public_key TEXT, wrapped TEXT, expired BOOLEAN)
LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  UPDATE mailbox.connections c SET last_used_at = now()
   WHERE c.access_token_hash = decode(p_access_hash, 'hex') AND c.stopped_at IS NULL
  RETURNING c.id, c.user_id, c.role, c.agent_name, encode(c.public_key, 'hex'), encode(c.wrapped_private_key, 'hex'),
            c.access_expires_at < now()
$$;

CREATE FUNCTION public.mailbox_by_refresh(p_refresh_hash TEXT)
RETURNS TABLE (id UUID, client_id TEXT, public_key TEXT, wrapped_refresh TEXT, expired BOOLEAN)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT c.id, c.client_id, encode(c.public_key, 'hex'), encode(c.wrapped_private_key_refresh, 'hex'),
         coalesce(c.refresh_expires_at < now(), false)
    FROM mailbox.connections c
   WHERE c.refresh_token_hash = decode(p_refresh_hash, 'hex') AND c.stopped_at IS NULL
$$;

-- A refresh token that was already rotated away is being presented again: it was copied. Stop the
-- connection so neither copy works. Returns true when that happened.
CREATE FUNCTION public.mailbox_refresh_reused(p_refresh_hash TEXT)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  UPDATE mailbox.connections
     SET stopped_at = now(), wrapped_private_key = NULL, wrapped_private_key_refresh = NULL,
         access_token_hash = NULL, refresh_token_hash = NULL, previous_refresh_hash = NULL
   WHERE previous_refresh_hash = decode(p_refresh_hash, 'hex') AND stopped_at IS NULL;
  RETURN FOUND;
END;
$$;

-- Swap in a new token pair, only if the refresh token presented is still the current one
-- (compare-and-swap), so a refresh token can be used once. Returns true when it swapped.
CREATE FUNCTION public.mailbox_rotate(
  p_old_refresh_hash TEXT, p_wrapped TEXT, p_wrapped_refresh TEXT, p_access_hash TEXT, p_refresh_hash TEXT, p_access_ttl_seconds INTEGER
) RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  UPDATE mailbox.connections
     SET wrapped_private_key = decode(p_wrapped, 'hex'), wrapped_private_key_refresh = decode(p_wrapped_refresh, 'hex'),
         access_token_hash = decode(p_access_hash, 'hex'), refresh_token_hash = decode(p_refresh_hash, 'hex'),
         access_expires_at = now() + make_interval(secs => p_access_ttl_seconds), last_used_at = now(),
         refresh_expires_at = now() + interval '30 days', previous_refresh_hash = decode(p_old_refresh_hash, 'hex')
   WHERE refresh_token_hash = decode(p_old_refresh_hash, 'hex') AND stopped_at IS NULL
     AND (refresh_expires_at IS NULL OR refresh_expires_at >= now());
  RETURN FOUND;
END;
$$;

-- Stop: delete the agent's keys and tokens. Anything still waiting for it can no longer be opened.
CREATE FUNCTION public.mailbox_stop(p_user_id UUID, p_connection UUID)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
  UPDATE mailbox.connections
     SET stopped_at = now(), wrapped_private_key = NULL, wrapped_private_key_refresh = NULL,
         access_token_hash = NULL, refresh_token_hash = NULL, previous_refresh_hash = NULL
   WHERE id = p_connection AND user_id = p_user_id AND stopped_at IS NULL;
  RETURN FOUND;
END;
$$;

-- RFC 7009 revocation: the agent hands back either of its tokens; the connection is stopped.
CREATE FUNCTION public.mailbox_revoke(p_token_hash TEXT)
RETURNS VOID LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  UPDATE mailbox.connections
     SET stopped_at = now(), wrapped_private_key = NULL, wrapped_private_key_refresh = NULL,
         access_token_hash = NULL, refresh_token_hash = NULL, previous_refresh_hash = NULL
   WHERE stopped_at IS NULL
     AND (access_token_hash = decode(p_token_hash, 'hex') OR refresh_token_hash = decode(p_token_hash, 'hex'))
$$;

CREATE FUNCTION public.mailbox_rate_limit(p_connection UUID, p_limit INTEGER)
RETURNS BOOLEAN LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  SELECT mailbox.hit_rate_limit(p_connection, p_limit)
$$;

-- Count one request against a key (a hashed caller address) in an hour window.
CREATE FUNCTION public.mailbox_request_limit(p_key TEXT, p_limit INTEGER)
RETURNS BOOLEAN LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  INSERT INTO mailbox.request_limits AS r (key, window_start, hits)
  VALUES (p_key, date_trunc('hour', now()), 1)
  ON CONFLICT (key, window_start) DO UPDATE SET hits = r.hits + 1
  RETURNING hits <= p_limit
$$;

-- ── Messages ────────────────────────────────────────────────────────────────────────────────────
-- The other active agents on the same account, with the public key a message is sealed to.
CREATE FUNCTION public.mailbox_peers(p_connection UUID)
RETURNS TABLE (id UUID, role TEXT, agent_name TEXT, public_key TEXT)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT p.id, p.role, p.agent_name, encode(p.public_key, 'hex')
    FROM mailbox.connections me JOIN mailbox.connections p ON p.user_id = me.user_id
   WHERE me.id = p_connection AND p.id <> me.id AND p.stopped_at IS NULL
   ORDER BY p.created_at
$$;

CREATE FUNCTION public.mailbox_post(
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
  -- An agent that is not reading its mail cannot be buried in it: 20 MB unread per receiver.
  IF (SELECT coalesce(sum(size_bytes), 0) FROM mailbox.messages WHERE to_connection = p_to AND read_at IS NULL) + p_size > 20971520 THEN
    RAISE EXCEPTION 'mailbox_full' USING HINT = 'The receiving agent has 20 MB of unread messages.';
  END IF;
  INSERT INTO mailbox.messages (id, user_id, from_connection, to_connection, kind, reply_to, ephemeral_public_key, nonce, ciphertext, size_bytes)
  VALUES (p_id, v_user, p_from, p_to, p_kind, p_reply_to, decode(p_ephemeral_public_key, 'hex'), decode(p_nonce, 'hex'),
          decode(p_ciphertext, 'hex'), p_size);
END;
$$;

-- Unread messages for one agent, oldest first, optionally of some kinds only.
CREATE FUNCTION public.mailbox_inbox(p_connection UUID, p_kinds TEXT[], p_limit INTEGER)
RETURNS TABLE (id UUID, user_id UUID, from_connection UUID, from_name TEXT, kind TEXT, reply_to UUID,
               ephemeral_public_key TEXT, nonce TEXT, ciphertext TEXT, created_at TIMESTAMPTZ)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT m.id, m.user_id, m.from_connection, f.agent_name, m.kind, m.reply_to,
         encode(m.ephemeral_public_key, 'hex'), encode(m.nonce, 'hex'), encode(m.ciphertext, 'hex'), m.created_at
    FROM mailbox.messages m JOIN mailbox.connections f ON f.id = m.from_connection
   WHERE m.to_connection = p_connection AND m.read_at IS NULL
     AND (p_kinds IS NULL OR m.kind = ANY (p_kinds))
   ORDER BY m.created_at
   LIMIT least(greatest(p_limit, 1), 50)
$$;

-- Who sent a message addressed to this agent (to reply to a task it already read). Nothing for a
-- message addressed to anyone else.
CREATE FUNCTION public.mailbox_message_sender(p_connection UUID, p_id UUID)
RETURNS TABLE (from_connection UUID, kind TEXT)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT m.from_connection, m.kind FROM mailbox.messages m WHERE m.id = p_id AND m.to_connection = p_connection
$$;

CREATE FUNCTION public.mailbox_mark_read(p_connection UUID, p_ids UUID[])
RETURNS INTEGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  v_count INTEGER;
BEGIN
  UPDATE mailbox.messages SET read_at = now()
   WHERE to_connection = p_connection AND id = ANY (p_ids) AND read_at IS NULL;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count;
END;
$$;

-- What Settings → Agents shows: agents and message metadata. Never contents.
CREATE FUNCTION public.mailbox_overview(p_user_id UUID)
RETURNS JSONB LANGUAGE sql STABLE SECURITY DEFINER SET search_path = '' AS $$
  SELECT jsonb_build_object(
    'agents', coalesce((SELECT jsonb_agg(jsonb_build_object('id', c.id, 'name', c.agent_name, 'role', c.role,
                          'connectedAt', c.created_at, 'lastUsedAt', c.last_used_at, 'stoppedAt', c.stopped_at)
                          ORDER BY c.created_at DESC)
                         FROM mailbox.connections c WHERE c.user_id = p_user_id), '[]'::jsonb),
    'activity', coalesce((SELECT jsonb_agg(row_to_json(a)::jsonb ORDER BY a."sentAt" DESC) FROM (
                            SELECT m.id, f.agent_name AS "from", t.agent_name AS "to", m.kind, m.size_bytes AS "size",
                                   m.created_at AS "sentAt", m.read_at AS "readAt"
                              FROM mailbox.messages m
                              JOIN mailbox.connections f ON f.id = m.from_connection
                              JOIN mailbox.connections t ON t.id = m.to_connection
                             WHERE m.user_id = p_user_id
                             ORDER BY m.created_at DESC LIMIT 100) a), '[]'::jsonb))
$$;

-- ── Access ──────────────────────────────────────────────────────────────────────────────────────
DO $$
DECLARE
  f TEXT;
BEGIN
  FOREACH f IN ARRAY ARRAY[
    'mailbox_register_client(text, text, text[])', 'mailbox_client(text)',
    'mailbox_create_code(text, text, uuid, text, text, text, integer)', 'mailbox_take_code(text)',
    'mailbox_connect(uuid, text, text, text, text, text, text, text, integer)', 'mailbox_by_access(text)',
    'mailbox_by_refresh(text)', 'mailbox_rotate(text, text, text, text, text, integer)', 'mailbox_stop(uuid, uuid)',
    'mailbox_revoke(text)', 'mailbox_rate_limit(uuid, integer)', 'mailbox_peers(uuid)',
    'mailbox_post(uuid, uuid, uuid, text, uuid, text, text, text, integer)', 'mailbox_inbox(uuid, text[], integer)',
    'mailbox_mark_read(uuid, uuid[])', 'mailbox_overview(uuid)', 'mailbox_message_sender(uuid, uuid)',
    'mailbox_refresh_reused(text)', 'mailbox_request_limit(text, integer)'
  ] LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION public.%s FROM PUBLIC, anon, authenticated', f);
    EXECUTE format('GRANT EXECUTE ON FUNCTION public.%s TO service_role', f);
  END LOOP;
END
$$;

NOTIFY pgrst, 'reload schema';
