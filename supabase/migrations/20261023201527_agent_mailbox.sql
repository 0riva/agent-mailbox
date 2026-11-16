-- Agent mailbox: a client's AI agents (Claude, Grok Bot, …) pass work to each other through
-- their Oriva account (o-core#2069).
--
-- Communication, not memory: a message is sealed to the agent it is for, deleted 7 days after it
-- is read (30 days if never read), and the agents keep their own records on the client's system.
--
-- What the database holds, and why none of it reveals a message:
--   - connections.public_key           the receiving agent's X25519 public key (public by design);
--   - connections.wrapped_private_key  that agent's private key, encrypted under a key derived from
--                                      the agent's own access token, which is stored only as a hash;
--   - messages.ciphertext              AES-256-GCM, sealed to the receiver's public key.
-- So a database read, a backup or a staff member with the service role cannot open a message:
-- that needs the receiving agent's live token, which only the agent holds. The server sees a
-- message in memory while delivering it. Encryption lives in apps/web/lib/mailbox/crypto.ts.
--
-- Only the server (service_role) can reach this schema. It is not exposed through the Data API,
-- and RLS is on with no policies, so even a grant added by mistake would read nothing.

CREATE SCHEMA IF NOT EXISTS mailbox;
REVOKE ALL ON SCHEMA mailbox FROM PUBLIC, anon, authenticated;
GRANT USAGE ON SCHEMA mailbox TO service_role;

-- OAuth clients that registered themselves (dynamic client registration). Open registration means
-- a client's name is a claim; the consent page shows the redirect host beside it.
CREATE TABLE mailbox.clients (
  client_id      TEXT PRIMARY KEY,
  client_name    TEXT NOT NULL CHECK (char_length(client_name) BETWEEN 1 AND 100),
  redirect_uris  TEXT[] NOT NULL CHECK (cardinality(redirect_uris) BETWEEN 1 AND 10),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One-time sign-in codes, held for minutes between Allow and the agent's token exchange.
CREATE TABLE mailbox.auth_codes (
  code_hash       BYTEA PRIMARY KEY CHECK (octet_length(code_hash) = 32),
  client_id       TEXT NOT NULL REFERENCES mailbox.clients (client_id) ON DELETE CASCADE,
  user_id         UUID NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  role            TEXT NOT NULL CHECK (role IN ('dispatcher', 'worker')),
  redirect_uri    TEXT NOT NULL,
  code_challenge  TEXT NOT NULL,
  expires_at      TIMESTAMPTZ NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX auth_codes_client_id_idx ON mailbox.auth_codes (client_id);
CREATE INDEX auth_codes_user_id_idx ON mailbox.auth_codes (user_id);

-- A connected agent. role: 'dispatcher' hands out work (posts tasks, reads results);
-- 'worker' does the work (fetches tasks, reports results, leaves notes).
CREATE TABLE mailbox.connections (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id              UUID NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  client_id            TEXT NOT NULL REFERENCES mailbox.clients (client_id) ON DELETE CASCADE,
  agent_name           TEXT NOT NULL CHECK (char_length(agent_name) BETWEEN 1 AND 100),
  role                 TEXT NOT NULL CHECK (role IN ('dispatcher', 'worker')),
  public_key           BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
  wrapped_private_key  BYTEA,          -- NULL once stopped: nothing waiting for it can be opened
  access_token_hash    BYTEA UNIQUE CHECK (access_token_hash IS NULL OR octet_length(access_token_hash) = 32),
  refresh_token_hash   BYTEA UNIQUE CHECK (refresh_token_hash IS NULL OR octet_length(refresh_token_hash) = 32),
  access_expires_at    TIMESTAMPTZ,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at         TIMESTAMPTZ,
  stopped_at           TIMESTAMPTZ,
  CHECK (stopped_at IS NULL OR (wrapped_private_key IS NULL AND access_token_hash IS NULL AND refresh_token_hash IS NULL))
);
CREATE INDEX connections_user_id_idx ON mailbox.connections (user_id);
CREATE INDEX connections_client_id_idx ON mailbox.connections (client_id);

-- A message, sealed to its receiver. The metadata (who, kind, when, size, read) is what
-- Settings → Agents shows; the contents are never shown there.
CREATE TABLE mailbox.messages (
  id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id               UUID NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  from_connection       UUID REFERENCES mailbox.connections (id) ON DELETE SET NULL,
  to_connection         UUID NOT NULL REFERENCES mailbox.connections (id) ON DELETE CASCADE,
  kind                  TEXT NOT NULL CHECK (kind IN ('task', 'result', 'note')),
  reply_to              UUID REFERENCES mailbox.messages (id) ON DELETE SET NULL,
  ephemeral_public_key  BYTEA NOT NULL CHECK (octet_length(ephemeral_public_key) = 32),
  nonce                 BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
  ciphertext            BYTEA NOT NULL CHECK (octet_length(ciphertext) BETWEEN 17 AND 204816),
  size_bytes            INTEGER NOT NULL CHECK (size_bytes BETWEEN 1 AND 204800),
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  read_at               TIMESTAMPTZ,
  delete_after          TIMESTAMPTZ NOT NULL DEFAULT now() + interval '30 days'
);
CREATE INDEX messages_user_id_idx ON mailbox.messages (user_id);
CREATE INDEX messages_from_connection_idx ON mailbox.messages (from_connection);
CREATE INDEX messages_to_connection_unread_idx ON mailbox.messages (to_connection, created_at) WHERE read_at IS NULL;
CREATE INDEX messages_reply_to_idx ON mailbox.messages (reply_to);
CREATE INDEX messages_delete_after_idx ON mailbox.messages (delete_after);

-- Per-connection request counts, kept in Postgres because serverless instances share no memory.
CREATE TABLE mailbox.rate_limits (
  connection_id  UUID NOT NULL REFERENCES mailbox.connections (id) ON DELETE CASCADE,
  window_start   TIMESTAMPTZ NOT NULL,
  hits           INTEGER NOT NULL DEFAULT 0 CHECK (hits >= 0),
  PRIMARY KEY (connection_id, window_start)
);

ALTER TABLE mailbox.clients     ENABLE ROW LEVEL SECURITY;
ALTER TABLE mailbox.auth_codes  ENABLE ROW LEVEL SECURITY;
ALTER TABLE mailbox.connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE mailbox.messages    ENABLE ROW LEVEL SECURITY;
ALTER TABLE mailbox.rate_limits ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON ALL TABLES IN SCHEMA mailbox FROM PUBLIC, anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA mailbox TO service_role;

-- Count one request against a connection's per-minute window and say whether it is allowed.
CREATE FUNCTION mailbox.hit_rate_limit(p_connection UUID, p_limit INTEGER)
RETURNS BOOLEAN LANGUAGE sql SECURITY INVOKER SET search_path = '' AS $$
  INSERT INTO mailbox.rate_limits AS r (connection_id, window_start, hits)
  VALUES (p_connection, date_trunc('minute', now()), 1)
  ON CONFLICT (connection_id, window_start) DO UPDATE SET hits = r.hits + 1
  RETURNING hits <= p_limit
$$;
REVOKE ALL ON FUNCTION mailbox.hit_rate_limit(UUID, INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION mailbox.hit_rate_limit(UUID, INTEGER) TO service_role;

-- Delete what the mailbox no longer needs: messages past their delete_after, expired sign-in
-- codes, and rate-limit windows older than a day. Returns the number of messages removed.
CREATE FUNCTION mailbox.purge()
RETURNS INTEGER LANGUAGE plpgsql SECURITY INVOKER SET search_path = '' AS $$
DECLARE
  v_messages INTEGER;
BEGIN
  DELETE FROM mailbox.messages WHERE delete_after < now();
  GET DIAGNOSTICS v_messages = ROW_COUNT;
  DELETE FROM mailbox.auth_codes WHERE expires_at < now();
  DELETE FROM mailbox.rate_limits WHERE window_start < now() - interval '1 day';
  RETURN v_messages;
END;
$$;
REVOKE ALL ON FUNCTION mailbox.purge() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION mailbox.purge() TO service_role;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
    PERFORM cron.unschedule(jobid) FROM cron.job WHERE jobname = 'purge-agent-mailbox';
    PERFORM cron.schedule('purge-agent-mailbox', '23 * * * *', 'SELECT mailbox.purge()');
  END IF;
END
$$;
