-- Agent mailbox, tightened after the security review of 20261023201527 (o-core#2069).
--
-- 1. A second wrapped copy of each agent's private key, under its REFRESH token. The server
--    holds only the refresh token when a token is renewed, so without this copy it could not
--    re-wrap the key, and every queued message would be lost when an access token expired.
-- 2. The sender is part of the sealed message (crypto.ts messageAad binds id, account, sender,
--    receiver and kind), so a message whose sender is gone must go too: from_connection becomes
--    NOT NULL ... ON DELETE CASCADE.
-- 3. "Deleted 7 days after it is read" is enforced here, not left to application code.
-- 4. The recorded size must match the ciphertext; nothing can be queued for a stopped agent;
--    sign-in return addresses must be https, or http on a loopback address (Grok Bot's local
--    OAuth callbacks).
-- 5. If pg_cron is missing the purge cannot be scheduled; say so instead of skipping silently.
--
-- Who can read these tables, precisely: only service_role through the API (the schema is not in
-- the Data API's exposed schemas, and anon/authenticated have no USAGE). Database superusers and
-- roles with BYPASSRLS/pg_read_all_data (postgres, supabase_read_only_user) can read the ROWS, as
-- with any table — which is why message bodies are ciphertext a row read cannot open.

ALTER TABLE mailbox.connections ADD COLUMN wrapped_private_key_refresh BYTEA;
ALTER TABLE mailbox.connections DROP CONSTRAINT connections_check;
ALTER TABLE mailbox.connections ADD CONSTRAINT connections_stopped_has_no_secrets CHECK (
  stopped_at IS NULL OR (wrapped_private_key IS NULL AND wrapped_private_key_refresh IS NULL
                         AND access_token_hash IS NULL AND refresh_token_hash IS NULL)
);

ALTER TABLE mailbox.messages DROP CONSTRAINT messages_from_connection_fkey;
ALTER TABLE mailbox.messages ALTER COLUMN from_connection SET NOT NULL;
ALTER TABLE mailbox.messages ADD CONSTRAINT messages_from_connection_fkey
  FOREIGN KEY (from_connection) REFERENCES mailbox.connections (id) ON DELETE CASCADE;
ALTER TABLE mailbox.messages ALTER COLUMN id DROP DEFAULT;  -- the id is sealed in, so the app sets it
ALTER TABLE mailbox.messages ADD CONSTRAINT messages_size_matches_ciphertext
  CHECK (size_bytes = octet_length(ciphertext) - 16);

CREATE FUNCTION mailbox.redirect_uris_safe(uris TEXT[])
RETURNS BOOLEAN LANGUAGE sql IMMUTABLE SET search_path = '' AS $$
  SELECT coalesce(bool_and(u ~ '^https://[^/?#]+' OR u ~ '^http://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]+)?(/|$)'), false)
    FROM unnest(uris) AS u
$$;
ALTER TABLE mailbox.clients ADD CONSTRAINT clients_redirect_uris_safe CHECK (mailbox.redirect_uris_safe(redirect_uris));

CREATE FUNCTION mailbox.messages_before_write()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY INVOKER SET search_path = '' AS $$
BEGIN
  IF TG_OP = 'INSERT' AND EXISTS (
       SELECT 1 FROM mailbox.connections
        WHERE id IN (NEW.from_connection, NEW.to_connection) AND stopped_at IS NOT NULL) THEN
    RAISE EXCEPTION 'agent connection is stopped' USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.read_at IS NOT NULL THEN
    NEW.delete_after := least(NEW.delete_after, NEW.read_at + interval '7 days');
  END IF;
  RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION mailbox.messages_before_write() FROM PUBLIC, anon, authenticated;
CREATE TRIGGER messages_before_write BEFORE INSERT OR UPDATE ON mailbox.messages
  FOR EACH ROW EXECUTE FUNCTION mailbox.messages_before_write();

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mailbox FROM PUBLIC, anon, authenticated;
-- redirect_uris_safe runs inside a CHECK, so the role that writes clients must be able to execute it.
GRANT EXECUTE ON FUNCTION mailbox.hit_rate_limit(UUID, INTEGER), mailbox.purge(), mailbox.redirect_uris_safe(TEXT[]) TO service_role;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
    RAISE WARNING 'pg_cron is not installed: mailbox.purge() is not scheduled, so expired agent messages will not be deleted';
  END IF;
END
$$;
