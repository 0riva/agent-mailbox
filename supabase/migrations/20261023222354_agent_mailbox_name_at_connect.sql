-- Name an agent on the Connect page (o-core#2069).
--
-- An agent arrives under whatever name its app sends: Grok Bot's connector calls itself "Cursor",
-- so "post a task to my Grok Bot" found no agent until the member renamed it in Settings. The
-- consent page now shows that name in an editable box; the owner's choice rides on the one-time
-- sign-in code and becomes the connection's name. No name (a consent page opened before this
-- shipped) keeps the old behaviour: the app's own name.
--
-- Each function is dropped and re-created in this one transaction with the new argument last and
-- DEFAULT NULL, so a caller still sending the old arguments resolves to it unchanged, and
-- mailbox_take_code only gains a column. Grants are re-applied: service_role only.

ALTER TABLE mailbox.auth_codes
  ADD COLUMN agent_name TEXT CHECK (agent_name IS NULL OR char_length(agent_name) BETWEEN 1 AND 100);

DROP FUNCTION public.mailbox_create_code(TEXT, TEXT, UUID, TEXT, TEXT, TEXT, INTEGER);
CREATE FUNCTION public.mailbox_create_code(
  p_code_hash TEXT, p_client_id TEXT, p_user_id UUID, p_role TEXT, p_redirect_uri TEXT, p_challenge TEXT, p_ttl_seconds INTEGER,
  p_agent_name TEXT DEFAULT NULL
) RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE v_name TEXT := nullif(btrim(p_agent_name), '');
BEGIN
  IF p_ttl_seconds NOT BETWEEN 30 AND 600 THEN RAISE EXCEPTION 'code lifetime out of range'; END IF;
  IF v_name IS NOT NULL AND char_length(v_name) > 100 THEN RAISE EXCEPTION 'name must be 1 to 100 characters'; END IF;
  IF NOT EXISTS (SELECT 1 FROM mailbox.clients WHERE client_id = p_client_id AND p_redirect_uri = ANY (redirect_uris)) THEN
    RAISE EXCEPTION 'redirect_uri is not registered for this client';
  END IF;
  INSERT INTO mailbox.auth_codes (code_hash, client_id, user_id, role, redirect_uri, code_challenge, expires_at, agent_name)
  VALUES (decode(p_code_hash, 'hex'), p_client_id, p_user_id, p_role, p_redirect_uri, p_challenge,
          now() + make_interval(secs => p_ttl_seconds), v_name);
END;
$$;

DROP FUNCTION public.mailbox_take_code(TEXT);
CREATE FUNCTION public.mailbox_take_code(p_code_hash TEXT)
RETURNS TABLE (client_id TEXT, user_id UUID, role TEXT, redirect_uri TEXT, code_challenge TEXT, expired BOOLEAN, agent_name TEXT)
LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  DELETE FROM mailbox.auth_codes c WHERE c.code_hash = decode(p_code_hash, 'hex')
  RETURNING c.client_id, c.user_id, c.role, c.redirect_uri, c.code_challenge, c.expires_at < now(), c.agent_name
$$;

DROP FUNCTION public.mailbox_connect(UUID, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, TEXT, INTEGER);
CREATE FUNCTION public.mailbox_connect(
  p_user_id UUID, p_client_id TEXT, p_role TEXT, p_public_key TEXT, p_wrapped TEXT, p_wrapped_refresh TEXT,
  p_access_hash TEXT, p_refresh_hash TEXT, p_access_ttl_seconds INTEGER, p_agent_name TEXT DEFAULT NULL
) RETURNS UUID LANGUAGE sql SECURITY DEFINER SET search_path = '' AS $$
  INSERT INTO mailbox.connections (user_id, client_id, agent_name, role, public_key, wrapped_private_key,
                                   wrapped_private_key_refresh, access_token_hash, refresh_token_hash, access_expires_at,
                                   refresh_expires_at)
  SELECT p_user_id, c.client_id, coalesce(nullif(btrim(p_agent_name), ''), c.client_name), p_role, decode(p_public_key, 'hex'),
         decode(p_wrapped, 'hex'), decode(p_wrapped_refresh, 'hex'), decode(p_access_hash, 'hex'), decode(p_refresh_hash, 'hex'),
         now() + make_interval(secs => p_access_ttl_seconds), now() + interval '30 days'
    FROM mailbox.clients c WHERE c.client_id = p_client_id
  RETURNING id
$$;

REVOKE ALL ON FUNCTION public.mailbox_create_code(text, text, uuid, text, text, text, integer, text) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.mailbox_take_code(text) FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.mailbox_connect(uuid, text, text, text, text, text, text, text, integer, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.mailbox_create_code(text, text, uuid, text, text, text, integer, text) TO service_role;
GRANT EXECUTE ON FUNCTION public.mailbox_take_code(text) TO service_role;
GRANT EXECUTE ON FUNCTION public.mailbox_connect(uuid, text, text, text, text, text, text, text, integer, text) TO service_role;

NOTIFY pgrst, 'reload schema';
