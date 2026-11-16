-- Agent mailbox: the owner can rename a connected agent (o-core#2069).
--
-- An agent arrives with the name its app sends, which is not always the name the owner knows it
-- by (Grok Bot's connector registers as "Cursor"). Other agents see this name in list_agents and
-- address tasks by it, so the owner sets it in Settings → Agents. Only the owner's own, active
-- agents can be renamed; service_role only, like every mailbox function.
CREATE FUNCTION public.mailbox_rename(p_user_id UUID, p_connection UUID, p_name TEXT)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE
  v_name TEXT := btrim(p_name);
BEGIN
  IF v_name IS NULL OR char_length(v_name) NOT BETWEEN 1 AND 100 THEN
    RAISE EXCEPTION 'name must be 1 to 100 characters';
  END IF;
  UPDATE mailbox.connections SET agent_name = v_name
   WHERE id = p_connection AND user_id = p_user_id AND stopped_at IS NULL;
  RETURN FOUND;
END;
$$;
REVOKE ALL ON FUNCTION public.mailbox_rename(uuid, uuid, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.mailbox_rename(uuid, uuid, text) TO service_role;

NOTIFY pgrst, 'reload schema';
