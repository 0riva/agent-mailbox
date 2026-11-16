/**
 * RFC 9728 protected-resource metadata for the agent mailbox (o-core#2069): where an agent that was
 * told 401 by /api/mailbox/mcp goes to sign in. Served at the bare path and at the path-suffixed
 * form (/.well-known/oauth-protected-resource/api/mailbox/mcp), since clients use both.
 */
import { preflight, json } from '../../../../../lib/mailbox/http';
import { mailboxOrigin, protectedResourceMetadata } from '../../../../../lib/mailbox/oauth';

export const dynamic = 'force-dynamic';

export function GET(request: Request) {
  return json(protectedResourceMetadata(mailboxOrigin(request.url)), 200, { 'Cache-Control': 'public, max-age=300' });
}

export const OPTIONS = preflight;
