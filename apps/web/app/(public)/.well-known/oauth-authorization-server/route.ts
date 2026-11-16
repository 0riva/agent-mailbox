/** RFC 8414 authorization-server metadata for the agent mailbox's sign-in (o-core#2069). */
import { preflight, json } from '../../../../lib/mailbox/http';
import { authorizationServerMetadata, mailboxOrigin } from '../../../../lib/mailbox/oauth';

export const dynamic = 'force-dynamic';

export function GET(request: Request) {
  return json(authorizationServerMetadata(mailboxOrigin(request.url)), 200, { 'Cache-Control': 'public, max-age=300' });
}

export const OPTIONS = preflight;
