/**
 * Allow or Cancel on the /oauth consent page (o-core#2069). The owner's own browser session only
 * (signedInOwner refuses any request carrying a bearer token), same-origin only, and the request is
 * re-validated here rather than trusted from the page. Answers with where to send the browser.
 */
import { NextResponse } from 'next/server';

import { signedInOwner } from '../../../../../lib/agents/signedInOwner';
import { OAuthError, approve, deny, mailboxOrigin, resourceUrl, validateAuthorize } from '../../../../../lib/mailbox/oauth';
import { rpcStore, type Role } from '../../../../../lib/mailbox/store';
import { serviceRoleClient } from '../../../_lib/serviceRoleClient';

export const dynamic = 'force-dynamic';

export async function POST(request: Request) {
  const origin = mailboxOrigin(request.url);
  if (request.headers.get('origin') !== origin) {
    return NextResponse.json({ error: 'Connect from the Oriva page your agent opened.' }, { status: 403 });
  }
  const owner = await signedInOwner(request);
  if ('error' in owner) return owner.error;

  const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
  const str = (k: string) => (typeof body[k] === 'string' ? (body[k] as string) : undefined);
  const store = rpcStore(serviceRoleClient());
  try {
    const req = await validateAuthorize(
      store,
      {
        response_type: 'code', client_id: str('client_id'), redirect_uri: str('redirect_uri'),
        code_challenge: str('code_challenge'), code_challenge_method: 'S256', state: str('state'),
      },
      resourceUrl(origin)
    );
    const redirectTo = str('decision') === 'allow' ? await approve(store, owner.userId, req, str('role') as Role, origin, str('name')) : deny(req, origin);
    return NextResponse.json({ redirectTo }, { headers: { 'Cache-Control': 'no-store' } });
  } catch (error) {
    if (error instanceof OAuthError) return NextResponse.json({ error: error.message }, { status: 400 });
    console.error('[mailbox] approve failed', error instanceof Error ? error.message : error);
    return NextResponse.json({ error: 'Something went wrong. Try again.' }, { status: 500 });
  }
}
