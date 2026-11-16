/**
 * /oauth — the consent page an AI agent (Claude, Grok Bot, …) sends the owner to when it asks to
 * connect to their Oriva agent mailbox (o-core#2069). The request is checked here, on the server,
 * before anything is shown: an unknown app or an unregistered return address gets an error page and
 * is never redirected to. The owner chooses what the agent does and presses Allow or Cancel.
 */
import type { Metadata } from 'next';

import { createViewerServerClient } from '../../lib/supabase-auth-server';
import { OAuthError, mailboxOrigin, resourceUrl, validateAuthorize } from '../../lib/mailbox/oauth';
import { rpcStore } from '../../lib/mailbox/store';
import { serviceRoleClient } from '../api/_lib/serviceRoleClient';
import { ConsentClient } from './ConsentClient';
import { headers } from 'next/headers';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Connect an AI agent · Oriva', robots: { index: false, follow: false } };

type Search = Record<string, string | string[] | undefined>;

/** Which Oriva account is about to be connected, with the address masked (f***@domain). */
function maskedAccount(email: string | undefined | null): string {
  if (!email || !email.includes('@')) return 'your Oriva account';
  const [local = '', domain = ''] = email.split('@');
  return `${local.slice(0, 1)}***@${domain}`;
}

export default async function OAuthConsentPage({ searchParams }: { searchParams: Promise<Search> }) {
  const raw = await searchParams;
  const params = Object.fromEntries(Object.entries(raw).map(([k, v]) => [k, Array.isArray(v) ? v[0] : v]));
  const h = await headers();
  const origin = mailboxOrigin(`${h.get('x-forwarded-proto') ?? 'https'}://${h.get('host') ?? 'oriva.io'}/`);

  let request;
  try {
    request = await validateAuthorize(rpcStore(serviceRoleClient()), params, resourceUrl(origin));
  } catch (error) {
    const message = error instanceof OAuthError ? error.message : 'This connection request could not be checked. Try again from your agent.';
    if (!(error instanceof OAuthError)) console.error('[mailbox] consent validation failed', error instanceof Error ? error.message : error);
    return <ConsentClient state="invalid" message={message} />;
  }

  const db = await createViewerServerClient();
  const { data } = await db.auth.getUser();
  const user = data?.user;
  if (!user) return <ConsentClient state="signed-out" agentName={request.clientName} />;
  if (user.is_anonymous) return <ConsentClient state="anonymous" agentName={request.clientName} />;

  return (
    <ConsentClient
      state="ready"
      agentName={request.clientName}
      returnHost={request.redirectHost}
      verified={request.verified}
      local={request.local}
      account={maskedAccount(user.email)}
      request={{
        client_id: request.clientId,
        redirect_uri: request.redirectUri,
        code_challenge: request.codeChallenge,
        state: request.state ?? '',
      }}
    />
  );
}
