/** The mailbox's token endpoint: code exchange and refresh (o-core#2069). */
import { serviceRoleClient } from '../../../_lib/serviceRoleClient';
import { json, oauthErrorResponse, preflight, readParams } from '../../../../../lib/mailbox/http';
import { OAuthError, exchangeCode, refreshTokens } from '../../../../../lib/mailbox/oauth';
import { rpcStore } from '../../../../../lib/mailbox/store';

export const dynamic = 'force-dynamic';

export async function POST(request: Request) {
  try {
    const p = await readParams(request);
    const store = rpcStore(serviceRoleClient());
    if (p.grant_type === 'authorization_code') return json(await exchangeCode(store, p));
    if (p.grant_type === 'refresh_token') return json(await refreshTokens(store, p));
    throw new OAuthError('unsupported_grant_type', 'grant_type must be authorization_code or refresh_token');
  } catch (error) {
    return oauthErrorResponse(error, 'token');
  }
}

export const OPTIONS = preflight;
