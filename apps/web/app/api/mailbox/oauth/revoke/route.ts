/** RFC 7009 revocation: an agent hands back a token and is disconnected (o-core#2069). */
import { serviceRoleClient } from '../../../_lib/serviceRoleClient';
import { json, oauthErrorResponse, preflight, readParams } from '../../../../../lib/mailbox/http';
import { revokeToken } from '../../../../../lib/mailbox/oauth';
import { rpcStore } from '../../../../../lib/mailbox/store';

export const dynamic = 'force-dynamic';

export async function POST(request: Request) {
  try {
    const p = await readParams(request);
    await revokeToken(rpcStore(serviceRoleClient()), p.token);
    return json({});
  } catch (error) {
    return oauthErrorResponse(error, 'revoke');
  }
}

export const OPTIONS = preflight;
