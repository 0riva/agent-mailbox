/** RFC 7591 dynamic client registration for agents connecting to the mailbox (o-core#2069). */
import { createHash } from 'node:crypto';

import { serviceRoleClient } from '../../../_lib/serviceRoleClient';
import { json, oauthErrorResponse, preflight } from '../../../../../lib/mailbox/http';
import { registerClient } from '../../../../../lib/mailbox/oauth';
import { rpcStore } from '../../../../../lib/mailbox/store';

export const dynamic = 'force-dynamic';

/** Registrations per caller address per hour. Each Connect registers once; this stops a flood. */
export const REGISTRATIONS_PER_HOUR = 10;

/** The caller's address, hashed: counted, never stored in the clear. */
function callerKey(request: Request): string {
  const ip = ((request.headers.get('x-forwarded-for') ?? '').split(',')[0] ?? '').trim() || request.headers.get('x-real-ip') || 'unknown';
  return `register:${createHash('sha256').update(ip).digest('hex').slice(0, 32)}`;
}

export async function POST(request: Request) {
  try {
    const store = rpcStore(serviceRoleClient());
    if (!(await store.requestLimit(callerKey(request), REGISTRATIONS_PER_HOUR))) {
      return json({ error: 'slow_down', error_description: 'Too many registrations from this address. Try again in an hour.' }, 429, { 'Retry-After': '3600' });
    }
    const body = await request.json().catch(() => null);
    return json(await registerClient(store, body), 201);
  } catch (error) {
    return oauthErrorResponse(error, 'register');
  }
}

export const OPTIONS = preflight;
