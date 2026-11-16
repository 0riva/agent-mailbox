/**
 * Settings → Agents → Agent mailbox (o-core#2069).
 *
 *   GET  → { agents: [{ id, name, role, connectedAt, lastUsedAt, stoppedAt }], activity: [{ id, from, to, kind, size, sentAt, readAt }] }
 *   PATCH { connectionId, name } → renames that agent: the name other agents see in list_agents and
 *        address tasks by (Grok Bot's connector arrives as "Cursor").
 *   POST { connectionId } → stops that agent: its keys and tokens are deleted, so anything still
 *        waiting for it can no longer be opened and its next request is refused.
 *
 * The owner's own browser session only (signedInOwner refuses any bearer token, so a connected
 * agent can never stop another or read this list). Message CONTENTS are never returned: the
 * database function behind this reads metadata only.
 */
import { NextResponse } from 'next/server';

import { signedInOwner } from '../../../../lib/agents/signedInOwner';
import { mailboxOrigin } from '../../../../lib/mailbox/oauth';
import { rpcStore } from '../../../../lib/mailbox/store';
import { serviceRoleClient } from '../../_lib/serviceRoleClient';

export const dynamic = 'force-dynamic';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function GET(request: Request) {
  const owner = await signedInOwner(request);
  if ('error' in owner) return owner.error;
  try {
    return NextResponse.json(await rpcStore(serviceRoleClient()).overview(owner.userId), { headers: { 'Cache-Control': 'no-store' } });
  } catch (error) {
    console.error('[mailbox] overview failed', error instanceof Error ? error.message : error);
    return NextResponse.json({ error: 'Could not read your agent mailbox.' }, { status: 500 });
  }
}

export async function PATCH(request: Request) {
  if (request.headers.get('origin') !== mailboxOrigin(request.url)) {
    return NextResponse.json({ error: 'Rename agents from Settings on oriva.io.' }, { status: 403 });
  }
  const owner = await signedInOwner(request);
  if ('error' in owner) return owner.error;
  const body = (await request.json().catch(() => null)) as { connectionId?: unknown; name?: unknown } | null;
  if (!body || typeof body.connectionId !== 'string' || !UUID.test(body.connectionId)) {
    return NextResponse.json({ error: 'Say which agent to rename.' }, { status: 400 });
  }
  const name = typeof body.name === 'string' ? body.name.trim() : '';
  if (!name || name.length > 100) return NextResponse.json({ error: 'Give the agent a name of 1 to 100 characters.' }, { status: 400 });
  try {
    const renamed = await rpcStore(serviceRoleClient()).rename(owner.userId, body.connectionId, name);
    if (!renamed) return NextResponse.json({ error: 'That agent is not connected to your mailbox, or is stopped.' }, { status: 404 });
    return NextResponse.json({ renamed: true, name });
  } catch (error) {
    console.error('[mailbox] rename failed', error instanceof Error ? error.message : error);
    return NextResponse.json({ error: 'Could not rename that agent. Try again.' }, { status: 500 });
  }
}

export async function POST(request: Request) {
  if (request.headers.get('origin') !== mailboxOrigin(request.url)) {
    return NextResponse.json({ error: 'Stop agents from Settings on oriva.io.' }, { status: 403 });
  }
  const owner = await signedInOwner(request);
  if ('error' in owner) return owner.error;
  const body = (await request.json().catch(() => null)) as { connectionId?: unknown } | null;
  if (!body || typeof body.connectionId !== 'string' || !UUID.test(body.connectionId)) {
    return NextResponse.json({ error: 'Say which agent to stop.' }, { status: 400 });
  }
  try {
    const stopped = await rpcStore(serviceRoleClient()).stop(owner.userId, body.connectionId);
    if (!stopped) return NextResponse.json({ error: 'That agent is not connected to your mailbox, or is already stopped.' }, { status: 404 });
    return NextResponse.json({ stopped: true });
  } catch (error) {
    console.error('[mailbox] stop failed', error instanceof Error ? error.message : error);
    return NextResponse.json({ error: 'Could not stop that agent. Try again.' }, { status: 500 });
  }
}
