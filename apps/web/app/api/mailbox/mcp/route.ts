/**
 * The agent mailbox MCP endpoint (o-core#2069): Streamable HTTP, stateless, JSON responses.
 * An unsigned or unknown caller gets 401 with WWW-Authenticate pointing at the protected-resource
 * document — that is how Claude and Grok Bot discover where to send the owner to Connect.
 */
import { serviceRoleClient } from '../../_lib/serviceRoleClient';
import { hashToken } from '../../../../lib/mailbox/crypto';
import { PUBLIC_CORS, json, preflight } from '../../../../lib/mailbox/http';
import { REQUESTS_PER_MINUTE, handleRpc } from '../../../../lib/mailbox/mcp';
import { handleModern, isModern } from '../../../../lib/mailbox/modern';
import { mailboxOrigin } from '../../../../lib/mailbox/oauth';
import { rpcStore } from '../../../../lib/mailbox/store';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

/** 20 messages of 200 KB, plus JSON. */
const MAX_BODY_BYTES = 4 * 1024 * 1024 + 64 * 1024;

function challenge(origin: string, description: string) {
  return json({ error: 'invalid_token', error_description: description }, 401, {
    'WWW-Authenticate': `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource/api/mailbox/mcp", error="invalid_token"`,
  });
}

export async function POST(request: Request) {
  const origin = mailboxOrigin(request.url);
  const token = (request.headers.get('authorization') ?? '').match(/^Bearer\s+(omb_[A-Za-z0-9_-]{43})$/)?.[1];
  if (!token) return challenge(origin, 'Connect this agent to Oriva first.');

  const store = rpcStore(serviceRoleClient());
  try {
    const caller = await store.byAccess(hashToken(token));
    if (!caller) return challenge(origin, 'This connection was stopped or never existed. Connect again.');
    if (caller.expired) return challenge(origin, 'The access token has expired. Refresh it.');
    const raw = await request.text();
    if (Buffer.byteLength(raw, 'utf8') > MAX_BODY_BYTES) {
      return json({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Request too large.' } }, 413);
    }
    let body: unknown;
    try {
      body = JSON.parse(raw);
    } catch {
      return json({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }, 400);
    }
    const batch = Array.isArray(body) ? body : [body];
    if (!batch.length || batch.length > 20) return json({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid request' } }, 400);

    // Every tool call counts against the per-minute limit, not only the HTTP request carrying it.
    const toolCalls = batch.filter((r) => (r as { method?: unknown })?.method === 'tools/call').length;
    for (let i = 0; i < Math.max(toolCalls, 1); i += 1) {
      if (!(await store.rateLimit(caller.id, REQUESTS_PER_MINUTE))) {
        return json({ jsonrpc: '2.0', id: null, error: { code: -32000, message: 'Too many requests. Wait a minute.' } }, 429, { 'Retry-After': '60' });
      }
    }

    const ctx = { store, caller, accessToken: token };

    // Protocol revision 2026-07-28 (o-core#2367): one request per POST, answered by modern.ts with the
    // HTTP status the revision requires. Everything else is the 2025-era path below, unchanged.
    if (batch.some(isModern)) {
      if (Array.isArray(body)) return json({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'A 2026-07-28 request cannot be sent in a batch.' } }, 400);
      try {
        const answer = await handleModern(ctx, body as Parameters<typeof handleModern>[1], request.headers);
        return answer.body ? json(answer.body, answer.status) : new Response(null, { status: 202, headers: PUBLIC_CORS });
      } catch (error) {
        console.error('[mailbox] mcp modern item failed', error instanceof Error ? error.message : error);
        return json({ jsonrpc: '2.0', id: (body as { id?: unknown })?.id ?? null, error: { code: -32603, message: 'Something went wrong. Try again.' } }, 500);
      }
    }

    const out = [];
    for (const req of batch) {
      // One failing item does not fail the others (they may already have marked mail read).
      try {
        const res = await handleRpc(ctx, (req ?? {}) as Parameters<typeof handleRpc>[1]);
        if (res) out.push(res);
      } catch (error) {
        console.error('[mailbox] mcp item failed', error instanceof Error ? error.message : error);
        const id = (req as { id?: unknown })?.id;
        if (id !== undefined) out.push({ jsonrpc: '2.0', id, error: { code: -32603, message: 'Something went wrong. Try again.' } });
      }
    }
    if (!out.length) return new Response(null, { status: 202, headers: PUBLIC_CORS });
    return json(Array.isArray(body) ? out : out[0]);
  } catch (error) {
    console.error('[mailbox] mcp failed', error instanceof Error ? error.message : error);
    return json({ jsonrpc: '2.0', id: null, error: { code: -32603, message: 'Something went wrong. Try again.' } }, 500);
  }
}

export function GET() {
  return json({ error: 'Use POST. This server answers each request on its own and has no event stream.' }, 405, { Allow: 'POST, OPTIONS' });
}

export const OPTIONS = preflight;
