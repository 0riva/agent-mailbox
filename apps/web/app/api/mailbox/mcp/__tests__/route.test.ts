/**
 * @jest-environment node
 *
 * The MCP endpoint's door (o-core#2069): no token, a stopped or unknown connection and an expired
 * token all get 401 with the discovery pointer; a busy agent gets 429; the wire format is JSON-RPC
 * over plain JSON responses. The tools themselves are tested in lib/mailbox/__tests__/mcp.test.ts.
 */
export {};

import { hashToken, newToken } from '../../../../../lib/mailbox/crypto';
import type { Caller, MailboxStore } from '../../../../../lib/mailbox/store';

const token = newToken();
const caller: Caller = { id: 'c1', userId: 'u1', role: 'worker', agentName: 'Grok Bot', publicKey: Buffer.alloc(32), wrapped: Buffer.alloc(76), expired: false };
let mockByAccess: (h: Buffer) => Promise<Caller | null>;
let mockAllowed = true;
let mockHits = 0;
const mockStore = {
  byAccess: (h: Buffer) => mockByAccess(h),
  rateLimit: async () => { mockHits += 1; return mockAllowed; },
  peers: async () => [],
} as unknown as MailboxStore;

jest.mock('../../../_lib/serviceRoleClient', () => ({ serviceRoleClient: () => ({}) }));
jest.mock('../../../../../lib/mailbox/store', () => ({ rpcStore: () => mockStore }));

const route = require('../route') as { POST: (r: Request) => Promise<Response>; GET: () => Response; OPTIONS: () => Response };
const post = (body: unknown, auth: string | null = `Bearer ${token}`) =>
  route.POST(new Request('https://oriva.io/api/mailbox/mcp', { method: 'POST', headers: { 'content-type': 'application/json', ...(auth ? { authorization: auth } : {}) }, body: typeof body === 'string' ? body : JSON.stringify(body) }));

beforeEach(() => {
  mockByAccess = async (h) => (h.equals(hashToken(token)) ? caller : null);
  mockAllowed = true;
  mockHits = 0;
  jest.spyOn(console, 'error').mockImplementation(() => undefined);
});
afterEach(() => jest.restoreAllMocks());

it('401s without a token and says where to Connect', async () => {
  const res = await post({ jsonrpc: '2.0', id: 1, method: 'ping' }, null);
  expect(res.status).toBe(401);
  expect(res.headers.get('www-authenticate')).toBe('Bearer resource_metadata="https://oriva.io/.well-known/oauth-protected-resource/api/mailbox/mcp", error="invalid_token"');
  expect(res.headers.get('access-control-expose-headers')).toContain('WWW-Authenticate');
});

it('401s for a malformed, unknown or stopped connection', async () => {
  expect((await post({ jsonrpc: '2.0', id: 1, method: 'ping' }, 'Bearer not-a-token')).status).toBe(401);
  expect((await post({ jsonrpc: '2.0', id: 1, method: 'ping' }, `Bearer ${newToken()}`)).status).toBe(401);
});

it('401s for an expired access token so the agent refreshes', async () => {
  mockByAccess = async () => ({ ...caller, expired: true });
  const res = await post({ jsonrpc: '2.0', id: 1, method: 'ping' });
  expect(res.status).toBe(401);
  expect((await res.json()).error_description).toContain('expired');
});

it('429s a busy agent', async () => {
  mockAllowed = false;
  const res = await post({ jsonrpc: '2.0', id: 1, method: 'ping' });
  expect(res.status).toBe(429);
  expect(res.headers.get('retry-after')).toBe('60');
});

it('counts every tool call in a batch against the limit, not just the request', async () => {
  const calls = Array.from({ length: 3 }, (_, i) => ({ jsonrpc: '2.0', id: i, method: 'tools/call', params: { name: 'list_agents', arguments: {} } }));
  await post([...calls, { jsonrpc: '2.0', id: 9, method: 'ping' }]);
  expect(mockHits).toBe(3);
  mockHits = 0;
  await post({ jsonrpc: '2.0', id: 1, method: 'ping' });
  expect(mockHits).toBe(1);
});

it('refuses an oversized body', async () => {
  expect((await post({ jsonrpc: '2.0', id: 1, method: 'ping', params: { pad: 'x'.repeat(4_300_000) } })).status).toBe(413);
});

it('answers one failed item without failing the rest of the batch', async () => {
  const realPeers = (mockStore as any).peers;
  (mockStore as any).peers = async () => { throw new Error('db-host-01 down'); };
  const res = await post([{ jsonrpc: '2.0', id: 1, method: 'ping' }, { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'list_agents', arguments: {} } }]);
  (mockStore as any).peers = realPeers;
  const body = await res.json();
  expect(res.status).toBe(200);
  expect(body[0]).toEqual({ jsonrpc: '2.0', id: 1, result: {} });
  expect(body[1].error.code).toBe(-32603);
  expect(JSON.stringify(body)).not.toContain('db-host-01');
});

it('answers single requests, batches and notifications', async () => {
  expect(await (await post({ jsonrpc: '2.0', id: 1, method: 'ping' })).json()).toEqual({ jsonrpc: '2.0', id: 1, result: {} });
  const batch = await (await post([{ jsonrpc: '2.0', id: 1, method: 'ping' }, { jsonrpc: '2.0', method: 'notifications/initialized' }, { jsonrpc: '2.0', id: 2, method: 'tools/list' }])).json();
  expect(batch.map((r: { id: number }) => r.id)).toEqual([1, 2]);
  expect((await post({ jsonrpc: '2.0', method: 'notifications/initialized' })).status).toBe(202);
});

it('rejects bad JSON and oversized batches', async () => {
  expect((await post('{not json')).status).toBe(400);
  expect((await post(Array.from({ length: 21 }, (_, i) => ({ jsonrpc: '2.0', id: i, method: 'ping' })))).status).toBe(400);
  expect((await post([])).status).toBe(400);
});

it('hides a server fault behind a generic message', async () => {
  mockByAccess = async () => { throw new Error('db-host-01 unreachable'); };
  const res = await post({ jsonrpc: '2.0', id: 1, method: 'ping' });
  expect(res.status).toBe(500);
  expect(JSON.stringify(await res.json())).not.toContain('db-host-01');
});

it('has no event stream, and answers CORS preflight', () => {
  expect(route.GET().status).toBe(405);
  expect(route.OPTIONS().status).toBe(204);
});

describe('protocol revision 2026-07-28 at the door (o-core#2367)', () => {
  const envelope = { 'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {} };
  const modern = (body: unknown, headers: Record<string, string>) =>
    route.POST(new Request('https://oriva.io/api/mailbox/mcp', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}`, 'mcp-protocol-version': '2026-07-28', ...headers },
      body: JSON.stringify(body),
    }));

  it('answers discovery with the status and body the new path decides', async () => {
    const res = await modern({ jsonrpc: '2.0', id: 1, method: 'server/discover', params: { _meta: envelope } }, { 'mcp-method': 'server/discover' });
    expect(res.status).toBe(200);
    expect((await res.json()).result.supportedVersions).toEqual(['2026-07-28']);
  });

  it('passes a header mismatch through as 400 and an unknown method as 404', async () => {
    const bad = await modern({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: { _meta: envelope } }, { 'mcp-method': 'tools/call' });
    expect(bad.status).toBe(400);
    expect((await bad.json()).error.code).toBe(-32020);
    const missing = await modern({ jsonrpc: '2.0', id: 2, method: 'prompts/list', params: { _meta: envelope } }, { 'mcp-method': 'prompts/list' });
    expect(missing.status).toBe(404);
  });

  it('refuses a 2026-07-28 request inside a batch', async () => {
    const res = await post([{ jsonrpc: '2.0', id: 1, method: 'server/discover', params: { _meta: envelope } }, { jsonrpc: '2.0', id: 2, method: 'ping' }]);
    expect(res.status).toBe(400);
    expect((await res.json()).error.code).toBe(-32600);
  });

  it('answers a 2026-07-28 notification 202 with no body', async () => {
    const res = await modern({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { _meta: envelope } }, { 'mcp-method': 'notifications/cancelled' });
    expect(res.status).toBe(202);
    expect(await res.text()).toBe('');
  });

  it('lets the new headers through a browser preflight', () => {
    expect(route.OPTIONS().headers.get('access-control-allow-headers')).toMatch(/Mcp-Method, Mcp-Name/);
  });
});
