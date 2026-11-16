/**
 * @jest-environment node
 *
 * The mailbox sign-in endpoints (o-core#2069): register, token, revoke and the consent page's
 * Allow/Cancel. The logic is tested in lib/mailbox/__tests__/oauth.test.ts; these pin the HTTP
 * contract — form-encoded OAuth bodies, RFC 6749 error shapes, CORS on the public endpoints, and
 * the refusals on Allow/Cancel (wrong origin, no owner session).
 */
export {};

import { createHash, randomBytes } from 'node:crypto';

import { memoryStore } from '../../../../../lib/mailbox/__tests__/helpers/memoryStore';

let mockStore = memoryStore().store;
let mockOwner: { userId: string } | { error: Response } = { userId: '02069000-0000-4000-8000-00000000000a' };

jest.mock('../../../_lib/serviceRoleClient', () => ({ serviceRoleClient: () => ({}) }));
jest.mock('../../../../../lib/mailbox/store', () => ({ rpcStore: () => mockStore }));
jest.mock('../../../../../lib/agents/signedInOwner', () => ({ signedInOwner: async () => mockOwner }));

const { POST: register } = require('../register/route') as { POST: (r: Request) => Promise<Response> };
const { POST: token } = require('../token/route') as { POST: (r: Request) => Promise<Response> };
const { POST: revoke } = require('../revoke/route') as { POST: (r: Request) => Promise<Response> };
const { POST: approveRoute } = require('../approve/route') as { POST: (r: Request) => Promise<Response> };

const ORIGIN = 'https://oriva.io';
const REDIRECT = 'https://claude.ai/api/mcp/auth_callback';
const form = (url: string, body: Record<string, string>) =>
  new Request(url, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body).toString() });
const jsonReq = (url: string, body: unknown, headers: Record<string, string> = {}) =>
  new Request(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });

function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
}

beforeEach(() => {
  mockStore = memoryStore().store;
  mockOwner = { userId: '02069000-0000-4000-8000-00000000000a' };
  delete process.env.ORIVA_MAILBOX_ORIGIN;
  jest.spyOn(console, 'error').mockImplementation(() => undefined);
});
afterEach(() => jest.restoreAllMocks());

async function registered() {
  const res = await register(jsonReq(`${ORIGIN}/api/mailbox/oauth/register`, { client_name: 'Claude', redirect_uris: [REDIRECT] }));
  return (await res.json()) as { client_id: string };
}

async function approved(decision: 'allow' | 'deny' = 'allow') {
  const { client_id } = await registered();
  const { verifier, challenge } = pkce();
  const res = await approveRoute(
    jsonReq(`${ORIGIN}/api/mailbox/oauth/approve`, { client_id, redirect_uri: REDIRECT, code_challenge: challenge, state: 's1', role: 'worker', decision }, { origin: ORIGIN })
  );
  return { res, client_id, verifier };
}

describe('register', () => {
  it('creates a public client, with CORS for agents in other apps', async () => {
    const res = await register(jsonReq(`${ORIGIN}/api/mailbox/oauth/register`, { client_name: 'Claude', redirect_uris: [REDIRECT] }));
    expect(res.status).toBe(201);
    expect(res.headers.get('access-control-allow-origin')).toBe('*');
    expect((await res.json()).client_id).toMatch(/^mbc_/);
  });

  it('limits registrations from one address', async () => {
    const from = (ip: string) => new Request(`${ORIGIN}/api/mailbox/oauth/register`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': ip }, body: JSON.stringify({ redirect_uris: [REDIRECT] }) });
    for (let i = 0; i < 10; i += 1) expect((await register(from('203.0.113.7'))).status).toBe(201);
    const blocked = await register(from('203.0.113.7'));
    expect(blocked.status).toBe(429);
    expect(blocked.headers.get('retry-after')).toBe('3600');
    expect((await register(from('198.51.100.2'))).status).toBe(201);
  });

  it('refuses an unsafe return address with an RFC 7591 error', async () => {
    const res = await register(jsonReq(`${ORIGIN}/api/mailbox/oauth/register`, { redirect_uris: ['http://evil.example/cb'] }));
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe('invalid_redirect_uri');
  });
});

describe('approve (the consent page)', () => {
  it('refuses another origin', async () => {
    const res = await approveRoute(jsonReq(`${ORIGIN}/api/mailbox/oauth/approve`, {}, { origin: 'https://evil.example' }));
    expect(res.status).toBe(403);
  });

  it('refuses a request with no origin', async () => {
    const res = await approveRoute(jsonReq(`${ORIGIN}/api/mailbox/oauth/approve`, {}));
    expect(res.status).toBe(403);
  });

  it('needs the owner signed in', async () => {
    mockOwner = { error: new Response(JSON.stringify({ error: 'Sign in first.' }), { status: 401 }) };
    const { res } = await approved();
    expect(res.status).toBe(401);
  });

  it('Allow sends the browser back with a code and the state', async () => {
    const { res } = await approved('allow');
    expect(res.status).toBe(200);
    const back = new URL((await res.json()).redirectTo);
    expect(`${back.origin}${back.pathname}`).toBe(REDIRECT);
    expect(back.searchParams.get('code')).toMatch(/^omb_/);
    expect(back.searchParams.get('state')).toBe('s1');
    expect(back.searchParams.get('iss')).toBe(ORIGIN);
  });

  it('Allow names the agent as the owner typed it, and refuses a blank name', async () => {
    const { client_id } = await registered();
    const { verifier, challenge } = pkce();
    const body = { client_id, redirect_uri: REDIRECT, code_challenge: challenge, state: 's1', role: 'worker', decision: 'allow' };
    const blank = await approveRoute(jsonReq(`${ORIGIN}/api/mailbox/oauth/approve`, { ...body, name: ' ' }, { origin: ORIGIN }));
    expect(blank.status).toBe(400);
    const res = await approveRoute(jsonReq(`${ORIGIN}/api/mailbox/oauth/approve`, { ...body, name: 'Grok Bot' }, { origin: ORIGIN }));
    const code = new URL((await res.json()).redirectTo).searchParams.get('code')!;
    await token(form(`${ORIGIN}/api/mailbox/oauth/token`, { grant_type: 'authorization_code', code, code_verifier: verifier, client_id, redirect_uri: REDIRECT }));
    const view = (await mockStore.overview('02069000-0000-4000-8000-00000000000a')) as { agents: Array<{ name: string }> };
    expect(view.agents.map((a) => a.name)).toEqual(['Grok Bot']);
  });

  it('Cancel sends back access_denied', async () => {
    const { res } = await approved('deny');
    expect(new URL((await res.json()).redirectTo).searchParams.get('error')).toBe('access_denied');
  });

  it('re-validates the request rather than trusting the page', async () => {
    const res = await approveRoute(
      jsonReq(`${ORIGIN}/api/mailbox/oauth/approve`, { client_id: 'mbc_forged', redirect_uri: REDIRECT, code_challenge: pkce().challenge, decision: 'allow', role: 'worker' }, { origin: ORIGIN })
    );
    expect(res.status).toBe(400);
  });

  it('honours a configured origin', async () => {
    process.env.ORIVA_MAILBOX_ORIGIN = 'https://staging.oriva.io';
    const res = await approveRoute(jsonReq(`${ORIGIN}/api/mailbox/oauth/approve`, {}, { origin: ORIGIN }));
    expect(res.status).toBe(403);
  });
});

describe('token', () => {
  it('exchanges a code from a form-encoded body, then refreshes', async () => {
    const { res, client_id, verifier } = await approved();
    const code = new URL((await res.json()).redirectTo).searchParams.get('code')!;
    const t = await token(form(`${ORIGIN}/api/mailbox/oauth/token`, { grant_type: 'authorization_code', code, code_verifier: verifier, client_id, redirect_uri: REDIRECT }));
    expect(t.status).toBe(200);
    expect(t.headers.get('cache-control')).toBe('no-store');
    const tokens = await t.json();
    expect(tokens.token_type).toBe('Bearer');
    const r = await token(form(`${ORIGIN}/api/mailbox/oauth/token`, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token }));
    expect(r.status).toBe(200);
    expect((await r.json()).access_token).not.toBe(tokens.access_token);
  });

  it('answers invalid_grant for a bad code', async () => {
    const t = await token(form(`${ORIGIN}/api/mailbox/oauth/token`, { grant_type: 'authorization_code', code: 'omb_x', code_verifier: 'v'.repeat(43), client_id: 'c', redirect_uri: REDIRECT }));
    expect(t.status).toBe(400);
    expect((await t.json()).error).toBe('invalid_grant');
  });

  it('refuses another grant type', async () => {
    const t = await token(form(`${ORIGIN}/api/mailbox/oauth/token`, { grant_type: 'password' }));
    expect((await t.json()).error).toBe('unsupported_grant_type');
  });

  it('never echoes an unexpected error', async () => {
    mockStore = { ...mockStore, takeCode: async () => { throw new Error('connection reset by db-host-01'); } };
    const t = await token(jsonReq(`${ORIGIN}/api/mailbox/oauth/token`, { grant_type: 'authorization_code', code: 'omb_x', code_verifier: 'v'.repeat(43), client_id: 'c', redirect_uri: REDIRECT }));
    expect(t.status).toBe(500);
    expect(JSON.stringify(await t.json())).not.toContain('db-host-01');
  });
});

describe('revoke', () => {
  it('always answers 200, and stops the agent the token belongs to', async () => {
    const { res, client_id, verifier } = await approved();
    const code = new URL((await res.json()).redirectTo).searchParams.get('code')!;
    const tokens = await (await token(form(`${ORIGIN}/api/mailbox/oauth/token`, { grant_type: 'authorization_code', code, code_verifier: verifier, client_id, redirect_uri: REDIRECT }))).json();
    expect((await revoke(form(`${ORIGIN}/api/mailbox/oauth/revoke`, { token: tokens.access_token }))).status).toBe(200);
    expect((await revoke(form(`${ORIGIN}/api/mailbox/oauth/revoke`, { token: 'omb_unknown' }))).status).toBe(200);
    const r = await token(form(`${ORIGIN}/api/mailbox/oauth/token`, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token }));
    expect(r.status).toBe(400);
  });
});
