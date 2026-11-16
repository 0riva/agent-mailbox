/**
 * @jest-environment node
 *
 * Settings → Agents → Agent mailbox route (o-core#2069): the owner's browser session only, a valid
 * agent id to stop, "not yours or already stopped" told apart from success, and no contents.
 */
export {};

let mockOwner: { userId: string } | { error: Response } = { userId: 'u1' };
let mockStop: (u: string, c: string) => Promise<boolean> = async () => true;
let mockOverview: (u: string) => Promise<unknown> = async () => ({ agents: [], activity: [] });
let mockRename: (u: string, c: string, n: string) => Promise<boolean> = async () => true;

jest.mock('../../../_lib/serviceRoleClient', () => ({ serviceRoleClient: () => ({}) }));
jest.mock('../../../../../lib/agents/signedInOwner', () => ({ signedInOwner: async () => mockOwner }));
jest.mock('../../../../../lib/mailbox/store', () => ({
  rpcStore: () => ({ stop: (u: string, c: string) => mockStop(u, c), overview: (u: string) => mockOverview(u), rename: (u: string, c: string, n: string) => mockRename(u, c, n) }),
}));

const { GET, POST, PATCH } = require('../route') as { GET: (r: Request) => Promise<Response>; POST: (r: Request) => Promise<Response>; PATCH: (r: Request) => Promise<Response> };
const patch = (body: unknown, origin: string | null = 'https://oriva.io') =>
  new Request('https://oriva.io/api/agents/mailbox', { method: 'PATCH', headers: { 'content-type': 'application/json', ...(origin ? { origin } : {}) }, body: JSON.stringify(body) });
const ID = '22222222-2222-4222-8222-222222222222';
const req = (body?: unknown, origin: string | null = 'https://oriva.io') =>
  new Request('https://oriva.io/api/agents/mailbox', body === undefined ? {} : { method: 'POST', headers: { 'content-type': 'application/json', ...(origin ? { origin } : {}) }, body: JSON.stringify(body) });

beforeEach(() => {
  mockOwner = { userId: 'u1' };
  mockStop = async () => true;
  mockOverview = async () => ({ agents: [], activity: [] });
  mockRename = async () => true;
  jest.spyOn(console, 'error').mockImplementation(() => undefined);
});
afterEach(() => jest.restoreAllMocks());

it('refuses anyone but the signed-in owner', async () => {
  mockOwner = { error: new Response('{}', { status: 403 }) };
  expect((await GET(req())).status).toBe(403);
  expect((await POST(req({ connectionId: ID }))).status).toBe(403);
});

it('refuses a Stop that did not come from Oriva itself', async () => {
  expect((await POST(req({ connectionId: ID }, 'https://evil.example'))).status).toBe(403);
  expect((await POST(req({ connectionId: ID }, null))).status).toBe(403);
});

it('reads the overview for the owner', async () => {
  let asked = '';
  mockOverview = async (u) => { asked = u; return { agents: [{ id: ID }], activity: [] }; };
  const res = await GET(req());
  expect(asked).toBe('u1');
  expect((await res.json()).agents[0].id).toBe(ID);
});

it('stops only the owner\'s agent, and says when there was nothing to stop', async () => {
  let args: string[] = [];
  mockStop = async (u, c) => { args = [u, c]; return true; };
  expect((await POST(req({ connectionId: ID }))).status).toBe(200);
  expect(args).toEqual(['u1', ID]);
  mockStop = async () => false;
  expect((await POST(req({ connectionId: ID }))).status).toBe(404);
});

describe('rename', () => {
  it('renames the owner\'s agent, trimmed', async () => {
    let args: string[] = [];
    mockRename = async (u, c, n) => { args = [u, c, n]; return true; };
    const res = await PATCH(patch({ connectionId: ID, name: '  Grok Bot  ' }));
    expect(res.status).toBe(200);
    expect(args).toEqual(['u1', ID, 'Grok Bot']);
  });

  it('refuses another origin, a non-owner, a bad id, a blank or long name', async () => {
    expect((await PATCH(patch({ connectionId: ID, name: 'x' }, 'https://evil.example'))).status).toBe(403);
    mockOwner = { error: new Response('{}', { status: 401 }) };
    expect((await PATCH(patch({ connectionId: ID, name: 'x' }))).status).toBe(401);
    mockOwner = { userId: 'u1' };
    expect((await PATCH(patch({ connectionId: 'nope', name: 'x' }))).status).toBe(400);
    expect((await PATCH(patch({ connectionId: ID, name: '   ' }))).status).toBe(400);
    expect((await PATCH(patch({ connectionId: ID, name: 'x'.repeat(101) }))).status).toBe(400);
  });

  it('says when the agent is not the owner\'s or is stopped, and hides faults', async () => {
    mockRename = async () => false;
    expect((await PATCH(patch({ connectionId: ID, name: 'x' }))).status).toBe(404);
    mockRename = async () => { throw new Error('db-host-01'); };
    const res = await PATCH(patch({ connectionId: ID, name: 'x' }));
    expect(res.status).toBe(500);
    expect(JSON.stringify(await res.json())).not.toContain('db-host-01');
  });
});

it('needs a valid agent id', async () => {
  expect((await POST(req({ connectionId: 'nope' }))).status).toBe(400);
  expect((await POST(req({}))).status).toBe(400);
});

it('hides a server fault', async () => {
  mockOverview = async () => { throw new Error('db-host-01'); };
  mockStop = async () => { throw new Error('db-host-01'); };
  const g = await GET(req());
  const p = await POST(req({ connectionId: ID }));
  expect([g.status, p.status]).toEqual([500, 500]);
  expect(JSON.stringify([await g.json(), await p.json()])).not.toContain('db-host-01');
});
