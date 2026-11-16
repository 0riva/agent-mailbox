/**
 * @jest-environment node
 *
 * The /oauth consent page decides what to show before anything renders (o-core#2069): an invalid
 * request is shown an error and never redirected; signed-out and anonymous owners are told what to
 * do; a signed-in owner gets the request the page validated, never the raw query.
 */
export {};

import { createHash, randomBytes } from 'node:crypto';

import { memoryStore } from '../../../lib/mailbox/__tests__/helpers/memoryStore';
import { registerClient } from '../../../lib/mailbox/oauth';

let mockStore = memoryStore().store;
let mockUser: { id: string; email?: string; is_anonymous?: boolean } | null = { id: 'u1', email: 'gavriel@example.com' };

jest.mock('../ConsentClient', () => ({ ConsentClient: () => null }));
jest.mock('../../api/_lib/serviceRoleClient', () => ({ serviceRoleClient: () => ({}) }));
jest.mock('../../../lib/mailbox/store', () => ({ rpcStore: () => mockStore }));
jest.mock('../../../lib/supabase-auth-server', () => ({
  createViewerServerClient: async () => ({ auth: { getUser: async () => ({ data: { user: mockUser } }) } }),
}));
jest.mock('next/headers', () => ({ headers: async () => new Map([['host', 'oriva.io'], ['x-forwarded-proto', 'https']]) }));

const Page = (require('../page') as { default: (p: { searchParams: Promise<Record<string, string>> }) => Promise<{ props: Record<string, unknown> }> }).default;
const REDIRECT = 'https://claude.ai/api/mcp/auth_callback';

async function query(overrides: Record<string, string> = {}) {
  const reg = await registerClient(mockStore, { client_name: 'Claude', redirect_uris: [REDIRECT] });
  const challenge = createHash('sha256').update(randomBytes(32).toString('base64url')).digest('base64url');
  return { response_type: 'code', client_id: reg.client_id, redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: 'S256', state: 'xyz', ...overrides };
}

beforeEach(() => {
  mockStore = memoryStore().store;
  mockUser = { id: 'u1', email: 'gavriel@example.com' };
  jest.spyOn(console, 'error').mockImplementation(() => undefined);
});
afterEach(() => jest.restoreAllMocks());

it('shows an error, and no redirect, for an unregistered return address', async () => {
  const el = await Page({ searchParams: Promise.resolve(await query({ redirect_uri: 'https://evil.example/cb' })) });
  expect(el.props.state).toBe('invalid');
  expect(el.props).not.toHaveProperty('request');
});

it('shows a generic error when the check itself fails', async () => {
  mockStore = { ...mockStore, client: async () => { throw new Error('db down'); } };
  const el = await Page({ searchParams: Promise.resolve({ response_type: 'code', client_id: 'mbc_x' }) });
  expect(el.props.state).toBe('invalid');
  expect(String(el.props.message)).not.toContain('db down');
});

it('asks a signed-out owner to log in', async () => {
  mockUser = null;
  const el = await Page({ searchParams: Promise.resolve(await query()) });
  expect(el.props).toMatchObject({ state: 'signed-out', agentName: 'Claude' });
});

it('asks an anonymous owner to add an email first', async () => {
  mockUser = { id: 'u1', is_anonymous: true };
  const el = await Page({ searchParams: Promise.resolve(await query()) });
  expect(el.props.state).toBe('anonymous');
});

it('hands a signed-in owner the validated request and the return host', async () => {
  const q = await query();
  const el = await Page({ searchParams: Promise.resolve({ ...q, extra: 'ignored' }) });
  expect(el.props).toMatchObject({ state: 'ready', agentName: 'Claude', returnHost: 'claude.ai', verified: true, local: false, account: 'g***@example.com' });
  expect(el.props.request).toEqual({ client_id: q.client_id, redirect_uri: REDIRECT, code_challenge: q.code_challenge, state: 'xyz' });
});
