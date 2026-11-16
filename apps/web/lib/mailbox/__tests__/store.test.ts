/**
 * @jest-environment node
 *
 * The mailbox store's wire format (o-core#2069): each call reaches the right server-only database
 * function with bytes as hex, and each row comes back as Buffers and camelCase. A database error is
 * raised, never swallowed into an empty answer. The functions themselves are proven against the
 * real migration by `pnpm test:agent-mailbox`.
 */
export {};

import { rpcStore } from '../store';

function fakeDb(answers: Record<string, unknown> = {}, error?: string) {
  const calls: Array<[string, Record<string, unknown>]> = [];
  const db = {
    rpc: async (fn: string, args: Record<string, unknown>) => {
      calls.push([fn, args]);
      return error ? { data: null, error: { message: error } } : { data: answers[fn] ?? null, error: null };
    },
  };
  return { db: db as never, calls };
}

const b = (h: string) => Buffer.from(h, 'hex');

it('sends bytes as hex and names the right function', async () => {
  const { db, calls } = fakeDb({ mailbox_connect: 'conn-1', mailbox_rotate: true, mailbox_stop: true, mailbox_rate_limit: true, mailbox_mark_read: 2, mailbox_refresh_reused: true, mailbox_request_limit: false, mailbox_rename: true });
  const s = rpcStore(db);
  expect(await s.connect({ userId: 'u', clientId: 'c', role: 'worker', agentName: 'Grok Bot', publicKey: b('aa'), wrapped: b('bb'), wrappedRefresh: b('cc'), accessHash: b('dd'), refreshHash: b('ee'), accessTtlSeconds: 3600 })).toBe('conn-1');
  expect(calls[0]).toEqual(['mailbox_connect', {
    p_user_id: 'u', p_client_id: 'c', p_role: 'worker', p_public_key: 'aa', p_wrapped: 'bb', p_wrapped_refresh: 'cc',
    p_access_hash: 'dd', p_refresh_hash: 'ee', p_access_ttl_seconds: 3600, p_agent_name: 'Grok Bot',
  }]);
  expect(await s.rotate({ oldRefreshHash: b('01'), wrapped: b('02'), wrappedRefresh: b('03'), accessHash: b('04'), refreshHash: b('05'), accessTtlSeconds: 60 })).toBe(true);
  expect(calls[1]).toEqual(['mailbox_rotate', { p_old_refresh_hash: '01', p_wrapped: '02', p_wrapped_refresh: '03', p_access_hash: '04', p_refresh_hash: '05', p_access_ttl_seconds: 60 }]);
  await s.createCode({ codeHash: b('ff'), clientId: 'c', userId: 'u', role: 'dispatcher', redirectUri: 'https://x/cb', challenge: 'ch', ttlSeconds: 300, agentName: null });
  expect(calls[2]).toEqual(['mailbox_create_code', { p_code_hash: 'ff', p_client_id: 'c', p_user_id: 'u', p_role: 'dispatcher', p_redirect_uri: 'https://x/cb', p_challenge: 'ch', p_ttl_seconds: 300, p_agent_name: null }]);
  await s.post({ id: 'm', from: 'f', to: 't', kind: 'task', replyTo: null, ephemeralPublicKey: b('11'), nonce: b('22'), ciphertext: b('33'), size: 1 });
  expect(calls[3]).toEqual(['mailbox_post', { p_id: 'm', p_from: 'f', p_to: 't', p_kind: 'task', p_reply_to: null, p_ephemeral_public_key: '11', p_nonce: '22', p_ciphertext: '33', p_size: 1 }]);
  expect(await s.stop('u', 'conn-1')).toBe(true);
  expect(await s.rateLimit('conn-1', 60)).toBe(true);
  expect(await s.markRead('conn-1', ['m'])).toBe(2);
  await s.revoke(b('99'));
  await s.registerClient('c', 'Claude', ['https://x/cb']);
  expect(await s.refreshReused(b('77'))).toBe(true);
  expect(await s.rename('u', 'conn-1', 'Grok Bot')).toBe(true);
  expect(await s.requestLimit('register:abc', 10)).toBe(false);
  expect(calls.slice(-3)).toEqual([
    ['mailbox_refresh_reused', { p_refresh_hash: '77' }],
    ['mailbox_rename', { p_user_id: 'u', p_connection: 'conn-1', p_name: 'Grok Bot' }],
    ['mailbox_request_limit', { p_key: 'register:abc', p_limit: 10 }],
  ]);
  expect(calls.slice(4).map((c) => c[0])).toEqual(['mailbox_stop', 'mailbox_rate_limit', 'mailbox_mark_read', 'mailbox_revoke', 'mailbox_register_client', 'mailbox_refresh_reused', 'mailbox_rename', 'mailbox_request_limit']);
  expect(calls[7][1]).toEqual({ p_token_hash: '99' });
});

it('turns rows into Buffers and camelCase', async () => {
  const { db } = fakeDb({
    mailbox_client: [{ client_name: 'Claude', redirect_uris: ['https://x/cb'] }],
    mailbox_take_code: [{ client_id: 'c', user_id: 'u', role: 'worker', redirect_uri: 'https://x/cb', code_challenge: 'ch', expired: false, agent_name: 'Grok Bot' }],
    mailbox_by_access: [{ id: 'i', user_id: 'u', role: 'worker', agent_name: 'Grok Bot', public_key: 'aa', wrapped: 'bb', expired: false }],
    mailbox_by_refresh: [{ id: 'i', client_id: 'c', public_key: 'aa', wrapped_refresh: 'cc', expired: false }],
    mailbox_peers: [{ id: 'p', role: 'dispatcher', agent_name: 'Claude', public_key: 'dd' }],
    mailbox_inbox: [{ id: 'm', user_id: 'u', from_connection: 'p', from_name: 'Claude', kind: 'task', reply_to: null, ephemeral_public_key: '11', nonce: '22', ciphertext: '33', created_at: 't' }],
    mailbox_overview: { agents: [], activity: [] },
    mailbox_message_sender: [{ from_connection: 'p', kind: 'task' }],
  });
  const s = rpcStore(db);
  expect(await s.client('c')).toEqual({ clientName: 'Claude', redirectUris: ['https://x/cb'] });
  expect(await s.takeCode(b('ff'))).toEqual({ clientId: 'c', userId: 'u', role: 'worker', redirectUri: 'https://x/cb', codeChallenge: 'ch', expired: false, agentName: 'Grok Bot' });
  const caller = await s.byAccess(b('ab'));
  expect(caller?.agentName).toBe('Grok Bot');
  expect(caller?.publicKey.equals(b('aa'))).toBe(true);
  expect((await s.byRefresh(b('ab')))?.wrappedRefresh.equals(b('cc'))).toBe(true);
  expect((await s.peers('i'))[0].publicKey.equals(b('dd'))).toBe(true);
  const [msg] = await s.inbox('i', ['task'], 10);
  expect(msg.ciphertext.equals(b('33'))).toBe(true);
  expect(msg.fromName).toBe('Claude');
  expect(await s.overview('u')).toEqual({ agents: [], activity: [] });
  expect(await s.messageSender('i', 'm')).toEqual({ fromConnection: 'p', kind: 'task' });
});

it('answers "not found" as null, not as a half-filled object', async () => {
  const { db } = fakeDb({ mailbox_client: [], mailbox_take_code: [], mailbox_by_access: [], mailbox_by_refresh: [], mailbox_peers: null, mailbox_inbox: null, mailbox_message_sender: [] });
  const s = rpcStore(db);
  expect(await s.client('c')).toBeNull();
  expect(await s.takeCode(b('ff'))).toBeNull();
  expect(await s.byAccess(b('ff'))).toBeNull();
  expect(await s.byRefresh(b('ff'))).toBeNull();
  expect(await s.peers('i')).toEqual([]);
  expect(await s.inbox('i', null, 5)).toEqual([]);
  expect(await s.messageSender('i', 'm')).toBeNull();
});

it('raises a database error instead of returning nothing', async () => {
  const { db } = fakeDb({}, 'permission denied for function mailbox_by_access');
  await expect(rpcStore(db).byAccess(b('ff'))).rejects.toThrow('mailbox_by_access: permission denied');
});

it('reaches the shared-project functions with the right names and arguments (o-core#2142)', async () => {
  const { db, calls } = fakeDb({
    mailbox_project_peers: [{ id: 'p1', role: 'worker', agent_name: 'Bolt builder', public_key: 'ab', project_id: 'g1', project_name: 'Spring launch', company_name: 'Bolt' }],
    mailbox_message_project: 'g1',
    mailbox_project_overview: { shared: [] },
    mailbox_share_agent: 'shared',
    mailbox_withdraw_agent: true,
    mailbox_project_stop: 'stopped',
  });
  const s = rpcStore(db);
  expect(await s.projectPeers('c1')).toEqual([{ id: 'p1', role: 'worker', agentName: 'Bolt builder', publicKey: b('ab'), projectId: 'g1', projectName: 'Spring launch', companyName: 'Bolt' }]);
  expect(calls.at(-1)).toEqual(['mailbox_project_peers', { p_connection: 'c1' }]);
  await s.postInProject({ id: 'm', from: 'f', to: 't', projectId: 'g1', kind: 'result', replyTo: 'r', ephemeralPublicKey: b('11'), nonce: b('22'), ciphertext: b('33'), size: 1 });
  expect(calls.at(-1)).toEqual(['mailbox_post_in_project', { p_id: 'm', p_from: 'f', p_to: 't', p_project: 'g1', p_kind: 'result', p_reply_to: 'r', p_ephemeral_public_key: '11', p_nonce: '22', p_ciphertext: '33', p_size: 1 }]);
  expect(await s.messageProject('c1', 'm1')).toBe('g1');
  expect(calls.at(-1)).toEqual(['mailbox_message_project', { p_connection: 'c1', p_id: 'm1' }]);
  expect(await s.projectOverview('u', 'g1')).toEqual({ shared: [] });
  expect(calls.at(-1)).toEqual(['mailbox_project_overview', { p_user_id: 'u', p_group: 'g1' }]);
  expect(await s.shareAgent('u', 'c1', 'g1', 'o1')).toBe('shared');
  expect(calls.at(-1)).toEqual(['mailbox_share_agent', { p_user_id: 'u', p_connection: 'c1', p_group: 'g1', p_org: 'o1' }]);
  expect(await s.withdrawAgent('u', 'c1', 'g1')).toBe(true);
  expect(calls.at(-1)).toEqual(['mailbox_withdraw_agent', { p_user_id: 'u', p_connection: 'c1', p_group: 'g1' }]);
  expect(await s.projectStop('u', 'g1', 'o1', true)).toBe('stopped');
  expect(calls.at(-1)).toEqual(['mailbox_project_stop', { p_user_id: 'u', p_group: 'g1', p_org: 'o1', p_stop: true }]);
});

it('answers null for a same-account message and for someone outside the project, and raises database errors', async () => {
  const { db } = fakeDb({});
  const s = rpcStore(db);
  expect(await s.messageProject('c1', 'm1')).toBeNull();
  expect(await s.projectOverview('u', 'g1')).toBeNull();
  expect(await s.projectPeers('c1')).toEqual([]);
  const failing = rpcStore(fakeDb({}, 'project_handover_refused').db);
  await expect(failing.postInProject({ id: 'm', from: 'f', to: 't', projectId: 'g1', kind: 'task', replyTo: null, ephemeralPublicKey: b('11'), nonce: b('22'), ciphertext: b('33'), size: 1 })).rejects.toThrow(
    '[mailbox] mailbox_post_in_project: project_handover_refused'
  );
});

it('reads where messages came from, and asks nothing for an empty list', async () => {
  const { db, calls } = fakeDb({ mailbox_message_origins: [{ id: 'm1', project_name: 'Spring launch', company_name: 'Bolt' }, { id: 'm2', project_name: 'Spring launch', company_name: null }] });
  const s = rpcStore(db);
  const origins = await s.messageOrigins('c1', ['m1', 'm2']);
  expect(calls.at(-1)).toEqual(['mailbox_message_origins', { p_connection: 'c1', p_ids: ['m1', 'm2'] }]);
  expect(origins.get('m1')).toEqual({ projectName: 'Spring launch', companyName: 'Bolt' });
  expect(origins.get('m2')).toEqual({ projectName: 'Spring launch', companyName: null });
  const before = calls.length;
  expect((await s.messageOrigins('c1', [])).size).toBe(0);
  expect(calls.length).toBe(before);
});
