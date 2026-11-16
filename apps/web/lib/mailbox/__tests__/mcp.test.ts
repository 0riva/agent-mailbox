/**
 * @jest-environment node
 *
 * The agent mailbox MCP server (o-core#2069): two agents connected through the real sign-in, a
 * task and its result round-tripped, each role kept to its own tools, and every message opened
 * only by the agent it was sealed to.
 */
export {};

import { createHash, randomBytes } from 'node:crypto';

import { hashToken } from '../crypto';
import { MAX_TEXT_BYTES, callTool, handleRpc, type McpContext } from '../mcp';
import { approve, exchangeCode, registerClient, validateAuthorize } from '../oauth';
import type { MailboxStore, Role } from '../store';
import { memoryStore } from './helpers/memoryStore';

const RESOURCE = 'https://oriva.io/api/mailbox/mcp';
const USER = '02069000-0000-4000-8000-00000000000a';

async function connect(store: MailboxStore, name: string, role: Role, user = USER): Promise<McpContext> {
  const redirect = `https://${name.toLowerCase().replace(/\W+/g, '')}.example/cb`;
  const reg = await registerClient(store, { client_name: name, redirect_uris: [redirect] });
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const req = await validateAuthorize(store, { response_type: 'code', client_id: reg.client_id, redirect_uri: redirect, code_challenge: challenge, code_challenge_method: 'S256' }, RESOURCE);
  const code = new URL(await approve(store, user, req, role, 'https://oriva.io')).searchParams.get('code')!;
  const tokens = await exchangeCode(store, { code, code_verifier: verifier, client_id: reg.client_id, redirect_uri: redirect });
  const caller = await store.byAccess(hashToken(tokens.access_token));
  return { store, caller: caller!, accessToken: tokens.access_token };
}

async function pair() {
  const m = memoryStore();
  const claude = await connect(m.store, 'Claude', 'dispatcher');
  const grok = await connect(m.store, 'Grok Bot', 'worker');
  return { ...m, claude, grok };
}

const idFrom = (s: string) => s.match(/[0-9a-f-]{36}/)![0];

it('round-trips a task and its result between two agents', async () => {
  const { claude, grok } = await pair();
  const posted = await callTool(claude, 'post_task', { text: 'Draft three post ideas for Monday.' });
  expect(posted).toContain('sent to Grok Bot');
  const taskId = idFrom(posted);

  const fetched = await callTool(grok, 'next_task', {});
  expect(fetched).toContain('Draft three post ideas for Monday.');
  expect(fetched).toContain(`Task ${taskId} from Claude`);
  expect(await callTool(grok, 'next_task', {})).toBe('No tasks waiting.');

  expect(await callTool(grok, 'report', { task_id: taskId, result: '1. Habits 2. Focus 3. Rest' })).toContain('sent to Claude');
  const replies = await callTool(claude, 'read_replies', {});
  expect(replies).toContain(`Result for task ${taskId} from Grok Bot`);
  expect(replies).toContain('1. Habits 2. Focus 3. Rest');
  expect(await callTool(claude, 'read_replies', {})).toBe('No replies yet.');
});

it('stores only ciphertext', async () => {
  const { claude, messages } = await pair();
  await callTool(claude, 'post_task', { text: 'SECRET-PLAN-MARKER' });
  expect(messages[0].ciphertext.includes(Buffer.from('SECRET-PLAN-MARKER'))).toBe(false);
});

it('keeps each role to its own tools', async () => {
  const { claude, grok } = await pair();
  await expect(callTool(claude, 'next_task', {})).rejects.toThrow('not available to an agent that hands out work');
  await expect(callTool(grok, 'post_task', { text: 'x' })).rejects.toThrow('not available to an agent that does the work');
  const list = (role: McpContext) => handleRpc(role, { jsonrpc: '2.0', id: 1, method: 'tools/list' });
  expect(((await list(claude)) as any).result.tools.map((t: { name: string }) => t.name)).toEqual(['list_agents', 'post_task', 'read_replies']);
  expect(((await list(grok)) as any).result.tools.map((t: { name: string }) => t.name)).toEqual(['list_agents', 'next_task', 'report', 'note']);
});

it('asks which worker when more than one is connected, and accepts its name', async () => {
  const { store, claude } = await pair();
  await connect(store, 'Second Bot', 'worker');
  await expect(callTool(claude, 'post_task', { text: 'x' })).rejects.toThrow('name one in `to`');
  expect(await callTool(claude, 'post_task', { text: 'x', to: 'second bot' })).toContain('sent to Second Bot');
});

it('says so when no worker is connected', async () => {
  const m = memoryStore();
  const claude = await connect(m.store, 'Claude', 'dispatcher');
  await expect(callTool(claude, 'post_task', { text: 'x' })).rejects.toThrow('No agent that does the work is connected yet');
  expect(await callTool(claude, 'list_agents', {})).toContain('No other agents are connected yet');
});

it('never crosses accounts', async () => {
  const { store, claude } = await pair();
  const stranger = await connect(store, 'Stranger Bot', 'worker', '02069000-0000-4000-8000-00000000000b');
  expect(await callTool(claude, 'list_agents', {})).not.toContain('Stranger Bot');
  await expect(callTool(claude, 'post_task', { text: 'x', to: stranger.caller.id })).rejects.toThrow('No working agent on this account matches');
});

it('refuses to report on a task that was not given to you', async () => {
  const { store, claude, grok } = await pair();
  const other = await connect(store, 'Other Bot', 'worker');
  const taskId = idFrom(await callTool(claude, 'post_task', { text: 'x', to: 'Grok Bot' }));
  await expect(callTool(other, 'report', { task_id: taskId, result: 'mine now' })).rejects.toThrow('was not given to you');
  await expect(callTool(grok, 'report', { task_id: 'nope', result: 'x' })).rejects.toThrow('must be the id');
});

it('discards a message altered in storage instead of returning it', async () => {
  const { claude, grok, messages } = await pair();
  await callTool(claude, 'post_task', { text: 'original' });
  messages[0].ciphertext[0] ^= 1; // altered in storage
  expect(await callTool(grok, 'next_task', {})).toContain('could not be opened');
  expect(await callTool(grok, 'next_task', {})).toBe('No tasks waiting.');
});

it('sends a note to the agents that hand out work', async () => {
  const { claude, grok } = await pair();
  expect(await callTool(grok, 'note', { message: 'Starting the weekly run.' })).toContain('Note sent to Claude');
  expect(await callTool(claude, 'read_replies', {})).toContain('Note from Grok Bot');
});

it('refuses to bury an agent that is not reading its mail (20 MB unread)', async () => {
  const { claude } = await pair();
  const chunk = 'x'.repeat(MAX_TEXT_BYTES);
  for (let i = 0; i < 102; i += 1) await callTool(claude, 'post_task', { text: chunk });
  await expect(callTool(claude, 'post_task', { text: chunk })).rejects.toThrow('20 MB of messages it has not read yet');
});

it('enforces the size cap', async () => {
  const { claude } = await pair();
  await expect(callTool(claude, 'post_task', { text: 'x'.repeat(MAX_TEXT_BYTES + 1) })).rejects.toThrow('over the 200 KB limit');
  await expect(callTool(claude, 'post_task', { text: '   ' })).rejects.toThrow('`text` is required');
});

describe('JSON-RPC', () => {
  it('initialize agrees a protocol version and explains the role', async () => {
    const { grok } = await pair();
    const res = (await handleRpc(grok, { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26' } })) as any;
    expect(res.result.protocolVersion).toBe('2025-03-26');
    expect(res.result.instructions).toContain('You do the work');
    const unknown = (await handleRpc(grok, { jsonrpc: '2.0', id: 2, method: 'initialize', params: { protocolVersion: '1999-01-01' } })) as any;
    expect(unknown.result.protocolVersion).toBe('2025-06-18');
  });

  it('answers tool errors as tool results, and other faults as JSON-RPC errors', async () => {
    const { grok } = await pair();
    const toolErr = (await handleRpc(grok, { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'post_task', arguments: {} } })) as any;
    expect(toolErr.result.isError).toBe(true);
    expect(((await handleRpc(grok, { jsonrpc: '2.0', id: 4, method: 'resources/list' })) as any).error.code).toBe(-32601);
    expect(((await handleRpc(grok, { id: 5, method: 'ping' })) as any).error.code).toBe(-32600);
    expect(await handleRpc(grok, { jsonrpc: '2.0', method: 'notifications/initialized' })).toBeNull();
    expect(((await handleRpc(grok, { jsonrpc: '2.0', id: 6, method: 'ping' })) as any).result).toEqual({});
  });
});
