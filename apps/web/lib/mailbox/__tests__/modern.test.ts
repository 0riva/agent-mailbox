/**
 * @jest-environment node
 *
 * The agent mailbox on MCP protocol revision 2026-07-28 (o-core#2367): discovery and the checks the
 * revision requires, background tasks (a task given with post_task comes back to the assistant by itself),
 * withdrawing a task, and the mailbox playbook as an MCP skill. Two agents connect through the real
 * sign-in, so every result here is genuinely sealed and opened.
 */
export {};

import { createHash, randomBytes } from 'node:crypto';

import { hashToken } from '../crypto';
import { callTool, type McpContext } from '../mcp';
import { MODERN_VERSION, POLL_INTERVAL_MS, TASKS_EXTENSION, handleModern } from '../modern';
import { approve, exchangeCode, registerClient, validateAuthorize } from '../oauth';
import { SKILL_MD, SKILL_URI } from '../skill';
import type { MailboxStore, Role } from '../store';
import { memoryStore } from './helpers/memoryStore';

const RESOURCE = 'https://oriva.io/api/mailbox/mcp';
const USER = '02367000-0000-4000-8000-00000000000a';

async function connect(store: MailboxStore, name: string, role: Role): Promise<McpContext> {
  const redirect = `https://${name.toLowerCase().replace(/\W+/g, '')}.example/cb`;
  const reg = await registerClient(store, { client_name: name, redirect_uris: [redirect] });
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const req = await validateAuthorize(store, { response_type: 'code', client_id: reg.client_id, redirect_uri: redirect, code_challenge: challenge, code_challenge_method: 'S256' }, RESOURCE);
  const code = new URL(await approve(store, USER, req, role, 'https://oriva.io')).searchParams.get('code')!;
  const tokens = await exchangeCode(store, { code, code_verifier: verifier, client_id: reg.client_id, redirect_uri: redirect });
  const caller = await store.byAccess(hashToken(tokens.access_token));
  return { store, caller: caller!, accessToken: tokens.access_token };
}

async function trio() {
  const m = memoryStore();
  const claude = await connect(m.store, 'Claude', 'dispatcher');
  const grok = await connect(m.store, 'Grok Bot', 'worker');
  const other = await connect(m.store, 'Other lead', 'dispatcher');
  return { ...m, claude, grok, other };
}

const WITH_TASKS = { extensions: { [TASKS_EXTENSION]: {} } };
type Caps = Record<string, unknown>;

let nextId = 1;
/** One 2026-07-28 request with the headers a real client sends. */
function call(ctx: McpContext, method: string, params: Record<string, unknown> = {}, caps: Caps = WITH_TASKS, opts: { headers?: Record<string, string | null>; version?: string; id?: number | null } = {}) {
  const name = method === 'tools/call' ? params.name : method === 'resources/read' ? params.uri : method.startsWith('tasks/') ? params.taskId : undefined;
  const base: Record<string, string> = { 'mcp-protocol-version': MODERN_VERSION, 'mcp-method': method, ...(name === undefined ? {} : { 'mcp-name': String(name) }) };
  const headers = new Headers();
  for (const [k, v] of Object.entries({ ...base, ...(opts.headers ?? {}) })) if (v !== null) headers.set(k, v);
  const id = opts.id === null ? undefined : (opts.id ?? nextId++);
  return handleModern(
    ctx,
    {
      jsonrpc: '2.0', ...(id === undefined ? {} : { id }), method,
      params: {
        ...params,
        _meta: {
          'io.modelcontextprotocol/protocolVersion': opts.version ?? MODERN_VERSION,
          'io.modelcontextprotocol/clientInfo': { name: 'test', version: '1' },
          'io.modelcontextprotocol/clientCapabilities': caps,
        },
      },
    },
    headers,
  );
}

const result = (a: { body: Record<string, unknown> | null }) => (a.body as { result: Record<string, any> }).result;
const error = (a: { body: Record<string, unknown> | null }) => (a.body as { error: { code: number; message: string; data?: any } }).error;
const text = (r: Record<string, any>) => r.content[0].text as string;

async function giveTask(claude: McpContext, words = 'Draft three post ideas for Monday.') {
  const a = await call(claude, 'tools/call', { name: 'post_task', arguments: { text: words } });
  return result(a).taskId as string;
}

describe('discovery and the checks 2026-07-28 requires', () => {
  it('advertises tools, the playbook and background tasks', async () => {
    const { claude } = await trio();
    const a = await call(claude, 'server/discover');
    expect(a.status).toBe(200);
    const r = result(a);
    expect(r.resultType).toBe('complete');
    expect(r.supportedVersions).toEqual([MODERN_VERSION]);
    expect(r.capabilities.extensions).toEqual({ 'io.modelcontextprotocol/tasks': {}, 'io.modelcontextprotocol/skills': {} });
    expect(r._meta['io.modelcontextprotocol/serverInfo'].name).toBe('oriva-agent-mailbox');
    expect(r.instructions).toMatch(/hand out work/);
  });

  it('refuses another protocol version, naming the ones it serves', async () => {
    const { claude } = await trio();
    const a = await call(claude, 'tools/list', {}, WITH_TASKS, { version: '2099-01-01' });
    expect(a.status).toBe(400);
    expect(error(a).code).toBe(-32022);
    expect(error(a).data.supported).toEqual(expect.arrayContaining([MODERN_VERSION, '2025-06-18']));
  });

  it('refuses a request without the client capabilities', async () => {
    const { claude } = await trio();
    const a = await call(claude, 'tools/list', {}, null as unknown as Caps);
    expect(a.status).toBe(400);
    expect(error(a).code).toBe(-32602);
  });

  it.each([
    ['no MCP-Protocol-Version header', 'tools/list', {}, { 'mcp-protocol-version': null }],
    ['no Mcp-Method header', 'tools/list', {}, { 'mcp-method': null }],
    ['an Mcp-Method that disagrees with the body', 'tools/list', {}, { 'mcp-method': 'tools/call' }],
    ['no Mcp-Name on a tool call', 'tools/call', { name: 'list_agents', arguments: {} }, { 'mcp-name': null }],
    ['an Mcp-Name naming another tool', 'tools/call', { name: 'list_agents', arguments: {} }, { 'mcp-name': 'post_task' }],
  ])('refuses %s', async (_label, method, params, headers) => {
    const { claude } = await trio();
    const a = await call(claude, method, params, WITH_TASKS, { headers });
    expect(a.status).toBe(400);
    expect(error(a).code).toBe(-32020);
  });

  it('answers an unknown method 404', async () => {
    const { claude } = await trio();
    const a = await call(claude, 'initialize');
    expect(a.status).toBe(404);
    expect(error(a).code).toBe(-32601);
  });

  it('accepts a notification with no body', async () => {
    const { claude } = await trio();
    expect(await call(claude, 'notifications/cancelled', {}, WITH_TASKS, { id: null })).toEqual({ status: 202, body: null });
  });

  it('lists the same tools as before, by role', async () => {
    const { claude, grok } = await trio();
    expect(result(await call(claude, 'tools/list')).tools.map((t: { name: string }) => t.name)).toEqual(['list_agents', 'post_task', 'read_replies']);
    expect(result(await call(grok, 'tools/list')).tools.map((t: { name: string }) => t.name)).toEqual(['list_agents', 'next_task', 'report', 'note']);
  });
});

describe('background tasks', () => {
  it('follows a task from posting to the worker’s result, then shows it once', async () => {
    const { claude, grok } = await trio();
    const posted = result(await call(claude, 'tools/call', { name: 'post_task', arguments: { text: 'Draft three post ideas for Monday.' } }));
    expect(posted.resultType).toBe('task');
    expect(posted.status).toBe('working');
    expect(posted.taskId).toMatch(/^[0-9a-f-]{36}$/);
    expect(posted.pollIntervalMs).toBe(POLL_INTERVAL_MS);
    const taskId = posted.taskId as string;

    const waiting = result(await call(claude, 'tasks/get', { taskId }));
    expect(waiting).toMatchObject({ resultType: 'complete', taskId, status: 'working', statusMessage: 'Waiting for the agent to pick up the task.' });
    expect(waiting.ttlMs).toBeGreaterThan(0);

    expect(await callTool(grok, 'next_task', {})).toContain('Draft three post ideas for Monday.');
    const picked = result(await call(claude, 'tasks/get', { taskId }));
    expect(picked.statusMessage).toBe('The agent has picked up the task and is working on it.');
    expect(Date.parse(picked.lastUpdatedAt)).toBeGreaterThanOrEqual(Date.parse(picked.createdAt));

    await callTool(grok, 'report', { task_id: taskId, result: '1. Habits 2. Focus 3. Rest' });
    const done = result(await call(claude, 'tasks/get', { taskId }));
    expect(done.status).toBe('completed');
    expect(done.result.isError).toBe(false);
    expect(text(done.result)).toBe(`Result for task ${taskId} from Grok Bot:\n\n1. Habits 2. Focus 3. Rest`);

    // Collected through the task, so it does not come back through read_replies — and asking again still answers.
    expect(await callTool(claude, 'read_replies', {})).toBe('No replies yet.');
    expect(result(await call(claude, 'tasks/get', { taskId })).status).toBe('completed');
  });

  it('answers post_task the classic way for a client that does not follow tasks', async () => {
    const { claude } = await trio();
    const r = result(await call(claude, 'tools/call', { name: 'post_task', arguments: { text: 'Do it.' } }, {}));
    expect(r.resultType).toBe('complete');
    expect(text(r)).toMatch(/sent to Grok Bot\. Its result will arrive through read_replies\./);
  });

  it('does not count a null tasks capability as declared', async () => {
    const { claude } = await trio();
    const r = result(await call(claude, 'tools/call', { name: 'post_task', arguments: { text: 'Do it.' } }, { extensions: { [TASKS_EXTENSION]: null } }));
    expect(r.resultType).toBe('complete');
  });

  it('never turns a worker’s call into a task, even with another worker it could reach', async () => {
    const m = memoryStore();
    const grok = await connect(m.store, 'Grok Bot', 'worker');
    await connect(m.store, 'Second worker', 'worker');
    const r = result(await call(grok, 'tools/call', { name: 'post_task', arguments: { text: 'x' } }));
    expect(r.resultType).toBe('complete');
    expect(r.isError).toBe(true);
    expect(text(r)).toMatch(/not available to an agent that does the work/);
    expect(m.messages).toHaveLength(0);
  });

  it('refuses task methods to a client that did not declare tasks', async () => {
    const { claude } = await trio();
    const taskId = await giveTask(claude);
    const a = await call(claude, 'tasks/get', { taskId }, {});
    expect(error(a).code).toBe(-32021);
    expect(error(a).data.requiredCapabilities).toEqual({ extensions: { [TASKS_EXTENSION]: {} } });
  });

  it('shows a task only to the agent that gave it', async () => {
    const { claude, grok, other } = await trio();
    const taskId = await giveTask(claude);
    expect(error(await call(other, 'tasks/get', { taskId })).code).toBe(-32602);
    expect(error(await call(grok, 'tasks/get', { taskId })).code).toBe(-32602);
    expect(error(await call(claude, 'tasks/get', { taskId: 'not-a-task' })).code).toBe(-32602);
    expect(error(await call(other, 'tasks/cancel', { taskId })).code).toBe(-32602);
  });

  it('withdraws a task before the worker picks it up: it never arrives', async () => {
    const { claude, grok } = await trio();
    const taskId = await giveTask(claude);
    expect(result(await call(claude, 'tasks/cancel', { taskId }))).toMatchObject({ resultType: 'complete' });
    expect(await callTool(grok, 'next_task', {})).toBe('No tasks waiting.');
    expect(result(await call(claude, 'tasks/get', { taskId })).status).toBe('cancelled');
  });

  it('withdraws a task the worker already has: its result is refused and it is told why', async () => {
    const { claude, grok } = await trio();
    const taskId = await giveTask(claude);
    await callTool(grok, 'next_task', {});
    await call(claude, 'tasks/cancel', { taskId });
    await expect(callTool(grok, 'report', { task_id: taskId, result: 'done' })).rejects.toThrow(/withdrew it, so your result was not sent/);
    expect(result(await call(claude, 'tasks/get', { taskId })).status).toBe('cancelled');
    expect(await callTool(claude, 'read_replies', {})).toBe('No replies yet.');
  });

  it('refuses a result that lands after the withdrawal, even when the report started before it', async () => {
    const m = await trio();
    const taskId = await giveTask(m.claude);
    await callTool(m.grok, 'next_task', {});
    // The worker's own check ran before the withdrawal; the database refuses the result anyway.
    m.store.taskWithdrawn = async () => false;
    await call(m.claude, 'tasks/cancel', { taskId });
    await expect(callTool(m.grok, 'report', { task_id: taskId, result: 'done' })).rejects.toThrow(/withdrew it, so your result was not sent/);
    expect(m.messages.filter((x) => x.kind === 'result')).toHaveLength(0);
    expect(result(await call(m.claude, 'tasks/get', { taskId })).status).toBe('cancelled');
  });

  it('finishes a task whose worker was disconnected with a readable error, never leaving it working', async () => {
    const m = await trio();
    const taskId = await giveTask(m.claude);
    await m.store.stop(USER, m.grok.caller.id);
    const r = result(await call(m.claude, 'tasks/get', { taskId }));
    expect(r.status).toBe('completed');
    expect(r.result.isError).toBe(true);
    expect(text(r.result)).toMatch(/will not be answered: the agent it was given to has been disconnected/);
  });

  it('says a task is held while a shared project holds it back', async () => {
    const { claude } = await trio();
    const taskId = await giveTask(claude);
    const real = claude.store.taskState.bind(claude.store);
    const held = { ...claude, store: { ...claude.store, taskState: async (c: string, t: string) => ({ ...(await real(c, t))!, held: true }) } };
    const r = result(await call(held, 'tasks/get', { taskId }));
    expect(r.status).toBe('working');
    expect(r.statusMessage).toMatch(/^Held: a company has stopped agent handovers/);
  });

  it('keeps an answered task answered when withdrawn too late', async () => {
    const { claude, grok } = await trio();
    const taskId = await giveTask(claude);
    await callTool(grok, 'next_task', {});
    await callTool(grok, 'report', { task_id: taskId, result: 'done' });
    expect(result(await call(claude, 'tasks/cancel', { taskId }))).toMatchObject({ resultType: 'complete' });
    expect(result(await call(claude, 'tasks/get', { taskId })).status).toBe('completed');
  });

  it('acknowledges tasks/update for its own task only', async () => {
    const { claude, other } = await trio();
    const taskId = await giveTask(claude);
    expect(result(await call(claude, 'tasks/update', { taskId, inputResponses: {} })).resultType).toBe('complete');
    expect(error(await call(other, 'tasks/update', { taskId, inputResponses: {} })).code).toBe(-32602);
  });
});

describe('the mailbox playbook as a skill', () => {
  it('lists one skill whose digest matches the bytes it serves', async () => {
    const { claude } = await trio();
    const [skill] = result(await call(claude, 'skills/list')).skills;
    expect(skill.uri).toBe(SKILL_URI);
    expect(skill.frontmatter.name).toBe('oriva-mailbox');
    const read = result(await call(claude, 'resources/read', { uri: SKILL_URI }));
    const served = read.contents[0].text as string;
    expect(served).toBe(SKILL_MD);
    expect(skill.resources).toEqual([
      { uri: SKILL_URI, digest: `sha256:${createHash('sha256').update(Buffer.from(served, 'utf8')).digest('hex')}`, size: Buffer.byteLength(served) },
    ]);
    expect(result(await call(claude, 'skills/get', { uri: SKILL_URI })).skill).toEqual(skill);
  });

  it('names only tools the mailbox has', () => {
    const named = [...SKILL_MD.matchAll(/`([a-z]+_[a-z_]+)`/g)].map((m) => m[1]);
    expect(named.length).toBeGreaterThan(4);
    expect(named.filter((n) => !['list_agents', 'post_task', 'read_replies', 'next_task', 'report', 'note', 'task_id'].includes(n))).toEqual([]);
  });

  it('refuses an unknown skill or resource', async () => {
    const { claude } = await trio();
    expect(error(await call(claude, 'skills/get', { uri: 'skill://nope/SKILL.md' })).code).toBe(-32602);
    expect(error(await call(claude, 'resources/read', { uri: 'skill://nope/SKILL.md' })).code).toBe(-32602);
  });
});
