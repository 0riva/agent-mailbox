/**
 * MCP protocol revision 2026-07-28 for the agent mailbox (o-core#2367), served beside the 2025-era
 * `initialize` handshake in `mcp.ts`, which is untouched.
 *
 * A 2026-07-28 request carries its protocol version and the client's capabilities in its own `_meta`
 * envelope; there is no session. What this adds:
 *   - `server/discover`, and the header checks the revision requires (`MCP-Protocol-Version`,
 *     `Mcp-Method`, `Mcp-Name`);
 *   - background tasks (extension `io.modelcontextprotocol/tasks`): `post_task` answers with a task the
 *     client follows through `tasks/get` until the worker reports — only when the request declared the
 *     extension; anyone else gets today's text answer;
 *   - the mailbox playbook as an MCP skill (`skill.ts`).
 *
 * A task is the existing `task` message (its id is the task id, a random UUID) and its outcome is the
 * `result` message replying to it, so a task is durable the moment `post_task` returns.
 *
 * Specs read 2026-11-25: modelcontextprotocol.io/specification/2026-07-28 (versioning, server/discover,
 * transports/streamable-http), github.com/modelcontextprotocol/ext-tasks (specification/2026-07-28/tasks.md),
 * modelcontextprotocol.io/extensions/skills/overview.
 */
import { PROTOCOL_VERSIONS, TOOLS, ToolError, callTool, opener, postTask, senderLabels, type McpContext } from './mcp';
import { SKILL_ENTRY, SKILL_MD, SKILL_URI } from './skill';

export const MODERN_VERSION = '2026-07-28';
const VERSION_KEY = 'io.modelcontextprotocol/protocolVersion';
const CAPS_KEY = 'io.modelcontextprotocol/clientCapabilities';
const SERVER_INFO_KEY = 'io.modelcontextprotocol/serverInfo';
export const TASKS_EXTENSION = 'io.modelcontextprotocol/tasks';
const SKILLS_EXTENSION = 'io.modelcontextprotocol/skills';

/** Agents usually answer on a schedule, so a task is checked at the slowest interval clients accept. */
export const POLL_INTERVAL_MS = 30_000;

type Rpc = { jsonrpc?: string; id?: string | number | null; method?: string; params?: Record<string, unknown> };
type Caps = { extensions?: Record<string, unknown> } & Record<string, unknown>;
export type ModernAnswer = { status: number; body: Record<string, unknown> | null };

const SERVER_INFO = { name: 'oriva-agent-mailbox', version: '1.1.0' };
const meta = { [SERVER_INFO_KEY]: SERVER_INFO };

/** A request is 2026-07-28 traffic when it carries the per-request protocol version. */
export function isModern(req: unknown): boolean {
  const m = (req as Rpc | null)?.params?._meta as Record<string, unknown> | undefined;
  return typeof m?.[VERSION_KEY] === 'string';
}

const ok = (id: Rpc['id'], result: Record<string, unknown>): ModernAnswer => ({
  status: 200,
  body: { jsonrpc: '2.0', id, result: { resultType: 'complete', ...result, _meta: meta } },
});
const fail = (id: Rpc['id'], status: number, code: number, message: string, data?: unknown): ModernAnswer => ({
  status,
  body: { jsonrpc: '2.0', id: id ?? null, error: { code, message, ...(data === undefined ? {} : { data }) } },
});

const declaresTasks = (caps: Caps) => {
  const declared = caps.extensions?.[TASKS_EXTENSION];
  return typeof declared === 'object' && declared !== null && !Array.isArray(declared);
};

function decodeHeader(v: string): string {
  try {
    return decodeURIComponent(v);
  } catch {
    return v;
  }
}

/** The value `Mcp-Name` must carry for a method, or undefined when the method has none. */
function nameFor(method: string, params: Record<string, unknown>): string | undefined {
  if (method === 'tools/call') return String(params.name ?? '');
  if (method === 'resources/read') return String(params.uri ?? '');
  if (method === 'tasks/get' || method === 'tasks/cancel' || method === 'tasks/update') return String(params.taskId ?? '');
  return undefined;
}

const instructions = (ctx: McpContext) =>
  ctx.caller.role === 'worker'
    ? 'Oriva agent mailbox. You do the work: call next_task to fetch a task, report to send its result, note for anything else. Messages are shown once; keep your own records.'
    : 'Oriva agent mailbox. You hand out work: post_task gives a task to an agent that does the work; its result comes back as the task result, or through read_replies. Messages are shown once; keep your own records.';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const latest = (...times: (string | null | undefined)[]) =>
  new Date(Math.max(...times.filter((t): t is string => !!t).map((t) => Date.parse(t)))).toISOString();

/** The task object every task answer shares. */
function taskFields(taskId: string, s: { createdAt: string; deleteAfter: string }, lastUpdatedAt: string) {
  return {
    taskId,
    createdAt: new Date(s.createdAt).toISOString(),
    lastUpdatedAt,
    ttlMs: Math.max(0, Date.parse(s.deleteAfter) - Date.parse(s.createdAt)),
  };
}

async function taskGet(ctx: McpContext, id: Rpc['id'], taskId: string): Promise<ModernAnswer> {
  const state = UUID.test(taskId) ? await ctx.store.taskState(ctx.caller.id, taskId) : null;
  if (!state) return fail(id, 200, -32602, 'Failed to retrieve task: Task not found');

  if (state.result) {
    const body = opener(ctx)(state.result);
    const from = (await senderLabels(ctx, [state.result]))(state.result);
    // Shown once: a result collected here does not come back through read_replies.
    await ctx.store.markRead(ctx.caller.id, [state.result.id]);
    return ok(id, {
      ...taskFields(taskId, state, latest(state.createdAt, state.fetchedAt, state.result.createdAt)),
      status: 'completed',
      statusMessage: `${from} reported.`,
      result:
        body === null
          ? { content: [{ type: 'text', text: `The result for task ${taskId} could not be opened — it was altered in storage, so it was discarded.` }], isError: true }
          : { content: [{ type: 'text', text: `Result for task ${taskId} from ${from}:\n\n${body}` }], isError: false },
    });
  }
  if (state.withdrawnAt) {
    return ok(id, { ...taskFields(taskId, state, latest(state.createdAt, state.fetchedAt, state.withdrawnAt)), status: 'cancelled' });
  }
  if (state.workerStopped) {
    // Final, and not a protocol error: the spec reserves `failed` for JSON-RPC errors, so an unanswerable
    // task completes as a tool error the assistant can read and act on.
    return ok(id, {
      ...taskFields(taskId, state, latest(state.createdAt, state.fetchedAt)),
      status: 'completed',
      statusMessage: 'The agent was disconnected before it reported.',
      result: {
        content: [{ type: 'text', text: `Task ${taskId} will not be answered: the agent it was given to has been disconnected from this account. Give it to another agent with post_task.` }],
        isError: true,
      },
    });
  }
  return ok(id, {
    ...taskFields(taskId, state, latest(state.createdAt, state.fetchedAt)),
    status: 'working',
    statusMessage: state.held
      ? 'Held: a company has stopped agent handovers in the shared project, or the agent left it. It is delivered if that changes.'
      : state.fetchedAt ? 'The agent has picked up the task and is working on it.' : 'Waiting for the agent to pick up the task.',
    pollIntervalMs: POLL_INTERVAL_MS,
  });
}

/** One 2026-07-28 request → its HTTP status and JSON-RPC body (null body = a notification, answered 202). */
export async function handleModern(ctx: McpContext, req: Rpc, headers: Headers): Promise<ModernAnswer> {
  const id = req.id ?? null;
  if (req.jsonrpc !== '2.0' || typeof req.method !== 'string') return fail(id, 400, -32600, 'Invalid request');
  const method = req.method;
  const params = req.params ?? {};
  const envelope = (params._meta ?? {}) as Record<string, unknown>;

  const version = envelope[VERSION_KEY];
  if (version !== MODERN_VERSION) {
    return fail(id, 400, -32022, 'Unsupported protocol version', { supported: [MODERN_VERSION, ...PROTOCOL_VERSIONS], requested: version });
  }
  const caps = envelope[CAPS_KEY];
  if (!caps || typeof caps !== 'object' || Array.isArray(caps)) {
    return fail(id, 400, -32602, `Missing required _meta field: ${CAPS_KEY}`);
  }

  // Headers must agree with the body (streamable-http § standard headers).
  const mismatch = (what: string) => fail(id, 400, -32020, `Header mismatch: ${what}`);
  if (headers.get('mcp-protocol-version') !== MODERN_VERSION) return mismatch('MCP-Protocol-Version must be 2026-07-28');
  if (headers.get('mcp-method') !== method) return mismatch(`Mcp-Method must be ${method}`);
  const name = nameFor(method, params);
  if (name !== undefined) {
    const sent = headers.get('mcp-name');
    if (sent === null || decodeHeader(sent) !== name) return mismatch(`Mcp-Name must match the request (${method})`);
  }

  if (req.id === undefined) return { status: 202, body: null };

  switch (method) {
    case 'server/discover':
      return ok(id, {
        supportedVersions: [MODERN_VERSION],
        capabilities: { tools: {}, resources: {}, extensions: { [TASKS_EXTENSION]: {}, [SKILLS_EXTENSION]: {} } },
        instructions: instructions(ctx),
      });

    case 'ping':
      return ok(id, {});

    case 'tools/list':
      return ok(id, { tools: TOOLS[ctx.caller.role] });

    case 'tools/call': {
      const toolName = String(params.name ?? '');
      const args = (params.arguments as Record<string, unknown>) ?? {};
      try {
        if (toolName === 'post_task' && ctx.caller.role === 'dispatcher' && declaresTasks(caps as Caps)) {
          const { id: taskId } = await postTask(ctx, args);
          const now = new Date().toISOString();
          // The task message is stored before this answer goes out, so tasks/get resolves at once.
          return {
            status: 200,
            body: {
              jsonrpc: '2.0', id,
              result: {
                resultType: 'task', taskId, status: 'working', statusMessage: 'Waiting for the agent to pick up the task.',
                createdAt: now, lastUpdatedAt: now, ttlMs: 30 * 24 * 60 * 60 * 1000, pollIntervalMs: POLL_INTERVAL_MS, _meta: meta,
              },
            },
          };
        }
        const text = await callTool(ctx, toolName, args);
        return ok(id, { content: [{ type: 'text', text }] });
      } catch (error) {
        if (error instanceof ToolError) return ok(id, { content: [{ type: 'text', text: error.message }], isError: true });
        throw error;
      }
    }

    case 'tasks/get':
    case 'tasks/cancel':
    case 'tasks/update': {
      if (!declaresTasks(caps as Caps)) {
        return fail(id, 200, -32021, 'Missing required client capability', { requiredCapabilities: { extensions: { [TASKS_EXTENSION]: {} } } });
      }
      const taskId = String(params.taskId ?? '');
      if (method === 'tasks/get') return taskGet(ctx, id, taskId);
      if (method === 'tasks/cancel') {
        const outcome = UUID.test(taskId) ? await ctx.store.withdrawTask(ctx.caller.id, taskId) : 'not_found';
        return outcome === 'not_found' ? fail(id, 200, -32602, 'Failed to cancel task: Task not found') : ok(id, {});
      }
      // The mailbox never asks the client for input, so there is nothing to apply; acknowledge a known task.
      const known = UUID.test(taskId) ? await ctx.store.taskState(ctx.caller.id, taskId) : null;
      return known ? ok(id, {}) : fail(id, 200, -32602, 'Failed to update task: Task not found');
    }

    case 'skills/list':
      return ok(id, { skills: [SKILL_ENTRY] });

    case 'skills/get':
      return params.uri === SKILL_URI ? ok(id, { skill: SKILL_ENTRY }) : fail(id, 200, -32602, 'Unknown skill');

    case 'resources/read':
      return params.uri === SKILL_URI
        ? ok(id, { contents: [{ uri: SKILL_URI, mimeType: 'text/markdown', text: SKILL_MD }] })
        : fail(id, 200, -32602, 'Unknown resource');

    default:
      return fail(id, 404, -32601, `Method not found: ${method}`);
  }
}
