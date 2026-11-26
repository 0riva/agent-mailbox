/**
 * The agent mailbox's MCP server (o-core#2069): what a connected agent can do, by role.
 *
 *   Hands out work (dispatcher): list_agents, post_task, read_replies
 *   Does the work (worker):      list_agents, next_task, report, note
 *
 * Streamable HTTP, stateless, JSON responses (no SSE): every request is answered on its own. Each
 * outgoing message is sealed to its receiver (crypto.ts sealTo) with the full envelope bound in;
 * each incoming one is opened with the caller's private key, unwrapped with the caller's own
 * access token for the length of the request. Communication, not memory: a message read is marked
 * read and deleted 7 days later, so agents keep their own records.
 */
import { randomUUID } from 'node:crypto';

import { messageAad, openSealed, sealTo, unwrapPrivateKey, type MessageKind } from './crypto';
import type { Caller, MailboxStore, Peer, ProjectPeer, Role, StoredMessage } from './store';

export const MAX_TEXT_BYTES = 204_800;
export const REQUESTS_PER_MINUTE = 60;
export const PROTOCOL_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];

export interface McpContext {
  store: MailboxStore;
  caller: Caller;
  accessToken: string;
}

type Tool = { name: string; description: string; inputSchema: Record<string, unknown> };
const obj = (properties: Record<string, unknown>, required: string[] = []) => ({ type: 'object', properties, required, additionalProperties: false });

const LIST_AGENTS: Tool = {
  name: 'list_agents',
  description: "List the other AI agents connected to this Oriva account's mailbox, and the agents of other companies shared into the same shared projects as you, with what each one does.",
  inputSchema: obj({}),
};

export const TOOLS: Record<Role, Tool[]> = {
  dispatcher: [
    LIST_AGENTS,
    {
      name: 'post_task',
      description: 'Give a task to an agent that does the work. If more than one is connected, name it in `to` (its name or id from list_agents). To give it to another company\'s agent, name that agent in `to`, and the shared project in `project` if it is in more than one. Returns the task id; its result arrives through read_replies.',
      inputSchema: obj({ text: { type: 'string', description: 'The task, complete and self-contained.' }, to: { type: 'string' }, project: { type: 'string', description: 'The shared project (its name or id from list_agents), for another company\'s agent.' } }, ['text']),
    },
    {
      name: 'read_replies',
      description: 'Read results and notes the other agents sent you, oldest first. Each is shown once: keep anything you need in your own records.',
      inputSchema: obj({ limit: { type: 'integer', minimum: 1, maximum: 20 } }),
    },
  ],
  worker: [
    LIST_AGENTS,
    {
      name: 'next_task',
      description: 'Fetch the oldest task waiting for you. Call it when asked to check in, and at the start of every scheduled run. When done, answer with report.',
      inputSchema: obj({}),
    },
    {
      name: 'report',
      description: 'Send the result of a task back to the agent that gave it. Put the full answer in `result`.',
      inputSchema: obj({ task_id: { type: 'string' }, result: { type: 'string' } }, ['task_id', 'result']),
    },
    {
      name: 'note',
      description: 'Send a message that is not the result of a task — a question, a progress update, something you noticed — to the agents on your account that hand out work, or to one agent named in `to` (another company\'s agent only when named, with `project` if it is in more than one).',
      inputSchema: obj({ message: { type: 'string' }, to: { type: 'string' }, project: { type: 'string' } }, ['message']),
    },
  ],
};

export class ToolError extends Error {}

function text(value: unknown, field: string): string {
  if (typeof value !== 'string' || !value.trim()) throw new ToolError(`\`${field}\` is required.`);
  if (Buffer.byteLength(value, 'utf8') > MAX_TEXT_BYTES) throw new ToolError(`\`${field}\` is over the 200 KB limit. Send a summary, or split it.`);
  return value;
}

/** An agent this one can reach: on the same account, or another company's agent through a shared project (o-core#2142). */
type Target = Peer & Partial<Pick<ProjectPeer, 'projectId' | 'projectName' | 'companyName'>>;

/** A name typed by a person, shown to an AI: one line, no control characters, bounded — never instructions. */
const clean = (s: string | null | undefined) => (s ?? '').replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]+/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 80);

function describePeer(p: Target) {
  const what = p.role === 'worker' ? 'does the work' : 'hands out work';
  return p.companyName
    ? `${clean(p.agentName)} (${what}) — company "${clean(p.companyName)}", in the shared project "${clean(p.projectName)}" — id ${p.id}`
    : `${clean(p.agentName)} (${what}) — id ${p.id}`;
}

function pick(peers: Target[], role: Role, to: unknown): Target {
  const candidates = peers.filter((p) => p.role === role);
  const wanted = typeof to === 'string' ? to.trim().toLowerCase() : '';
  if (wanted) {
    const hit = candidates.filter((p) => p.id === wanted || p.agentName.toLowerCase() === wanted);
    const [only] = hit;
    if (hit.length === 1 && only) return only;
    if (hit.length > 1 && hit.every((h) => h.id === hit[0]?.id)) {
      throw new ToolError(`${clean(hit[0]?.agentName)} is in more than one shared project; name one in \`project\`: ${hit.map((h) => `"${clean(h.projectName)}"`).join(', ')}.`);
    }
    throw new ToolError(`No single ${role === 'worker' ? 'working' : 'dispatching'} agent matches "${clean(String(to))}". Reachable: ${candidates.map(describePeer).join('; ') || 'none'}.`);
  }
  const [sole] = candidates;
  if (candidates.length === 1 && sole) return sole;
  if (!candidates.length) {
    throw new ToolError(role === 'worker' ? 'No agent that does the work is connected yet. Connect one from that agent, choosing "Does the work".' : 'No agent that hands out work is connected.');
  }
  throw new ToolError(`More than one agent could take this; name one in \`to\`: ${candidates.map(describePeer).join('; ')}.`);
}

/**
 * Who a named agent is. A name is matched against this account's own agents first, so a task never goes to
 * another company's agent that merely shares a name. Another company's agent is reached by its id, or by its
 * name together with `project`. Anything ambiguous is refused.
 */
async function resolve(ctx: McpContext, role: Role, to: unknown, project: unknown): Promise<Target> {
  const { store, caller } = ctx;
  const wanted = typeof to === 'string' ? to.trim().toLowerCase() : '';
  const inProject = typeof project === 'string' ? project.trim().toLowerCase() : '';
  if (inProject) {
    const inThat = (await store.projectPeers(caller.id)).filter((p) => p.projectId === inProject || p.projectName.toLowerCase() === inProject);
    if (!inThat.length) throw new ToolError(`No other company's agent can be reached in a shared project called "${clean(String(project))}".`);
    return pick(inThat, role, to);
  }
  const own = await store.peers(caller.id);
  if (!wanted) return pick(own, role, to);
  const mine = own.filter((p) => p.role === role && (p.id === wanted || p.agentName.toLowerCase() === wanted));
  if (mine.length) return pick(own, role, to);
  const byId = (await store.projectPeers(caller.id)).filter((p) => p.role === role && p.id === wanted);
  if (byId.length) return pick(byId, role, to);
  throw new ToolError(
    `No ${role === 'worker' ? 'working' : 'dispatching'} agent on this account matches "${clean(String(to))}". To reach another company's agent, give its id from list_agents, or its name with \`project\`.`
  );
}

async function send(ctx: McpContext, to: Target, kind: MessageKind, body: string, replyTo: string | null): Promise<string> {
  const id = randomUUID();
  // The sender's account is sealed in; the database stores the same account on the message, so the receiver opens it with it.
  const sealed = sealTo(to.publicKey, body, messageAad({ messageId: id, userId: ctx.caller.userId, fromConnection: ctx.caller.id, toConnection: to.id, kind }));
  const message = { id, from: ctx.caller.id, to: to.id, kind, replyTo, ...sealed, size: Buffer.byteLength(body, 'utf8') };
  try {
    if (to.projectId) await ctx.store.postInProject({ ...message, projectId: to.projectId });
    else await ctx.store.post(message);
  } catch (error) {
    if (error instanceof Error && error.message.includes('mailbox_full')) {
      throw new ToolError(`${to.agentName} has 20 MB of messages it has not read yet. Wait until it catches up.`);
    }
    if (error instanceof Error && error.message.includes('task_withdrawn')) {
      // The database refuses a result to a withdrawn task even when the withdrawal lands mid-report (o-core#2367).
      throw new ToolError(`The agent that gave task ${replyTo} withdrew it, so your result was not sent. You can stop working on it.`);
    }
    if (error instanceof Error && error.message.includes('project_handover_refused')) {
      throw new ToolError(`${to.agentName} cannot be reached in "${to.projectName}" right now: a company stopped agent handovers there, or an agent was withdrawn from it.`);
    }
    throw error;
  }
  return id;
}

/** Who a message is from, as the message itself records it: another company's messages say which company and project. */
export async function senderLabels(ctx: McpContext, messages: StoredMessage[]): Promise<(m: StoredMessage) => string> {
  const origins = await ctx.store.messageOrigins(ctx.caller.id, messages.map((m) => m.id));
  return (m) => {
    const o = origins.get(m.id);
    return o ? `${clean(m.fromName)} (company "${clean(o.companyName) || 'another company'}", shared project "${clean(o.projectName)}")` : clean(m.fromName);
  };
}

/** Open this agent's own messages. One that will not open (altered in storage) is reported, not returned. */
export function opener(ctx: McpContext) {
  let privateKey: Buffer | null = null;
  return (m: StoredMessage): string | null => {
    privateKey ??= unwrapPrivateKey(ctx.caller.wrapped, ctx.accessToken);
    try {
      return openSealed(
        { publicKey: ctx.caller.publicKey, privateKey },
        { ephemeralPublicKey: m.ephemeralPublicKey, nonce: m.nonce, ciphertext: m.ciphertext },
        messageAad({ messageId: m.id, userId: m.userId, fromConnection: m.fromConnection, toConnection: ctx.caller.id, kind: m.kind })
      );
    } catch {
      return null;
    }
  };
}

/** Give a task to a worker: shared by the classic answer above and the background-task answer (o-core#2367). */
export async function postTask(ctx: McpContext, args: Record<string, unknown>): Promise<{ id: string; agentName: string }> {
  const body = text(args.text, 'text');
  const to = await resolve(ctx, 'worker', args.to, args.project);
  const id = await send(ctx, to, 'task', body, null);
  return { id, agentName: to.agentName };
}

export async function callTool(ctx: McpContext, name: string, args: Record<string, unknown>): Promise<string> {
  if (!TOOLS[ctx.caller.role].some((t) => t.name === name)) {
    throw new ToolError(`\`${name}\` is not available to an agent that ${ctx.caller.role === 'worker' ? 'does the work' : 'hands out work'}.`);
  }
  const { store, caller } = ctx;

  if (name === 'list_agents') {
    const peers = await store.peers(caller.id);
    const shared = await store.projectPeers(caller.id);
    const own = peers.length ? `Also connected:\n${peers.map((p) => `- ${describePeer(p)}`).join('\n')}` : 'No other agents are connected yet.';
    const other = shared.length ? `\nOther companies' agents in your shared projects:\n${shared.map((p) => `- ${describePeer(p)}`).join('\n')}` : '';
    return `You are ${caller.agentName}. ${own}${other}`;
  }

  // Without a named agent, work stays on this account, as before; another company's agent must be named.
  const named = (v: unknown) => typeof v === 'string' && v.trim() !== '';

  if (name === 'post_task') {
    const { id, agentName } = await postTask(ctx, args);
    return `Task ${id} sent to ${agentName}. Its result will arrive through read_replies.`;
  }

  if (name === 'read_replies') {
    const limit = Math.min(Math.max(Number(args.limit ?? 10) || 10, 1), 20);
    const messages = await store.inbox(caller.id, ['result', 'note'], limit);
    if (!messages.length) return 'No replies yet.';
    const open = opener(ctx);
    const label = await senderLabels(ctx, messages);
    const lines = messages.map((m) => {
      const body = open(m);
      const from = label(m);
      const head = m.kind === 'result' ? `Result for task ${m.replyTo} from ${from}` : `Note from ${from}`;
      return `--- ${head} (${m.createdAt})\n${body ?? '[This message could not be opened — it was altered in storage, so it was discarded.]'}`;
    });
    await store.markRead(caller.id, messages.map((m) => m.id));
    return lines.join('\n\n');
  }

  if (name === 'next_task') {
    const [task] = await store.inbox(caller.id, ['task'], 1);
    if (!task) return 'No tasks waiting.';
    const body = opener(ctx)(task);
    await store.markRead(caller.id, [task.id]);
    if (body === null) return `Task ${task.id} could not be opened — it was altered in storage, so it was discarded. Call next_task again.`;
    const from = (await senderLabels(ctx, [task]))(task);
    return `Task ${task.id} from ${from}:\n\n${body}\n\nWhen done, call report with task_id "${task.id}".`;
  }

  if (name === 'report') {
    const taskId = typeof args.task_id === 'string' ? args.task_id.trim() : '';
    const body = text(args.result, 'result');
    if (!/^[0-9a-f-]{36}$/.test(taskId)) throw new ToolError('`task_id` must be the id next_task gave you.');
    const sender = await store.messageSender(caller.id, taskId);
    if (!sender || sender.kind !== 'task') throw new ToolError(`Task ${taskId} was not given to you.`);
    if (await store.taskWithdrawn(caller.id, taskId)) {
      throw new ToolError(`The agent that gave task ${taskId} withdrew it, so your result was not sent. You can stop working on it.`);
    }
    // A task that came through a shared project is answered through that same project.
    const projectId = await store.messageProject(caller.id, taskId);
    const to: Target | undefined = projectId
      ? (await store.projectPeers(caller.id)).find((p) => p.id === sender.fromConnection && p.projectId === projectId)
      : (await store.peers(caller.id)).find((p) => p.id === sender.fromConnection);
    if (!to) {
      throw new ToolError(
        projectId
          ? 'The agent that gave this task can no longer be reached in that shared project (it was withdrawn, or agent handovers were stopped), so the result has nowhere to go.'
          : 'The agent that gave this task is no longer connected, so the result has nowhere to go.'
      );
    }
    await send(ctx, to, 'result', body, taskId);
    return `Result for task ${taskId} sent to ${to.agentName}.`;
  }

  if (name === 'note') {
    const body = text(args.message, 'message');
    const targets = named(args.to) || named(args.project) ? [await resolve(ctx, 'dispatcher', args.to, args.project)] : (await store.peers(caller.id)).filter((p) => p.role === 'dispatcher');
    if (!targets.length) throw new ToolError('No agent that hands out work is connected to receive a note.');
    for (const t of targets) await send(ctx, t, 'note', body, null);
    return `Note sent to ${targets.map((t) => t.agentName).join(', ')}.`;
  }

  throw new ToolError(`Unknown tool \`${name}\`.`);
}

type Rpc = { jsonrpc?: string; id?: string | number | null; method?: string; params?: Record<string, unknown> };

/** One JSON-RPC message → its response, or null for a notification. */
export async function handleRpc(ctx: McpContext, req: Rpc): Promise<Record<string, unknown> | null> {
  const id = req.id ?? null;
  if (req.id === undefined) return null; // notifications/initialized and friends
  if (req.jsonrpc !== '2.0' || typeof req.method !== 'string') return { jsonrpc: '2.0', id, error: { code: -32600, message: 'Invalid request' } };
  const params = req.params ?? {};
  switch (req.method) {
    case 'initialize': {
      const asked = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
      return {
        jsonrpc: '2.0', id,
        result: {
          protocolVersion: PROTOCOL_VERSIONS.includes(asked) ? asked : PROTOCOL_VERSIONS[0],
          capabilities: { tools: {} },
          serverInfo: { name: 'oriva-agent-mailbox', version: '1.0.0' },
          instructions: ctx.caller.role === 'worker'
            ? 'Oriva agent mailbox. You do the work: call next_task to fetch a task, report to send its result, note for anything else. Messages are shown once; keep your own records.'
            : 'Oriva agent mailbox. You hand out work: post_task gives a task to an agent that does the work, read_replies collects results and notes. Messages are shown once; keep your own records.',
        },
      };
    }
    case 'ping':
      return { jsonrpc: '2.0', id, result: {} };
    case 'tools/list':
      return { jsonrpc: '2.0', id, result: { tools: TOOLS[ctx.caller.role] } };
    case 'tools/call': {
      try {
        const out = await callTool(ctx, String(params.name ?? ''), (params.arguments as Record<string, unknown>) ?? {});
        return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: out }] } };
      } catch (error) {
        if (error instanceof ToolError) return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: error.message }], isError: true } };
        throw error;
      }
    }
    default:
      return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${req.method}` } };
  }
}
