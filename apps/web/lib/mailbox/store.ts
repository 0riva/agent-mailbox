/**
 * The agent mailbox's store (o-core#2069): typed calls to the server-only database functions in
 * supabase/migrations/20261023203732_agent_mailbox_rpc.sql. The `mailbox` schema itself is not
 * exposed through the Data API; these functions are the only way in, and only the service role may
 * call them. Bytes cross as hex. Construct with `rpcStore(serviceRoleClient())` in a route; tests
 * pass an in-memory implementation of the same interface.
 */
import type { SupabaseClient } from '@supabase/supabase-js';

import type { MessageKind } from './crypto';

export type Role = 'dispatcher' | 'worker';

export interface ClientRecord {
  clientName: string;
  redirectUris: string[];
}

export interface TakenCode {
  clientId: string;
  userId: string;
  role: Role;
  redirectUri: string;
  codeChallenge: string;
  expired: boolean;
  /** The name the owner chose on the Connect page; null = use the app's own name. */
  agentName: string | null;
}

export interface Caller {
  id: string;
  userId: string;
  role: Role;
  agentName: string;
  publicKey: Buffer;
  wrapped: Buffer;
  expired: boolean;
}

export interface RefreshRecord {
  id: string;
  clientId: string;
  publicKey: Buffer;
  wrappedRefresh: Buffer;
  expired: boolean;
}

export interface NewConnection {
  userId: string;
  clientId: string;
  role: Role;
  /** Null = the app's own name. */
  agentName: string | null;
  publicKey: Buffer;
  wrapped: Buffer;
  wrappedRefresh: Buffer;
  accessHash: Buffer;
  refreshHash: Buffer;
  accessTtlSeconds: number;
}

export interface Rotation {
  oldRefreshHash: Buffer;
  wrapped: Buffer;
  wrappedRefresh: Buffer;
  accessHash: Buffer;
  refreshHash: Buffer;
  accessTtlSeconds: number;
}

export interface Peer {
  id: string;
  role: Role;
  agentName: string;
  publicKey: Buffer;
}

/** An agent of another account, reachable through a shared project both agents are shared into (o-core#2142). */
export interface ProjectPeer extends Peer {
  projectId: string;
  projectName: string;
  companyName: string;
}

export interface StoredMessage {
  id: string;
  userId: string;
  fromConnection: string;
  fromName: string;
  kind: MessageKind;
  replyTo: string | null;
  ephemeralPublicKey: Buffer;
  nonce: Buffer;
  ciphertext: Buffer;
  createdAt: string;
}

export interface NewMessage {
  id: string;
  from: string;
  to: string;
  kind: MessageKind;
  replyTo: string | null;
  ephemeralPublicKey: Buffer;
  nonce: Buffer;
  ciphertext: Buffer;
  size: number;
}

/** Where a task this agent gave has got to (o-core#2367). The result is sealed to the giver, as in its inbox. */
export interface TaskState {
  createdAt: string;
  deleteAfter: string;
  fetchedAt: string | null;
  withdrawnAt: string | null;
  /** The worker it was given to has been disconnected, so it can never be answered. */
  workerStopped: boolean;
  /** A shared project is holding it back (a company stopped handovers, or an agent left the project). */
  held: boolean;
  result: StoredMessage | null;
}

export type WithdrawOutcome = 'withdrawn' | 'answered' | 'not_found';

export interface MailboxStore {
  registerClient(clientId: string, name: string, redirectUris: string[]): Promise<void>;
  client(clientId: string): Promise<ClientRecord | null>;
  createCode(c: { codeHash: Buffer; clientId: string; userId: string; role: Role; redirectUri: string; challenge: string; ttlSeconds: number; agentName: string | null }): Promise<void>;
  takeCode(codeHash: Buffer): Promise<TakenCode | null>;
  connect(c: NewConnection): Promise<string>;
  byAccess(accessHash: Buffer): Promise<Caller | null>;
  byRefresh(refreshHash: Buffer): Promise<RefreshRecord | null>;
  rotate(r: Rotation): Promise<boolean>;
  /** A refresh token already rotated away was presented again: stop its connection. True if one was stopped. */
  refreshReused(refreshHash: Buffer): Promise<boolean>;
  /** Count a request against a key (a hashed caller address) in an hour window; false once over the limit. */
  requestLimit(key: string, perHour: number): Promise<boolean>;
  stop(userId: string, connectionId: string): Promise<boolean>;
  /** Rename one of the owner's active agents; false if it is not theirs or is stopped. */
  rename(userId: string, connectionId: string, name: string): Promise<boolean>;
  revoke(tokenHash: Buffer): Promise<void>;
  rateLimit(connectionId: string, perMinute: number): Promise<boolean>;
  peers(connectionId: string): Promise<Peer[]>;
  post(m: NewMessage): Promise<void>;
  inbox(connectionId: string, kinds: MessageKind[] | null, limit: number): Promise<StoredMessage[]>;
  markRead(connectionId: string, ids: string[]): Promise<number>;
  /** Who sent a message addressed to this agent; null for a message addressed to anyone else. */
  messageSender(connectionId: string, messageId: string): Promise<{ fromConnection: string; kind: MessageKind } | null>;
  /** A task this agent gave, or null for any message it did not give as a task. */
  taskState(connectionId: string, taskId: string): Promise<TaskState | null>;
  withdrawTask(connectionId: string, taskId: string): Promise<WithdrawOutcome>;
  /** Whether a task addressed to this agent was withdrawn by the agent that gave it. */
  taskWithdrawn(connectionId: string, taskId: string): Promise<boolean>;
  overview(userId: string): Promise<unknown>;
  // Shared projects (o-core#2142): agents of other companies, reached only inside a project.
  projectPeers(connectionId: string): Promise<ProjectPeer[]>;
  postInProject(m: NewMessage & { projectId: string }): Promise<void>;
  /** For messages addressed to this agent that came through a project: the project and the sender's company then. */
  messageOrigins(connectionId: string, messageIds: string[]): Promise<Map<string, { projectName: string; companyName: string | null }>>;
  /** The project a message addressed to this agent came through; null for same-account messages. */
  messageProject(connectionId: string, messageId: string): Promise<string | null>;
  /** What a member sees on the project page; null when they are not in any company in the project. */
  projectOverview(userId: string, projectId: string): Promise<unknown | null>;
  shareAgent(userId: string, connectionId: string, projectId: string, companyId: string): Promise<string>;
  withdrawAgent(userId: string, connectionId: string, projectId: string): Promise<boolean>;
  projectStop(userId: string, projectId: string, companyId: string, stop: boolean): Promise<string>;
}

const hex = (b: Buffer) => b.toString('hex');
const unhex = (s: string | null | undefined) => Buffer.from(s ?? '', 'hex');

/** A store backed by the service-role database functions. */
export function rpcStore(db: SupabaseClient): MailboxStore {
  async function call<T>(fn: string, args: Record<string, unknown>): Promise<T> {
    const { data, error } = await db.rpc(fn, args);
    if (error) throw new Error(`[mailbox] ${fn}: ${error.message}`);
    return data as T;
  }
  const first = <T>(rows: T[] | null | undefined): T | null => (Array.isArray(rows) ? rows[0] ?? null : null);

  return {
    async registerClient(clientId, name, redirectUris) {
      await call('mailbox_register_client', { p_client_id: clientId, p_name: name, p_redirect_uris: redirectUris });
    },
    async client(clientId) {
      const row = first(await call<Array<{ client_name: string; redirect_uris: string[] }>>('mailbox_client', { p_client_id: clientId }));
      return row ? { clientName: row.client_name, redirectUris: row.redirect_uris } : null;
    },
    async createCode(c) {
      await call('mailbox_create_code', {
        p_code_hash: hex(c.codeHash), p_client_id: c.clientId, p_user_id: c.userId, p_role: c.role,
        p_redirect_uri: c.redirectUri, p_challenge: c.challenge, p_ttl_seconds: c.ttlSeconds, p_agent_name: c.agentName,
      });
    },
    async takeCode(codeHash) {
      const row = first(await call<Array<{ client_id: string; user_id: string; role: Role; redirect_uri: string; code_challenge: string; expired: boolean; agent_name: string | null }>>(
        'mailbox_take_code', { p_code_hash: hex(codeHash) }
      ));
      return row
        ? { clientId: row.client_id, userId: row.user_id, role: row.role, redirectUri: row.redirect_uri, codeChallenge: row.code_challenge, expired: row.expired, agentName: row.agent_name ?? null }
        : null;
    },
    async connect(c) {
      return call<string>('mailbox_connect', {
        p_user_id: c.userId, p_client_id: c.clientId, p_role: c.role, p_public_key: hex(c.publicKey), p_wrapped: hex(c.wrapped),
        p_wrapped_refresh: hex(c.wrappedRefresh), p_access_hash: hex(c.accessHash), p_refresh_hash: hex(c.refreshHash),
        p_access_ttl_seconds: c.accessTtlSeconds, p_agent_name: c.agentName,
      });
    },
    async byAccess(accessHash) {
      const row = first(await call<Array<{ id: string; user_id: string; role: Role; agent_name: string; public_key: string; wrapped: string; expired: boolean }>>(
        'mailbox_by_access', { p_access_hash: hex(accessHash) }
      ));
      return row
        ? { id: row.id, userId: row.user_id, role: row.role, agentName: row.agent_name, publicKey: unhex(row.public_key), wrapped: unhex(row.wrapped), expired: row.expired }
        : null;
    },
    async byRefresh(refreshHash) {
      const row = first(await call<Array<{ id: string; client_id: string; public_key: string; wrapped_refresh: string; expired: boolean }>>('mailbox_by_refresh', {
        p_refresh_hash: hex(refreshHash),
      }));
      return row ? { id: row.id, clientId: row.client_id, publicKey: unhex(row.public_key), wrappedRefresh: unhex(row.wrapped_refresh), expired: row.expired } : null;
    },
    async refreshReused(refreshHash) {
      return call<boolean>('mailbox_refresh_reused', { p_refresh_hash: hex(refreshHash) });
    },
    async requestLimit(key, perHour) {
      return call<boolean>('mailbox_request_limit', { p_key: key, p_limit: perHour });
    },
    async rotate(r) {
      return call<boolean>('mailbox_rotate', {
        p_old_refresh_hash: hex(r.oldRefreshHash), p_wrapped: hex(r.wrapped), p_wrapped_refresh: hex(r.wrappedRefresh),
        p_access_hash: hex(r.accessHash), p_refresh_hash: hex(r.refreshHash), p_access_ttl_seconds: r.accessTtlSeconds,
      });
    },
    async stop(userId, connectionId) {
      return call<boolean>('mailbox_stop', { p_user_id: userId, p_connection: connectionId });
    },
    async rename(userId, connectionId, name) {
      return call<boolean>('mailbox_rename', { p_user_id: userId, p_connection: connectionId, p_name: name });
    },
    async revoke(tokenHash) {
      await call('mailbox_revoke', { p_token_hash: hex(tokenHash) });
    },
    async rateLimit(connectionId, perMinute) {
      return call<boolean>('mailbox_rate_limit', { p_connection: connectionId, p_limit: perMinute });
    },
    async peers(connectionId) {
      const rows = await call<Array<{ id: string; role: Role; agent_name: string; public_key: string }>>('mailbox_peers', { p_connection: connectionId });
      return (rows ?? []).map((r) => ({ id: r.id, role: r.role, agentName: r.agent_name, publicKey: unhex(r.public_key) }));
    },
    async post(m) {
      await call('mailbox_post', {
        p_id: m.id, p_from: m.from, p_to: m.to, p_kind: m.kind, p_reply_to: m.replyTo,
        p_ephemeral_public_key: hex(m.ephemeralPublicKey), p_nonce: hex(m.nonce), p_ciphertext: hex(m.ciphertext), p_size: m.size,
      });
    },
    async inbox(connectionId, kinds, limit) {
      const rows = await call<Array<{
        id: string; user_id: string; from_connection: string; from_name: string; kind: MessageKind; reply_to: string | null;
        ephemeral_public_key: string; nonce: string; ciphertext: string; created_at: string;
      }>>('mailbox_inbox', { p_connection: connectionId, p_kinds: kinds, p_limit: limit });
      return (rows ?? []).map((r) => ({
        id: r.id, userId: r.user_id, fromConnection: r.from_connection, fromName: r.from_name, kind: r.kind, replyTo: r.reply_to,
        ephemeralPublicKey: unhex(r.ephemeral_public_key), nonce: unhex(r.nonce), ciphertext: unhex(r.ciphertext), createdAt: r.created_at,
      }));
    },
    async markRead(connectionId, ids) {
      return call<number>('mailbox_mark_read', { p_connection: connectionId, p_ids: ids });
    },
    async taskState(connectionId, taskId) {
      const row = first(await call<Array<{
        created_at: string; delete_after: string; fetched_at: string | null; withdrawn_at: string | null;
        worker_stopped: boolean; held: boolean;
        result_id: string | null; result_user_id: string | null; result_from: string | null; result_from_name: string | null;
        result_ephemeral_public_key: string | null; result_nonce: string | null; result_ciphertext: string | null; result_created_at: string | null;
      }>>('mailbox_task_state', { p_connection: connectionId, p_task: taskId }));
      if (!row) return null;
      const result: StoredMessage | null = row.result_id
        ? {
            id: row.result_id, userId: row.result_user_id ?? '', fromConnection: row.result_from ?? '', fromName: row.result_from_name ?? '',
            kind: 'result', replyTo: taskId,
            ephemeralPublicKey: unhex(row.result_ephemeral_public_key ?? ''), nonce: unhex(row.result_nonce ?? ''),
            ciphertext: unhex(row.result_ciphertext ?? ''), createdAt: row.result_created_at ?? row.created_at,
          }
        : null;
      return {
        createdAt: row.created_at, deleteAfter: row.delete_after, fetchedAt: row.fetched_at, withdrawnAt: row.withdrawn_at,
        workerStopped: row.worker_stopped === true, held: row.held === true, result,
      };
    },
    async withdrawTask(connectionId, taskId) {
      return call<WithdrawOutcome>('mailbox_withdraw_task', { p_connection: connectionId, p_task: taskId });
    },
    async taskWithdrawn(connectionId, taskId) {
      return call<boolean>('mailbox_task_withdrawn', { p_connection: connectionId, p_task: taskId });
    },
    async projectPeers(connectionId) {
      const rows = await call<Array<{ id: string; role: Role; agent_name: string; public_key: string; project_id: string; project_name: string; company_name: string }>>(
        'mailbox_project_peers', { p_connection: connectionId }
      );
      return (rows ?? []).map((r) => ({
        id: r.id, role: r.role, agentName: r.agent_name, publicKey: unhex(r.public_key), projectId: r.project_id, projectName: r.project_name, companyName: r.company_name,
      }));
    },
    async postInProject(m) {
      await call('mailbox_post_in_project', {
        p_id: m.id, p_from: m.from, p_to: m.to, p_project: m.projectId, p_kind: m.kind, p_reply_to: m.replyTo,
        p_ephemeral_public_key: hex(m.ephemeralPublicKey), p_nonce: hex(m.nonce), p_ciphertext: hex(m.ciphertext), p_size: m.size,
      });
    },
    async messageOrigins(connectionId, messageIds) {
      if (!messageIds.length) return new Map();
      const rows = await call<Array<{ id: string; project_name: string; company_name: string | null }>>('mailbox_message_origins', { p_connection: connectionId, p_ids: messageIds });
      return new Map((rows ?? []).map((r) => [r.id, { projectName: r.project_name, companyName: r.company_name ?? null }]));
    },
    async messageProject(connectionId, messageId) {
      return (await call<string | null>('mailbox_message_project', { p_connection: connectionId, p_id: messageId })) ?? null;
    },
    async projectOverview(userId, projectId) {
      return (await call<unknown>('mailbox_project_overview', { p_user_id: userId, p_group: projectId })) ?? null;
    },
    async shareAgent(userId, connectionId, projectId, companyId) {
      return call<string>('mailbox_share_agent', { p_user_id: userId, p_connection: connectionId, p_group: projectId, p_org: companyId });
    },
    async withdrawAgent(userId, connectionId, projectId) {
      return call<boolean>('mailbox_withdraw_agent', { p_user_id: userId, p_connection: connectionId, p_group: projectId });
    },
    async projectStop(userId, projectId, companyId, stop) {
      return call<string>('mailbox_project_stop', { p_user_id: userId, p_group: projectId, p_org: companyId, p_stop: stop });
    },
    async messageSender(connectionId, messageId) {
      const row = first(await call<Array<{ from_connection: string; kind: MessageKind }>>('mailbox_message_sender', { p_connection: connectionId, p_id: messageId }));
      return row ? { fromConnection: row.from_connection, kind: row.kind } : null;
    },
    async overview(userId) {
      return call<unknown>('mailbox_overview', { p_user_id: userId });
    },
  };
}
