/**
 * An in-memory MailboxStore for tests, with the same rules the database functions enforce
 * (supabase/migrations/20261023203732_agent_mailbox_rpc.sql): a code is taken once, a refresh
 * token rotates once (compare-and-swap), a stopped agent has no tokens or keys, messages go only
 * between active agents on one account — or, through a shared project, between agents shared into it
 * while no company has stopped handovers there (o-core#2142). The database side of each rule is
 * proven separately by `pnpm test:agent-mailbox` and `pnpm test:mailbox-project-handover`.
 */
import { randomUUID } from 'node:crypto';

import type { MailboxStore, NewConnection, NewMessage, Role, StoredMessage } from '../../store';

interface Conn extends NewConnection {
  id: string;
  agentName: string;
  accessExpiresAt: number;
  refreshExpiresAt: number;
  previousRefreshHash: Buffer | null;
  stopped: boolean;
}

export function memoryStore() {
  const clients = new Map<string, { clientName: string; redirectUris: string[] }>();
  const codes = new Map<string, { clientId: string; userId: string; role: Role; redirectUri: string; challenge: string; expiresAt: number; agentName: string | null }>();
  const conns = new Map<string, Conn>();
  const messages: Array<NewMessage & { userId: string; readAt: number | null; createdAt: string; projectId?: string }> = [];
  // Shared projects: which companies are in each, who is in each company, which agents are shared, and stops.
  const projects = new Map<string, { name: string; companies: Map<string, { name: string; members: Set<string>; active: boolean }> }>();
  const shares: Array<{ projectId: string; connectionId: string; companyId: string; withdrawn: boolean }> = [];
  const stops = new Set<string>();
  const memberCompanies = (userId: string, projectId: string) =>
    [...(projects.get(projectId)?.companies.entries() ?? [])].filter(([, c]) => c.active && c.members.has(userId)).map(([id]) => id);
  const shareCompany = (projectId: string, connectionId: string): string | null => {
    if ([...stops].some((s) => s.startsWith(`${projectId}:`))) return null;
    const conn = conns.get(connectionId);
    const share = shares.find((s) => s.projectId === projectId && s.connectionId === connectionId && !s.withdrawn);
    if (!conn || conn.stopped || !share) return null;
    const company = projects.get(projectId)?.companies.get(share.companyId);
    return company?.active && company.members.has(conn.userId) ? share.companyId : null;
  };
  const hits = new Map<string, number>();
  const requestHits = new Map<string, number>();
  const key = (b: Buffer | null | undefined) => (b ? b.toString('hex') : '');
  let now = () => Date.now();

  const store: MailboxStore = {
    async registerClient(clientId, name, redirectUris) {
      clients.set(clientId, { clientName: name, redirectUris });
    },
    async client(clientId) {
      return clients.get(clientId) ?? null;
    },
    async createCode(c) {
      const client = clients.get(c.clientId);
      if (!client || !client.redirectUris.includes(c.redirectUri)) throw new Error('redirect_uri is not registered for this client');
      const name = c.agentName?.trim() || null;
      if (name && name.length > 100) throw new Error('name must be 1 to 100 characters');
      codes.set(key(c.codeHash), { clientId: c.clientId, userId: c.userId, role: c.role, redirectUri: c.redirectUri, challenge: c.challenge, expiresAt: now() + c.ttlSeconds * 1000, agentName: name });
    },
    async takeCode(codeHash) {
      const c = codes.get(key(codeHash));
      if (!c) return null;
      codes.delete(key(codeHash));
      return { clientId: c.clientId, userId: c.userId, role: c.role, redirectUri: c.redirectUri, codeChallenge: c.challenge, expired: c.expiresAt < now(), agentName: c.agentName };
    },
    async connect(c) {
      const id = randomUUID();
      conns.set(id, {
        ...c, id, agentName: c.agentName?.trim() || clients.get(c.clientId)?.clientName || 'AI agent', accessExpiresAt: now() + c.accessTtlSeconds * 1000,
        refreshExpiresAt: now() + 30 * 86_400_000, previousRefreshHash: null, stopped: false,
      });
      return id;
    },
    async byAccess(accessHash) {
      const c = [...conns.values()].find((x) => !x.stopped && key(x.accessHash) === key(accessHash));
      return c ? { id: c.id, userId: c.userId, role: c.role, agentName: c.agentName, publicKey: c.publicKey, wrapped: c.wrapped, expired: c.accessExpiresAt < now() } : null;
    },
    async byRefresh(refreshHash) {
      const c = [...conns.values()].find((x) => !x.stopped && key(x.refreshHash) === key(refreshHash));
      return c ? { id: c.id, clientId: c.clientId, publicKey: c.publicKey, wrappedRefresh: c.wrappedRefresh, expired: c.refreshExpiresAt < now() } : null;
    },
    async rotate(r) {
      const c = [...conns.values()].find((x) => !x.stopped && key(x.refreshHash) === key(r.oldRefreshHash) && x.refreshExpiresAt >= now());
      if (!c) return false;
      Object.assign(c, {
        wrapped: r.wrapped, wrappedRefresh: r.wrappedRefresh, accessHash: r.accessHash, refreshHash: r.refreshHash,
        accessExpiresAt: now() + r.accessTtlSeconds * 1000, refreshExpiresAt: now() + 30 * 86_400_000, previousRefreshHash: r.oldRefreshHash,
      });
      return true;
    },
    async refreshReused(refreshHash) {
      const c = [...conns.values()].find((x) => !x.stopped && key(x.previousRefreshHash) === key(refreshHash));
      if (!c) return false;
      c.stopped = true;
      return true;
    },
    async requestLimit(k, perHour) {
      const n = (requestHits.get(k) ?? 0) + 1;
      requestHits.set(k, n);
      return n <= perHour;
    },
    async stop(userId, connectionId) {
      const c = conns.get(connectionId);
      if (!c || c.userId !== userId || c.stopped) return false;
      c.stopped = true;
      return true;
    },
    async rename(userId, connectionId, name) {
      const c = conns.get(connectionId);
      const trimmed = name.trim();
      if (!trimmed || trimmed.length > 100) throw new Error('name must be 1 to 100 characters');
      if (!c || c.userId !== userId || c.stopped) return false;
      c.agentName = trimmed;
      return true;
    },
    async revoke(tokenHash) {
      for (const c of conns.values()) if (key(c.accessHash) === key(tokenHash) || key(c.refreshHash) === key(tokenHash)) c.stopped = true;
    },
    async rateLimit(connectionId, perMinute) {
      const n = (hits.get(connectionId) ?? 0) + 1;
      hits.set(connectionId, n);
      return n <= perMinute;
    },
    async peers(connectionId) {
      const me = conns.get(connectionId);
      if (!me) return [];
      return [...conns.values()]
        .filter((p) => p.id !== me.id && p.userId === me.userId && !p.stopped)
        .map((p) => ({ id: p.id, role: p.role, agentName: p.agentName, publicKey: p.publicKey }));
    },
    async post(m) {
      const from = conns.get(m.from);
      const to = conns.get(m.to);
      if (!from || !to || from.stopped || to.stopped || from.userId !== to.userId) throw new Error('sender and receiver must be active agents on the same account');
      const unread = messages.filter((x) => x.to === m.to && x.readAt === null).reduce((n, x) => n + x.size, 0);
      if (unread + m.size > 20_971_520) throw new Error('[mailbox] mailbox_post: mailbox_full');
      messages.push({ ...m, userId: from.userId, readAt: null, createdAt: new Date(now()).toISOString() });
    },
    async inbox(connectionId, kinds, limit) {
      return messages
        .filter((m) => m.to === connectionId && m.readAt === null && (!kinds || kinds.includes(m.kind)))
        // Project mail is held while either agent cannot reach the other there (stop, withdrawal, departure).
        .filter((m) => !m.projectId || (shareCompany(m.projectId, m.from) && shareCompany(m.projectId, m.to)))
        .slice(0, limit)
        .map((m): StoredMessage => ({
          id: m.id, userId: m.userId, fromConnection: m.from, fromName: conns.get(m.from)?.agentName ?? '', kind: m.kind, replyTo: m.replyTo,
          ephemeralPublicKey: m.ephemeralPublicKey, nonce: m.nonce, ciphertext: m.ciphertext, createdAt: m.createdAt,
        }));
    },
    async markRead(connectionId, ids) {
      let n = 0;
      for (const m of messages) if (m.to === connectionId && ids.includes(m.id) && m.readAt === null) { m.readAt = now(); n += 1; }
      return n;
    },
    async messageSender(connectionId, messageId) {
      const m = messages.find((x) => x.id === messageId && x.to === connectionId);
      return m ? { fromConnection: m.from, kind: m.kind } : null;
    },
    async overview(userId) {
      return { agents: [...conns.values()].filter((c) => c.userId === userId).map((c) => ({ id: c.id, name: c.agentName, role: c.role })), activity: [] };
    },
    async projectPeers(connectionId) {
      const me = conns.get(connectionId);
      if (!me || me.stopped) return [];
      return shares
        .filter((mine) => mine.connectionId === me.id && shareCompany(mine.projectId, me.id))
        .flatMap((mine) =>
          shares
            .filter((s) => s.projectId === mine.projectId && conns.get(s.connectionId)?.userId !== me.userId && shareCompany(s.projectId, s.connectionId))
            .map((s) => {
              const p = conns.get(s.connectionId)!;
              const project = projects.get(s.projectId)!;
              return { id: p.id, role: p.role, agentName: p.agentName, publicKey: p.publicKey, projectId: s.projectId, projectName: project.name, companyName: project.companies.get(s.companyId)!.name };
            })
        );
    },
    async postInProject(m) {
      const from = conns.get(m.from);
      const to = conns.get(m.to);
      if (!from || !to || from.stopped || to.stopped || from.userId === to.userId || !shareCompany(m.projectId, m.from) || !shareCompany(m.projectId, m.to)) {
        throw new Error('[mailbox] mailbox_post_in_project: project_handover_refused');
      }
      if (m.replyTo && !messages.some((x) => x.id === m.replyTo && x.to === m.from && x.projectId === m.projectId)) {
        throw new Error('reply_to is not a message this agent received in this project');
      }
      messages.push({ ...m, userId: from.userId, readAt: null, createdAt: new Date(now()).toISOString() });
    },
    async messageOrigins(connectionId, messageIds) {
      const out = new Map<string, { projectName: string; companyName: string | null }>();
      for (const m of messages) {
        if (m.to !== connectionId || !m.projectId || !messageIds.includes(m.id)) continue;
        const project = projects.get(m.projectId);
        const share = [...shares].reverse().find((s) => s.projectId === m.projectId && s.connectionId === m.from);
        out.set(m.id, { projectName: project?.name ?? '', companyName: share ? project?.companies.get(share.companyId)?.name ?? null : null });
      }
      return out;
    },
    async messageProject(connectionId, messageId) {
      return messages.find((x) => x.id === messageId && x.to === connectionId)?.projectId ?? null;
    },
    async projectOverview(userId, projectId) {
      return memberCompanies(userId, projectId).length ? { shares: shares.filter((s) => s.projectId === projectId && !s.withdrawn), stops: [...stops] } : null;
    },
    async shareAgent(userId, connectionId, projectId, companyId) {
      const conn = conns.get(connectionId);
      if (!conn || conn.userId !== userId || conn.stopped) return 'not_your_agent';
      if (!memberCompanies(userId, projectId).includes(companyId)) return 'not_in_project';
      if (shares.some((s) => s.projectId === projectId && s.connectionId === connectionId && !s.withdrawn)) return 'already_shared';
      shares.push({ projectId, connectionId, companyId, withdrawn: false });
      return 'shared';
    },
    async withdrawAgent(userId, connectionId, projectId) {
      const share = shares.find((s) => s.projectId === projectId && s.connectionId === connectionId && !s.withdrawn && conns.get(connectionId)?.userId === userId);
      if (!share) return false;
      share.withdrawn = true;
      return true;
    },
    async projectStop(userId, projectId, companyId, stop) {
      if (!memberCompanies(userId, projectId).includes(companyId)) return 'not_in_project';
      if (stop) stops.add(`${projectId}:${companyId}`);
      else stops.delete(`${projectId}:${companyId}`);
      return stop ? 'stopped' : 'resumed';
    },
  };
  /** Set up a shared project with companies and their members, for the cross-company tests. */
  const addProject = (projectId: string, name: string, companies: Record<string, { name: string; members: string[] }>) => {
    projects.set(projectId, {
      name,
      companies: new Map(Object.entries(companies).map(([id, c]) => [id, { name: c.name, members: new Set(c.members), active: true }])),
    });
  };
  return { store, conns, messages, projects, addProject, setNow: (fn: () => number) => (now = fn) };
}
