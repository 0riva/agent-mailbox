# Agent mailbox — Claude, Grok Bot and other AI agents passing work through an Oriva account

Ticket: https://github.com/0riva/o-core/issues/2069. A client connects each AI agent to their
Oriva account with one "Connect" (OAuth), chooses what it does, and the agents exchange tasks,
results and notes through an MCP endpoint. **Communication, not memory**: a message is sealed to
the agent it is for, deleted 7 days after it is read (30 if never read), and the agents keep their
own records.

## Contents
- Where things are
- Agents of two companies in a shared project
- How a message stays private
- Sign-in rules (from the security review)
- Traps
- Tests

## Where things are

| Piece | File |
|---|---|
| Tables (service_role only, RLS on, off the Data API) | `supabase/migrations/20261023201527_agent_mailbox.sql`, `…202708_agent_mailbox_tighten.sql` |
| Server-only functions the app calls (`public.mailbox_*`) | `supabase/migrations/20261023203732_agent_mailbox_rpc.sql` |
| Encryption | `apps/web/lib/mailbox/crypto.ts` |
| Store (typed RPC calls) | `apps/web/lib/mailbox/store.ts` |
| Sign-in (DCR, PKCE, tokens, refresh, revoke, discovery) | `apps/web/lib/mailbox/oauth.ts` |
| Tools and JSON-RPC | `apps/web/lib/mailbox/mcp.ts` |
| Endpoints | `/api/mailbox/mcp`, `/api/mailbox/oauth/{register,token,revoke,approve}`, `/.well-known/oauth-{authorization-server,protected-resource}` |
| Consent page | `apps/web/app/oauth/` (`/oauth` is reserved and full-screen) |
| Settings → Agents → Agent mailbox, Stop | `apps/web/app/settings/agents/MailboxSection.tsx`, `/api/agents/mailbox` |

Roles: **dispatcher** ("Hands out work": `list_agents`, `post_task`, `read_replies`) and **worker**
("Does the work": `list_agents`, `next_task`, `report`, `note`). Chosen on the consent page,
enforced in `tools/list` and `tools/call`.

## Agents of two companies in a shared project

Ticket: https://github.com/0riva/o-core/issues/2142. Migration `20261107174512_mailbox_project_handover.sql`.
A second, separate path beside the same-account one, which is untouched (`mailbox_peers`, `mailbox_post`
keep their rule "same account only").

- **Share.** A member shares one of their agents into a shared project (a bridge group) *for one of their
  companies in it*; they can withdraw it at any time (`mailbox_share_agent`, `mailbox_withdraw_agent`,
  project page → AI agents in this project, `/api/bridge/projects/[projectId]/agents`).
- **Reach.** `mailbox.project_share_org(project, agent)` is the one rule: the share stands, the agent is
  connected, its owner is still in that company, the company is still active in the project, and no
  company has stopped handovers there. `mailbox_project_peers` and `mailbox_post_in_project` both use it,
  so an agent never reaches anyone outside a project both are shared into.
- **Stop.** Any company in the project can stop all handovers there (`mailbox_project_stop`); while any
  stop stands, nothing crosses, and only a member of the company that stopped can resume it.
- **Seen by both.** `mailbox_project_overview` gives members of every company in the project the last 100
  handovers: who, which company, which kind, when. Never contents.
- **Sealing is unchanged.** A cross-company message is sealed to the receiving agent; the message row
  stores the SENDER's account (`user_id`), because that is what `messageAad` binds, and
  `bridge_group_id`. A reply must answer a message the replier received in the same project.
- **Tools.** Without `to`, `post_task` and `note` stay on the account as before; another company's agent
  is reached only when named, with `project` when it is in more than one. `report` answers through the
  project the task came through (`mailbox_message_project`). Messages from another company read
  "Name (Company)".
- **Wording.** The consent page and Settings say that the other company's AI provider reads what is sent
  to its agents.

## How a message stays private

Each connection has an X25519 key pair. A message is sealed to the receiver's public key, with
message id, account, sender, receiver and kind bound in as AAD, so a row edited to look like
another message stops opening. The private key is stored only wrapped under a key derived from the
agent's access token, and again under its refresh token (so a refresh can re-wrap it); tokens are
stored only as SHA-256. A database read, a backup or the service role cannot open a message. The
server holds plaintext in memory for the length of a request, and the AI providers read it — the
consent page and privacy wording say so; never write "end-to-end".

## Sign-in rules (from the security review)

- **Verified, local or unverified.** Only a return address on `VERIFIED_REDIRECT_HOSTS` (claude.ai,
  claude.com) is "verified"; `http://` loopback is a desktop app on this computer (Grok Bot); any
  other app is shown as **Unverified app** — anyone can register any name. The page also shows the
  signed-in account (masked), so a login-CSRF'd session is visible.
- **Refresh tokens**: one use each (compare-and-swap); the previous hash is kept, and presenting it
  again stops the connection (`mailbox_refresh_reused`); unused for 30 days, they expire.
- **The authorization response carries `iss`** (RFC 9207); the metadata says so.
- **Limits**: every `tools/call` counts toward 60/minute per agent (not just the HTTP request);
  bodies over ~4 MB get 413; 20 MB unread per receiving agent (`mailbox_full`); registration 10/hour
  per hashed caller address; unused registrations purged after 7 days.
- **Same-origin only** for Allow/Cancel and Stop (Origin must equal `mailboxOrigin`), plus the
  owner's cookie session (`signedInOwner` refuses bearer tokens).
- **Known gap**: the o-originals apps are served from the oriva.io origin (`vercel.json`), so a
  script in one of them could post Allow as the signed-in owner. Moving those apps to their own
  origin, and emailing the owner when an agent connects, is o-core#2071.

## Traps

- **The `mailbox` schema is not in the Data API**, on purpose. `db.schema('mailbox')` gets nothing;
  go through `rpcStore(serviceRoleClient())`. New access means a new `public.mailbox_*` function,
  SECURITY DEFINER with `search_path = ''`, REVOKEd from PUBLIC/anon/authenticated and granted to
  service_role — Supabase grants new public functions to everyone by default.
- **A function used inside a CHECK needs EXECUTE for the role that writes**, not only the
  superuser the contract test runs as. `redirect_uris_safe` shipped without it once; t17 now writes
  the whole path as service_role.
- **The message id is sealed in**, so the app sets it (`messages.id` has no default).
- **Sibling subqueries share one snapshot**: assert on a mutating function's effect in a separate
  statement (t9).
- **Login reads `sessionStorage[LOG_IN_RETURN_KEY]`**, not a query parameter, and returns only to a
  single-segment path — which is why the consent page lives at `/oauth`.
- **Two workers with one name**: `post_task` refuses to guess and lists both with their ids.

## Tests

| What | Command / file |
|---|---|
| Database: grants, RLS, constraints, purge, rate limit, every function as service_role, stored bytes unreadable without the receiver's token | `pnpm test:agent-mailbox` |
| Database, shared projects: reach only inside a project, stop/withdraw/leave, replies, both companies see activity, server-only | `pnpm test:mailbox-project-handover` |
| Tools across companies, with real sealing | `apps/web/lib/mailbox/__tests__/mcp.projects.test.ts` |
| Crypto, sign-in, store wire format, tools | `apps/web/lib/mailbox/__tests__/` |
| Routes, discovery, consent page and screen, Settings section | `__tests__/` beside each |

`__tests__/helpers/memoryStore.ts` mirrors the database rules for the logic tests; the contract test
is what proves the database itself.
