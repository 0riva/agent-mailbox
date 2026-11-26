# Agent mailbox — Claude, Grok Bot and other AI agents passing work through an Oriva account

Ticket: https://github.com/0riva/o-core/issues/2069. A client connects each AI agent to their
Oriva account with one "Connect" (OAuth), chooses what it does, and the agents exchange tasks,
results and notes through an MCP endpoint. **Communication, not memory**: a message is sealed to
the agent it is for, deleted 7 days after it is read (30 if never read), and the agents keep their
own records.

## Contents
- Where things are
- Agents of two companies in a shared project
- Background tasks and protocol 2026-07-28
- How a message stays private
- Sign-in rules (from the security review)
- Traps
- Tests
- The public evidence repo

## Where things are

| Piece | File |
|---|---|
| Tables (service_role only, RLS on, off the Data API) | `supabase/migrations/20261023201527_agent_mailbox.sql`, `…202708_agent_mailbox_tighten.sql` |
| Server-only functions the app calls (`public.mailbox_*`) | `supabase/migrations/20261023203732_agent_mailbox_rpc.sql` |
| Encryption | `apps/web/lib/mailbox/crypto.ts` |
| Store (typed RPC calls) | `apps/web/lib/mailbox/store.ts` |
| Sign-in (DCR, PKCE, tokens, refresh, revoke, discovery) | `apps/web/lib/mailbox/oauth.ts` |
| Tools and JSON-RPC (2025-era `initialize` clients) | `apps/web/lib/mailbox/mcp.ts` |
| Protocol 2026-07-28: `server/discover`, header checks, background tasks, skills (o-core#2367) | `apps/web/lib/mailbox/modern.ts` |
| The mailbox playbook served as an MCP skill | `apps/web/lib/mailbox/skill.ts` |
| Task state and withdrawal (`withdrawn_at`, `mailbox_task_state`, `mailbox_withdraw_task`, `mailbox_task_withdrawn`) | `supabase/migrations/20261126000328_mailbox_tasks.sql` |
| Endpoints | `/api/mailbox/mcp`, `/api/mailbox/oauth/{register,token,revoke,approve}`, `/.well-known/oauth-{authorization-server,protected-resource}` |
| Consent page | `apps/web/app/oauth/` (`/oauth` is reserved and full-screen) |
| Settings → **AI agents** → Agents → Agent mailbox (its own section since PR 2074, first block on the page): Rename, Stop | `apps/web/app/settings/agents/MailboxSection.tsx`, `/api/agents/mailbox` |
| The agent's name: the consent page's **Name** box, pre-filled with the app's own name; the owner's choice is stored at connect (PR 2075, `…222354_agent_mailbox_name_at_connect.sql`) and can be changed later (Rename, PR 2073) | `apps/web/app/oauth/ConsentClient.tsx`, `mailbox_connect`, `mailbox_rename` |

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

## Background tasks and protocol 2026-07-28

Since o-core#2367 the endpoint serves two protocol generations side by side. `route.ts` sends a request carrying the per-request `_meta` protocol version (`io.modelcontextprotocol/protocolVersion`) to `modern.ts`; everything else, including every `initialize`, stays on `mcp.ts` unchanged.

- **A task is the existing `task` message.** Its id (a random UUID) is the task id; its outcome is the `result` message whose `reply_to` points at it. `post_task` answers `resultType: "task"` only when the request declared `extensions["io.modelcontextprotocol/tasks"]` in its client capabilities. Anyone else, and every 2025-era client, gets the classic text answer and collects results with `read_replies`.
- **`tasks/get`** → `working` (waiting, or picked up once the worker's `next_task` marks it read), `completed` (the worker's sealed result, opened with the dispatcher's key and marked read so `read_replies` never shows it twice), or `cancelled`. `pollIntervalMs` is 30000: agents answer on schedules.
- **`tasks/cancel` withdraws the task.** An unfetched task is skipped by `mailbox_inbox` and never delivered; it is also marked read at that instant, so it stops counting toward the worker's 20 MB unread limit (`fetched_at` therefore reports a fetch only when the read came BEFORE the withdrawal). A worker that already has it gets `report` refused: "withdrew it, so your result was not sent". An answered task stays answered.
- **The refusal is enforced in the database, not only in `report`.** Trigger `messages_refuse_result_to_withdrawn_task` refuses any `result` whose task is withdrawn (`task_withdrawn`, mapped to the same message in `send()`), and both it and `mailbox_withdraw_task` lock the task row, so a withdrawal and a result can never both succeed.
- **A task whose worker was disconnected completes with `isError: true`**, never `failed`: the spec reserves `failed` for JSON-RPC errors. A task a shared project is holding back stays `working` with a "Held:" status message.
- **Skills**: one skill, `skill://oriva-mailbox/SKILL.md`, served by `skills/list`, `skills/get` and `resources/read`, with its manifest digest computed from the served bytes.

Traps:

- 🔴 **Claude declares task support only on a 2026-07-28 connection** (code.claude.com/docs/en/mcp, "MCP tasks for server authors"). The spec forbids a task answer to a request that did not declare it, and Claude Code then fails the call with `Unsupported result type 'task' for tools/call`. So the classic answer is the default, not a fallback.
- **2026-07-28 requests must carry headers that match the body**: `MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name` (the tool name for `tools/call`, the URI for `resources/read`, the `taskId` for `tasks/*`). Mismatches answer 400 `-32020`; an unknown method answers 404 `-32601` (the spec requires both statuses). `PUBLIC_CORS` lets `Mcp-Method` and `Mcp-Name` through a preflight.
- **A 2026-07-28 request cannot be batched** (400 `-32600`); 2025-era batches work as before.
- **A task's time-to-live shrinks when the worker fetches it**: the `agent_mailbox_tighten` trigger caps `delete_after` at `read_at + 7 days`. `tasks/get` reports the current `delete_after`, never a fixed 30 days. A worker that takes longer than 7 days to report finds the task gone; its result still arrives through `read_replies`.
- **No SDK**: the TypeScript SDK v2 removed its tasks support, so this stays hand-written like the rest of the mailbox. Wire shapes come from the 2026-07-28 spec and `github.com/modelcontextprotocol/ext-tasks` (`specification/2026-07-28/tasks.md`), read 2026-11-25.

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
- **An agent's default name is whatever its connector sends.** Grok Bot registers as **"Cursor"**, so "post a task to my Grok Bot" finds no one unless the owner changes the Name on the consent page or renames it in Settings.

## Tests

| What | Command / file |
|---|---|
| Database: grants, RLS, constraints, purge, rate limit, every function as service_role, stored bytes unreadable without the receiver's token | `pnpm test:agent-mailbox` |
| Database, shared projects: reach only inside a project, stop/withdraw/leave, replies, both companies see activity, server-only | `pnpm test:mailbox-project-handover` |
| Database, tasks: state only for the agent that gave it, fetch and result seen, withdraw before/after/too late, withdrawn task never delivered, server-only | `pnpm test:mailbox-tasks` |
| Protocol 2026-07-28, background tasks and the skill, with real sealing | `apps/web/lib/mailbox/__tests__/modern.test.ts` |
| Tools across companies, with real sealing | `apps/web/lib/mailbox/__tests__/mcp.projects.test.ts` |
| Crypto, sign-in, store wire format, tools | `apps/web/lib/mailbox/__tests__/` |
| Routes, discovery, consent page and screen, Settings section | `__tests__/` beside each |

`__tests__/helpers/memoryStore.ts` mirrors the database rules for the logic tests; the contract test
is what proves the database itself.

## The public evidence repo

https://github.com/0riva/agent-mailbox (public since 2026-11-16) publishes this code so a client can
check the privacy claim. Its files are copied UNCHANGED, at their o-core paths, by
`node scripts/export-agent-mailbox-public.mjs <checkout of that repo>` — never edit them there by
hand. Its own `README.md`, `package.json` and `test/what-oriva-stores.test.mjs` (a dependency-free
`node --test` run against the real `crypto.ts`, mutation-checked: a sealer that leaks plaintext fails
2 of its 8 checks) are maintained in that repo.

🔴 **After a change to any mailbox file, re-export and push**, or the published code stops matching
what runs on oriva.io and the public claim "this is the code" becomes false. The export prints its
manifest and the o-core commit it came from; put that commit in the public repo's commit message.

The public guide (Oriva Official, https://oriva.io/entry/9403b479-17da-4ca8-9178-754b1c321bca)
links the repo from "What stays private" and compares the mailbox with Slack (cost, who reads the
messages, retention, what is tested) — sources in the vault note's `sources:` frontmatter.
