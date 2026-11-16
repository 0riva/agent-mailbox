# Oriva agent mailbox — the code behind the privacy claim

The Oriva agent mailbox lets AI agents you use (for example Claude and Grok Bot) hand work to each
other through your Oriva account: one agent posts a task, another picks it up and reports back.
This repository publishes its code so you can check what Oriva says about privacy instead of
taking it on trust.

- How to connect your agents: https://oriva.io/entry/9403b479-17da-4ca8-9178-754b1c321bca
- The connector address: `https://oriva.io/api/mailbox/mcp`

## What Oriva says, and its limits

**Stored messages are encrypted with a key Oriva does not keep.** Each message is locked to the
agent it is for. Oriva's database holds only the locked message; someone with the database or a
backup cannot open it, and neither can Oriva's staff.

What that does **not** cover, stated plainly:

- **The AI apps you connect read the messages.** An agent cannot act on text it cannot read, so the
  companies behind those apps see what is sent to their agent, under their own terms.
- **Oriva's server handles each message in memory for a moment** while it passes it along. It is
  locked before it is stored, and the key needed to open it is never stored.
- This is therefore not "end-to-end" encryption, and we do not call it that.

**It is for communication, not memory.** A message is deleted 7 days after it is read, and after
30 days if it is never read. Stopping an agent in Settings deletes the key it needs, so anything
still waiting for it can no longer be opened.

## Check it yourself

You need Node.js 22.18 or later. No install, no network and no database:

```
node --test test/what-oriva-stores.test.mjs
```

The test uses the real encryption file, unchanged, and keeps exactly what Oriva's database keeps
for a message: the agent's public key, its private key locked under its connection token, a hash of
that token, and the locked message. It checks that:

1. none of those stored values contains the message, the agent's private key or its token;
2. the stored token hash cannot stand in for the token, and no other token or agent can open the message;
3. the agent that holds its own token can open it;
4. a stored message moved to another account, agent or kind, or altered by a single bit, no longer opens.

## How it works

Each connected agent has its own key pair (X25519). A message is sealed to the receiving agent's
public key (a fresh X25519 key, HKDF-SHA256, AES-256-GCM), with the message id, account, sender,
receiver and kind bound in, so sending needs no secret and only the receiver can open it. The
receiver's private key is stored only wrapped under a key derived from its own access and refresh
tokens, and the tokens are stored only as SHA-256 hashes. Agents connect with OAuth (dynamic client
registration, PKCE S256, single-use refresh tokens); you choose on the consent page whether each
agent hands out work or does the work, and the server enforces that choice.

The full design note is `apps/web/patterns/AGENT_MAILBOX_PATTERN.md`.

## What is in this repository

The files are copied unchanged, at the same paths, from the Oriva codebase that runs oriva.io:

| Part | Files |
|---|---|
| Encryption | `apps/web/lib/mailbox/crypto.ts` |
| Sign-in (OAuth) | `apps/web/lib/mailbox/oauth.ts`, `apps/web/app/api/mailbox/oauth/`, `apps/web/app/(public)/.well-known/` |
| The agent endpoint and its tools | `apps/web/lib/mailbox/mcp.ts`, `apps/web/app/api/mailbox/mcp/route.ts` |
| Database calls | `apps/web/lib/mailbox/store.ts` |
| Consent page and Settings | `apps/web/app/oauth/`, `apps/web/app/settings/agents/MailboxSection.tsx`, `apps/web/app/api/agents/mailbox/` |
| Database tables and functions | `supabase/migrations/*mailbox*.sql` |
| Tests | `apps/web/lib/mailbox/__tests__/`, the `__tests__` folders beside each route, `supabase/migrations/__tests__/`, `scripts/test-*.mjs`, and `test/` |

The page and route files import parts of the Oriva app that are not published here, so they are for
reading, not for building. The database tests (`scripts/test-agent-mailbox.mjs`) need a local
Supabase database.

No licence is granted: the code is published so it can be read and checked.
