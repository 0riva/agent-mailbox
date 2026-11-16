#!/usr/bin/env node
/**
 * Behavioural contract: the agent mailbox stores nothing a database reader can open (o-core#2069).
 *
 *   node scripts/test-agent-mailbox.mjs
 *
 * Seals a real message with apps/web/lib/mailbox/crypto.ts, stores it through the migration's
 * own tables, and checks the database side (grants, RLS, constraints, purge, rate limit). Then it
 * takes ONLY what the database held — public keys, wrapped keys, token hashes, ciphertext — and
 * proves the message cannot be opened from it, and can be with the agent's real token.
 * Same shape as scripts/test-paid-adverts.mjs:
 *  - NO SECOND COPY: the migration file and the real crypto module are used, not re-typed;
 *  - NO FOOTPRINT: one transaction, always rolled back;
 *  - NO FALSE PASS: every declared assertion must be reported, and all true.
 * Needs the local database, and Node with TypeScript type stripping (22.18+).
 */
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { createDecipheriv, hkdfSync, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const MIGRATIONS = ['20261023201527_agent_mailbox.sql', '20261023202708_agent_mailbox_tighten.sql', '20261023203732_agent_mailbox_rpc.sql', '20261023215923_agent_mailbox_rename.sql', '20261023222354_agent_mailbox_name_at_connect.sql'].map((f) => join(ROOT, 'supabase/migrations', f));
const SUITE = join(ROOT, 'supabase/migrations/__tests__/agent_mailbox.test.sql');
const PGURL = process.env.DATABASE_URL || 'postgresql://postgres:postgres@127.0.0.1:54331/postgres';

const fail = (msg) => {
  console.error(`\n✗ ${msg}`);
  process.exit(1);
};

const mb = await import(join(ROOT, 'apps/web/lib/mailbox/crypto.ts'));

// Two agents, each with keys wrapped under its own token, and one sealed task.
const agent = () => {
  const keys = mb.generateConnectionKeys();
  const access = mb.newToken();
  const refresh = mb.newToken();
  return { keys, access, refresh, wrapped: mb.wrapPrivateKey(keys.privateKey, access), wrappedRefresh: mb.wrapPrivateKey(keys.privateKey, refresh) };
};
const dispatcher = agent();
const worker = agent();
const MARKER = `MAILBOX-MARKER-${randomUUID()}`;
const messageId = randomUUID();
const userId = '02069000-0000-4000-8000-00000000000a';
const aad = mb.messageAad({
  messageId,
  userId,
  fromConnection: '02069000-0000-4000-8000-0000000000c1',
  toConnection: '02069000-0000-4000-8000-0000000000c2',
  kind: 'task',
});
const text = `Summarise this week's posts. ${MARKER}`;
const sealed = mb.sealTo(worker.keys.publicKey, text, aad);

const hex = (b) => Buffer.from(b).toString('hex');
const vars = {
  dispatcher_pub: hex(dispatcher.keys.publicKey),
  dispatcher_wrapped: hex(dispatcher.wrapped),
  dispatcher_wrapped_refresh: hex(dispatcher.wrappedRefresh),
  dispatcher_access_hash: hex(mb.hashToken(dispatcher.access)),
  dispatcher_refresh_hash: hex(mb.hashToken(dispatcher.refresh)),
  dispatcher_private: hex(dispatcher.keys.privateKey),
  worker_pub: hex(worker.keys.publicKey),
  worker_wrapped: hex(worker.wrapped),
  worker_wrapped_refresh: hex(worker.wrappedRefresh),
  worker_access_hash: hex(mb.hashToken(worker.access)),
  worker_refresh_hash: hex(mb.hashToken(worker.refresh)),
  worker_private: hex(worker.keys.privateKey),
  worker_access: worker.access,
  worker_refresh: worker.refresh,
  message_id: messageId,
  eph_pub: hex(sealed.ephemeralPublicKey),
  nonce: hex(sealed.nonce),
  ciphertext: hex(sealed.ciphertext),
  size_bytes: String(Buffer.byteLength(text)),
  marker: MARKER,
};

const suite = readFileSync(SUITE, 'utf8');
// A literal ending in '_' is a name PREFIX (t19_rpc_ || name), not an assertion.
const declared = [...new Set([...suite.matchAll(/'(t\d+_[a-z0-9_]+)'/g)].map((m) => m[1]))].filter((n) => !n.endsWith('_'));
if (declared.length === 0) fail('the suite declares no assertions — refusing to report a pass');
if (!suite.includes('--@@MIGRATION@@')) fail('the suite has no --@@MIGRATION@@ marker');

const script = join(mkdtempSync(join(tmpdir(), 'agent-mailbox-')), 'run.sql');
writeFileSync(script, ['BEGIN;', suite.split('--@@MIGRATION@@').join(MIGRATIONS.map((m) => readFileSync(m, 'utf8')).join('\n')), 'ROLLBACK;'].join('\n'));

let out;
try {
  out = execFileSync(
    'psql',
    [PGURL, '-v', 'ON_ERROR_STOP=1', '-At', ...Object.entries(vars).flatMap(([k, v]) => ['-v', `${k}=${v}`]), '-f', script],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 16 * 1024 * 1024 }
  );
} catch (error) {
  const lines = String(error.stderr || error.message).split('\n').filter(Boolean);
  const first = lines.find((l) => l.includes('ERROR')) || lines[0];
  fail(`psql failed: ${first}\n\nIs the local database up? Tried ${PGURL.replace(/:[^:@]*@/, ':***@')}`);
}

const results = new Map(
  out.split('\n').map((line) => line.match(/^(t\d+_[a-z0-9_]+)=(true|false)$/)).filter(Boolean).map((m) => [m[1], m[2] === 'true'])
);

// The runner's own assertions, from the bytes the database handed back.
const storedValue = (name) => {
  const v = out.split('\n').find((l) => l.startsWith(`${name}=`))?.slice(name.length + 1);
  if (!v) fail(`the suite never returned ${name}`);
  return Buffer.from(v, 'hex');
};
const fromDb = { ephemeralPublicKey: sealed.ephemeralPublicKey, nonce: sealed.nonce, ciphertext: storedValue('stored_ciphertext') };
const storedWrapped = storedValue('stored_worker_wrapped');
const storedHash = storedValue('stored_worker_access_hash');
// Rebuild the wrap key exactly as someone holding the rows would: HKDF over what is stored.
const unwrapAsReader = (ikm) => {
  const key = Buffer.from(hkdfSync('sha256', ikm, storedWrapped.subarray(0, 16), 'oriva-mailbox/wrap/v1', 32));
  const d = createDecipheriv('aes-256-gcm', key, storedWrapped.subarray(16, 28), { authTagLength: 16 });
  d.setAuthTag(storedWrapped.subarray(60));
  return Buffer.concat([d.update(storedWrapped.subarray(28, 60)), d.final()]);
};
const throws = (fn) => {
  try {
    fn();
    return false;
  } catch {
    return true;
  }
};
// A check that throws reports false, so a broken property is named rather than crashing the run.
const holds = (fn) => {
  try {
    return fn() === true;
  } catch {
    return false;
  }
};
const runner = {
  // What the database holds about the worker — the wrapped key, its salt and the token HASH —
  // does not unwrap the key, whether the hash is used as raw bytes or as text.
  r1_db_contents_cannot_unwrap_the_key:
    throws(() => unwrapAsReader(storedHash)) && throws(() => unwrapAsReader(Buffer.from(storedHash.toString('hex'), 'utf8'))),
  // Control for r1: the same reconstruction with the real token does unwrap the stored key.
  r1b_real_token_unwraps_the_stored_key: holds(() => unwrapAsReader(Buffer.from(worker.access, 'utf8')).equals(worker.keys.privateKey)),
  // The sender's own token cannot open a message sealed to someone else.
  r2_sender_cannot_open_it: throws(() =>
    mb.openSealed({ publicKey: dispatcher.keys.publicKey, privateKey: mb.unwrapPrivateKey(dispatcher.wrapped, dispatcher.access) }, fromDb, aad)
  ),
  // With the worker's real token the stored bytes do open — so the test above is not vacuous.
  r3_receiver_token_opens_it: holds(
    () => mb.openSealed({ publicKey: worker.keys.publicKey, privateKey: mb.unwrapPrivateKey(storedWrapped, worker.access) }, fromDb, aad) === text
  ),
  // The refresh token unwraps its own copy, so a token refresh can re-wrap the key.
  r4_refresh_token_unwraps_its_copy: holds(() => mb.unwrapPrivateKey(worker.wrappedRefresh, worker.refresh).equals(worker.keys.privateKey)),
};

const RPC_CHECKS = 34;  // distinct t19_rpc_* names written by the suite's DO block; a missing one must fail the run
const rpcRows = [...results.keys()].filter((n) => n.startsWith('t19_rpc_')).length;
if (rpcRows !== RPC_CHECKS) fail(`expected ${RPC_CHECKS} t19_rpc_* results, got ${rpcRows}`);
const missing = declared.filter((name) => !results.has(name));
if (missing.length) fail(`${missing.length} declared assertion(s) never reported: ${missing.join(', ')}`);
const all = [...results.entries(), ...Object.entries(runner)];
for (const [name, ok] of all) console.log(`${ok ? '✓' : '✗'} ${name}`);
const failed = all.filter(([, ok]) => !ok);
if (failed.length) fail(`${failed.length} assertion(s) failed`);
console.log(`\n✓ ${all.length} agent mailbox assertions pass (${results.size} in the database, ${Object.keys(runner).length} on the stored bytes)`);
