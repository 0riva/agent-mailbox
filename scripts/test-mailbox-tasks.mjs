#!/usr/bin/env node
/**
 * Behavioural contract: a dispatcher follows a task it gave (its state, the worker's result) and can
 * withdraw it; a withdrawn task never reaches a worker that has not fetched it (o-core#2367).
 *
 *   node scripts/test-mailbox-tasks.mjs
 *
 * Applies the agent mailbox migrations and 20261126000328_mailbox_tasks.sql inside one
 * transaction on the local database, exercises every server function, and rolls back.
 *  - NO SECOND COPY: the migration file itself is applied, not re-typed;
 *  - NO FOOTPRINT: one transaction, always rolled back;
 *  - NO FALSE PASS: every declared assertion must be reported, and all true.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const MIGRATIONS = [
  '20261023201527_agent_mailbox.sql',
  '20261023202708_agent_mailbox_tighten.sql',
  '20261023203732_agent_mailbox_rpc.sql',
  '20261023215923_agent_mailbox_rename.sql',
  '20261023222354_agent_mailbox_name_at_connect.sql',
  '20261107174512_mailbox_project_handover.sql',
  '20261126000328_mailbox_tasks.sql',
].map((f) => join(ROOT, 'supabase/migrations', f));
const SUITE = join(ROOT, 'supabase/migrations/__tests__/mailbox_tasks.test.sql');
const PGURL = process.env.DATABASE_URL || 'postgresql://postgres:postgres@127.0.0.1:54331/postgres';

const fail = (msg) => {
  console.error(`\n✗ ${msg}`);
  process.exit(1);
};

const suite = readFileSync(SUITE, 'utf8');
const declared = [...new Set([...suite.matchAll(/'(t\d+b?_[a-z0-9_]+)'/g)].map((m) => m[1]))];
if (declared.length === 0) fail('the suite declares no assertions — refusing to report a pass');
if (!suite.includes('--@@MIGRATION@@')) fail('the suite has no --@@MIGRATION@@ marker');

const script = join(mkdtempSync(join(tmpdir(), 'mailbox-tasks-')), 'run.sql');
writeFileSync(script, ['BEGIN;', suite.replace('--@@MIGRATION@@', () => MIGRATIONS.map((m) => readFileSync(m, 'utf8')).join('\n')), 'ROLLBACK;'].join('\n'));

let out;
try {
  out = execFileSync('psql', [PGURL, '-v', 'ON_ERROR_STOP=1', '-At', '-f', script], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 16 * 1024 * 1024,
  });
} catch (error) {
  const lines = String(error.stderr || error.message).split('\n').filter(Boolean);
  fail(`psql failed: ${lines.find((l) => l.includes('ERROR')) || lines[0]}\n\nIs the local database up? Tried ${PGURL.replace(/:[^:@]*@/, ':***@')}`);
}

const results = new Map(
  out.split('\n').map((line) => line.match(/^(t\d+b?_[a-z0-9_]+)=(true|false)$/)).filter(Boolean).map((m) => [m[1], m[2] === 'true'])
);

let failed = 0;
for (const name of declared) {
  if (!results.has(name)) {
    console.error(`✗ ${name} — never reported`);
    failed++;
  } else if (!results.get(name)) {
    console.error(`✗ ${name}`);
    failed++;
  } else {
    console.log(`✓ ${name}`);
  }
}
if (failed) fail(`${failed} of ${declared.length} assertions failed`);
console.log(`\n${declared.length} of ${declared.length} mailbox-task assertions hold.`);
