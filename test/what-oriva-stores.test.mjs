// What Oriva stores for a message, and what it takes to read it.
//
// Run:  node --test test/          (Node 22.18 or later; no install, no network, no database)
//
// It uses the real encryption code from apps/web/lib/mailbox/crypto.ts, unchanged. It plays both
// sides: an agent connects (gets a key pair and a token), another agent sends it a message, and we
// keep exactly what Oriva's database keeps — the agent's public key, its private key WRAPPED under
// its token, a hash of the token, and the sealed message. Then we check that those stored values
// alone cannot open the message, and that the agent's own token can.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateConnectionKeys,
  hashToken,
  messageAad,
  newToken,
  openSealed,
  sealTo,
  unwrapPrivateKey,
  wrapPrivateKey,
} from '../apps/web/lib/mailbox/crypto.ts';

const SECRET = 'Draft three post ideas for Monday — PRIVATE-MARKER-41c9';
const envelope = {
  messageId: '11111111-1111-4111-8111-111111111111',
  userId: '22222222-2222-4222-8222-222222222222',
  fromConnection: '33333333-3333-4333-8333-333333333333',
  toConnection: '44444444-4444-4444-8444-444444444444',
  kind: 'task',
};

// The receiving agent connects. Only the agent keeps `token`.
const keys = generateConnectionKeys();
const token = newToken();

// What Oriva's database holds after the agent connects and a message is sent to it.
const stored = {
  publicKey: keys.publicKey,
  wrappedPrivateKey: wrapPrivateKey(keys.privateKey, token),
  tokenHash: hashToken(token),
  message: sealTo(keys.publicKey, SECRET, messageAad(envelope)),
};
const storedBytes = Buffer.concat([
  stored.publicKey,
  stored.wrappedPrivateKey,
  stored.tokenHash,
  stored.message.ephemeralPublicKey,
  stored.message.nonce,
  stored.message.ciphertext,
]);

test('the stored values do not contain the message, in any common encoding', () => {
  for (const encoding of ['utf8', 'hex', 'base64', 'base64url']) {
    assert.ok(!storedBytes.toString(encoding).includes(Buffer.from('PRIVATE-MARKER-41c9').toString(encoding)), encoding);
  }
  assert.ok(!storedBytes.includes(Buffer.from('PRIVATE-MARKER-41c9')));
});

test('the stored values do not contain the private key or the token', () => {
  assert.ok(!storedBytes.includes(keys.privateKey));
  assert.ok(!storedBytes.includes(Buffer.from(token)));
});

test('the stored token hash cannot stand in for the token', () => {
  for (const guess of [stored.tokenHash.toString('hex'), stored.tokenHash.toString('base64url'), stored.tokenHash.toString('utf8')]) {
    assert.throws(() => unwrapPrivateKey(stored.wrappedPrivateKey, guess));
  }
});

test('a different token cannot unwrap the key', () => {
  assert.throws(() => unwrapPrivateKey(stored.wrappedPrivateKey, newToken()));
});

test('a different agent\'s key cannot open the message', () => {
  assert.throws(() => openSealed(generateConnectionKeys(), stored.message, messageAad(envelope)));
});

test('the receiving agent, with its own token, opens the message', () => {
  const privateKey = unwrapPrivateKey(stored.wrappedPrivateKey, token);
  const text = openSealed({ publicKey: stored.publicKey, privateKey }, stored.message, messageAad(envelope));
  assert.equal(text, SECRET);
});

test('a stored message moved to another account, agent or kind no longer opens', () => {
  const privateKey = unwrapPrivateKey(stored.wrappedPrivateKey, token);
  const owner = { publicKey: stored.publicKey, privateKey };
  for (const change of [
    { userId: '55555555-5555-4555-8555-555555555555' },
    { fromConnection: '66666666-6666-4666-8666-666666666666' },
    { kind: 'note' },
  ]) {
    assert.throws(() => openSealed(owner, stored.message, messageAad({ ...envelope, ...change })), JSON.stringify(change));
  }
});

test('a stored message altered by one bit no longer opens', () => {
  const privateKey = unwrapPrivateKey(stored.wrappedPrivateKey, token);
  const altered = { ...stored.message, ciphertext: Buffer.from(stored.message.ciphertext) };
  altered.ciphertext[0] ^= 1;
  assert.throws(() => openSealed({ publicKey: stored.publicKey, privateKey }, altered, messageAad(envelope)));
});
