/**
 * @jest-environment node
 *
 * Agent mailbox encryption (o-core#2069): a message opens only for the agent it was sealed to,
 * only with that agent's live token, and only unaltered.
 */
export {};

import { createDecipheriv, hkdfSync } from 'node:crypto';
import {
  WRAPPED_KEY_LENGTH,
  generateConnectionKeys,
  hashToken,
  messageAad,
  newToken,
  openSealed,
  sealTo,
  tokensMatch,
  unwrapPrivateKey,
  wrapPrivateKey,
} from '../crypto';

const MARKER = 'MAILBOX-PLAINTEXT-MARKER-7f3a';
const envelope = {
  messageId: '11111111-1111-4111-8111-111111111111',
  userId: '22222222-2222-4222-8222-222222222222',
  fromConnection: '33333333-3333-4333-8333-333333333333',
  toConnection: '44444444-4444-4444-8444-444444444444',
  kind: 'task' as const,
};
const aad = messageAad(envelope);

describe('tokens', () => {
  it('are 256-bit, prefixed, and stored only as a hash', () => {
    const t = newToken();
    expect(t).toMatch(/^omb_[A-Za-z0-9_-]{43}$/);
    expect(hashToken(t)).toHaveLength(32);
    expect(hashToken(t).includes(Buffer.from(t.slice(4), 'base64url'))).toBe(false);
    expect(newToken()).not.toBe(t);
  });

  it('match only their own hash', () => {
    const t = newToken();
    expect(tokensMatch(t, hashToken(t))).toBe(true);
    expect(tokensMatch(newToken(), hashToken(t))).toBe(false);
    expect(tokensMatch(t, Buffer.alloc(31))).toBe(false);
  });
});

describe('wrapping a private key under a token', () => {
  it('round-trips with the same token', () => {
    const keys = generateConnectionKeys();
    const token = newToken();
    const wrapped = wrapPrivateKey(keys.privateKey, token);
    expect(wrapped).toHaveLength(WRAPPED_KEY_LENGTH);
    expect(unwrapPrivateKey(wrapped, token).equals(keys.privateKey)).toBe(true);
  });

  it('never contains the key itself, and differs each time', () => {
    const keys = generateConnectionKeys();
    const token = newToken();
    const a = wrapPrivateKey(keys.privateKey, token);
    const b = wrapPrivateKey(keys.privateKey, token);
    expect(a.includes(keys.privateKey)).toBe(false);
    expect(a.equals(b)).toBe(false);
  });

  it('refuses a different token', () => {
    const keys = generateConnectionKeys();
    const wrapped = wrapPrivateKey(keys.privateKey, newToken());
    expect(() => unwrapPrivateKey(wrapped, newToken())).toThrow();
  });

  it('refuses a tampered wrap', () => {
    const keys = generateConnectionKeys();
    const token = newToken();
    const wrapped = wrapPrivateKey(keys.privateKey, token);
    wrapped[40] ^= 0x01;
    expect(() => unwrapPrivateKey(wrapped, token)).toThrow();
  });

  // The property that matters: a database reader holds the wrapped key, its salt and the token's
  // HASH. Rebuilding the wrap key from those — the way an attacker with the rows would — must not
  // decrypt. (A regression that derived the wrap key from the hash would make this pass-through.)
  it('cannot be unwrapped from what the database stores (the hash in place of the token)', () => {
    const keys = generateConnectionKeys();
    const token = newToken();
    const wrapped = wrapPrivateKey(keys.privateKey, token);
    const salt = wrapped.subarray(0, 16);
    const nonce = wrapped.subarray(16, 28);
    const body = wrapped.subarray(28, 60);
    const tag = wrapped.subarray(60);
    const asAttacker = (ikm: Buffer) => {
      const key = Buffer.from(hkdfSync('sha256', ikm, salt, 'oriva-mailbox/wrap/v1', 32));
      const d = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
      d.setAuthTag(tag);
      return Buffer.concat([d.update(body), d.final()]);
    };
    expect(() => asAttacker(hashToken(token))).toThrow();
    expect(() => asAttacker(Buffer.from(hashToken(token).toString('hex'), 'utf8'))).toThrow();
    // Control: the same reconstruction with the real token does decrypt, so the test is not vacuous.
    expect(asAttacker(Buffer.from(token, 'utf8')).equals(keys.privateKey)).toBe(true);
  });

  it('refuses something that is not a mailbox token', () => {
    const keys = generateConnectionKeys();
    expect(() => wrapPrivateKey(keys.privateKey, 'not-a-token')).toThrow('not a mailbox token');
  });
});

describe('sealing a message to an agent', () => {
  it('opens for the recipient and contains no plaintext', () => {
    const recipient = generateConnectionKeys();
    const sealed = sealTo(recipient.publicKey, `Do the thing. ${MARKER}`, aad);
    expect(sealed.ciphertext.includes(Buffer.from(MARKER))).toBe(false);
    expect(sealed.ephemeralPublicKey).toHaveLength(32);
    expect(sealed.nonce).toHaveLength(12);
    expect(openSealed(recipient, sealed, aad)).toBe(`Do the thing. ${MARKER}`);
  });

  it('does not open for another agent', () => {
    const recipient = generateConnectionKeys();
    const other = generateConnectionKeys();
    const sealed = sealTo(recipient.publicKey, MARKER, aad);
    expect(() => openSealed(other, sealed, aad)).toThrow();
  });

  it.each([
    ['another account', { userId: '55555555-5555-4555-8555-555555555555' }],
    ['another message id', { messageId: '66666666-6666-4666-8666-666666666666' }],
    ['another sender', { fromConnection: '77777777-7777-4777-8777-777777777777' }],
    ['another receiver', { toConnection: '88888888-8888-4888-8888-888888888888' }],
    ['a different kind', { kind: 'note' as const }],
  ])('does not open when the row is edited to %s', (_label, change) => {
    const recipient = generateConnectionKeys();
    const sealed = sealTo(recipient.publicKey, MARKER, aad);
    expect(() => openSealed(recipient, sealed, messageAad({ ...envelope, ...change }))).toThrow();
  });

  it('refuses an envelope that is not fixed-format', () => {
    expect(() => messageAad({ ...envelope, fromConnection: 'X|Y' })).toThrow();
    expect(() => messageAad({ ...envelope, kind: 'admin' as never })).toThrow();
  });

  it('does not open when the ciphertext or its tag is altered', () => {
    const recipient = generateConnectionKeys();
    for (const index of [0, -1]) {
      const sealed = sealTo(recipient.publicKey, MARKER, aad);
      const at = index < 0 ? sealed.ciphertext.length + index : index;
      sealed.ciphertext[at] ^= 0x01;
      expect(() => openSealed(recipient, sealed, aad)).toThrow();
    }
  });

  it('refuses an all-zero (low-order) public key', () => {
    expect(() => sealTo(Buffer.alloc(32), MARKER, aad)).toThrow();
  });

  it('opens only through the full chain: token → wrapped key → message', () => {
    const recipient = generateConnectionKeys();
    const token = newToken();
    const stored = { publicKey: recipient.publicKey, wrapped: wrapPrivateKey(recipient.privateKey, token) };
    const sealed = sealTo(stored.publicKey, MARKER, aad);

    const opened = openSealed(
      { publicKey: stored.publicKey, privateKey: unwrapPrivateKey(stored.wrapped, token) },
      sealed,
      aad
    );
    expect(opened).toBe(MARKER);
    expect(() => unwrapPrivateKey(stored.wrapped, newToken())).toThrow();
  });

  it('handles a message at the 200 KB cap', () => {
    const recipient = generateConnectionKeys();
    const big = 'x'.repeat(204_800);
    const sealed = sealTo(recipient.publicKey, big, aad);
    expect(sealed.ciphertext.length).toBe(204_816);
    expect(openSealed(recipient, sealed, aad)).toBe(big);
  });
});
