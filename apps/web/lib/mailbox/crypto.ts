/**
 * Agent mailbox encryption (o-core#2069). Node's built-in crypto only — no dependency to audit.
 *
 * Each connected agent has an X25519 key pair. A message is SEALED to the receiving agent's public
 * key (ephemeral X25519 + HKDF-SHA256 + AES-256-GCM, with the message id, account, sender, receiver
 * and kind bound in as additional data), so sending needs no secret, only the receiver can open it,
 * and a row edited to look like a different message no longer opens. The receiver's private key is
 * stored WRAPPED under a key derived from each of the receiver's own tokens (access and refresh, so
 * a refresh can re-wrap it), and the tokens themselves are stored only as SHA-256 hashes. A database read therefore cannot open a message:
 * that takes the receiver's live token, which only the agent holds.
 *
 * Formats (all Buffers):
 *   wrapped private key  = salt(16) ‖ nonce(12) ‖ ciphertext(32) ‖ tag(16)   — 76 bytes
 *   sealed message       = { ephemeralPublicKey(32), nonce(12), ciphertext ‖ tag(16) }
 */
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
  type KeyObject,
} from 'node:crypto';

const WRAP_INFO = 'oriva-mailbox/wrap/v1';
const SEAL_INFO = 'oriva-mailbox/seal/v1';
const TOKEN_PREFIX = 'omb_';
const KEY_LEN = 32;
const NONCE_LEN = 12;
const TAG_LEN = 16;
const SALT_LEN = 16;

export const WRAPPED_KEY_LENGTH = SALT_LEN + NONCE_LEN + KEY_LEN + TAG_LEN;

export interface ConnectionKeys {
  /** Raw 32-byte X25519 public key — stored as is. */
  publicKey: Buffer;
  /** Raw 32-byte X25519 private key — never stored unwrapped. */
  privateKey: Buffer;
}

export interface SealedMessage {
  ephemeralPublicKey: Buffer;
  nonce: Buffer;
  /** AES-256-GCM ciphertext with its 16-byte tag appended. */
  ciphertext: Buffer;
}

const b64u = (buf: Buffer) => buf.toString('base64url');

function publicKeyObject(raw: Buffer): KeyObject {
  if (raw.length !== KEY_LEN) throw new Error('public key must be 32 bytes');
  return createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: b64u(raw) }, format: 'jwk' });
}

function privateKeyObject(rawPrivate: Buffer, rawPublic: Buffer): KeyObject {
  if (rawPrivate.length !== KEY_LEN) throw new Error('private key must be 32 bytes');
  return createPrivateKey({
    key: { kty: 'OKP', crv: 'X25519', d: b64u(rawPrivate), x: b64u(rawPublic) },
    format: 'jwk',
  });
}

function rawFromJwk(value: string | undefined): Buffer {
  if (!value) throw new Error('key export failed');
  return Buffer.from(value, 'base64url');
}

export function generateConnectionKeys(): ConnectionKeys {
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  const jwk = privateKey.export({ format: 'jwk' });
  return { publicKey: rawFromJwk(publicKey.export({ format: 'jwk' }).x), privateKey: rawFromJwk(jwk.d) };
}

/** A new bearer token (access or refresh): 256 random bits. */
export function newToken(): string {
  return TOKEN_PREFIX + b64u(randomBytes(32));
}

/** What the database stores in place of a token. */
export function hashToken(token: string): Buffer {
  return createHash('sha256').update(token, 'utf8').digest();
}

export function tokensMatch(token: string, storedHash: Buffer): boolean {
  const got = hashToken(token);
  return storedHash.length === got.length && timingSafeEqual(got, storedHash);
}

function wrapKey(token: string, salt: Buffer): Buffer {
  if (!token.startsWith(TOKEN_PREFIX) || token.length < TOKEN_PREFIX.length + 43) {
    throw new Error('not a mailbox token');
  }
  return Buffer.from(hkdfSync('sha256', Buffer.from(token, 'utf8'), salt, WRAP_INFO, KEY_LEN));
}

/** Encrypt a connection's private key under its access token, for storage. */
export function wrapPrivateKey(privateKey: Buffer, token: string): Buffer {
  if (privateKey.length !== KEY_LEN) throw new Error('private key must be 32 bytes');
  const salt = randomBytes(SALT_LEN);
  const nonce = randomBytes(NONCE_LEN);
  const cipher = createCipheriv('aes-256-gcm', wrapKey(token, salt), nonce);
  const body = Buffer.concat([cipher.update(privateKey), cipher.final()]);
  return Buffer.concat([salt, nonce, body, cipher.getAuthTag()]);
}

/** Recover a connection's private key with its access token. Throws on a wrong token. */
export function unwrapPrivateKey(wrapped: Buffer, token: string): Buffer {
  if (wrapped.length !== WRAPPED_KEY_LENGTH) throw new Error('wrapped key has the wrong length');
  const salt = wrapped.subarray(0, SALT_LEN);
  const nonce = wrapped.subarray(SALT_LEN, SALT_LEN + NONCE_LEN);
  const body = wrapped.subarray(SALT_LEN + NONCE_LEN, SALT_LEN + NONCE_LEN + KEY_LEN);
  const tag = wrapped.subarray(SALT_LEN + NONCE_LEN + KEY_LEN);
  const decipher = createDecipheriv('aes-256-gcm', wrapKey(token, salt), nonce, { authTagLength: TAG_LEN });
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]);
}

// A low-order public key (an all-zero shared secret) is refused by OpenSSL inside diffieHellman.
function sharedKey(secret: Buffer, ephemeralPublic: Buffer, recipientPublic: Buffer): Buffer {
  const salt = Buffer.concat([ephemeralPublic, recipientPublic]);
  return Buffer.from(hkdfSync('sha256', secret, salt, SEAL_INFO, KEY_LEN));
}

export const MESSAGE_KINDS = ['task', 'result', 'note'] as const;
export type MessageKind = (typeof MESSAGE_KINDS)[number];

export interface MessageEnvelope {
  messageId: string;
  userId: string;
  fromConnection: string;
  toConnection: string;
  kind: MessageKind;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * What a sealed message is bound to. Changing any of these on the stored row — moving it to another
 * account or agent, re-labelling a note as a task, swapping the sender — makes it fail to open.
 * Every field is fixed-format (four lower-case UUIDs and a kind from a closed set), so the joined
 * string is unambiguous.
 */
export function messageAad(e: MessageEnvelope): Buffer {
  for (const id of [e.messageId, e.userId, e.fromConnection, e.toConnection]) {
    if (!UUID.test(id)) throw new Error('envelope ids must be lower-case UUIDs');
  }
  if (!MESSAGE_KINDS.includes(e.kind)) throw new Error('unknown message kind');
  return Buffer.from(`v1|${e.messageId}|${e.userId}|${e.fromConnection}|${e.toConnection}|${e.kind}`, 'utf8');
}

/** Seal a message to a recipient's public key. Needs no secret. */
export function sealTo(recipientPublicKey: Buffer, plaintext: string, aad: Buffer): SealedMessage {
  const recipient = publicKeyObject(recipientPublicKey);
  const ephemeral = generateKeyPairSync('x25519');
  const ephemeralPublicKey = rawFromJwk(ephemeral.publicKey.export({ format: 'jwk' }).x);
  const secret = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: recipient });
  const nonce = randomBytes(NONCE_LEN);
  const cipher = createCipheriv('aes-256-gcm', sharedKey(secret, ephemeralPublicKey, recipientPublicKey), nonce);
  cipher.setAAD(aad);
  const body = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return { ephemeralPublicKey, nonce, ciphertext: Buffer.concat([body, cipher.getAuthTag()]) };
}

/** Open a sealed message with the recipient's key pair. Throws if anything was altered. */
export function openSealed(keys: ConnectionKeys, sealed: SealedMessage, aad: Buffer): string {
  if (sealed.nonce.length !== NONCE_LEN || sealed.ciphertext.length <= TAG_LEN) {
    throw new Error('sealed message is malformed');
  }
  const secret = diffieHellman({
    privateKey: privateKeyObject(keys.privateKey, keys.publicKey),
    publicKey: publicKeyObject(sealed.ephemeralPublicKey),
  });
  const decipher = createDecipheriv(
    'aes-256-gcm',
    sharedKey(secret, sealed.ephemeralPublicKey, keys.publicKey),
    sealed.nonce,
    { authTagLength: TAG_LEN }
  );
  decipher.setAAD(aad);
  decipher.setAuthTag(sealed.ciphertext.subarray(sealed.ciphertext.length - TAG_LEN));
  const body = sealed.ciphertext.subarray(0, sealed.ciphertext.length - TAG_LEN);
  return Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8');
}
