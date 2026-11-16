/**
 * The agent mailbox's sign-in (o-core#2069): a small OAuth 2.1 authorization server so Claude and
 * Grok Bot can "Connect" to an Oriva account with no key to copy.
 *
 * - Public clients only (no client secret), PKCE S256 required, dynamic client registration.
 * - Tokens are opaque random 256-bit values (crypto.ts newToken), stored only as SHA-256 hashes.
 * - On the code exchange the agent's X25519 key pair is created and its private half is wrapped
 *   under BOTH tokens; a refresh unwraps it with the refresh token and re-wraps it under the new
 *   pair (compare-and-swap, so a refresh token works once).
 * Pure logic over a MailboxStore, so it is testable without a database; routes wire it to HTTP.
 */
import { createHash, randomBytes } from 'node:crypto';

import { generateConnectionKeys, hashToken, newToken, unwrapPrivateKey, wrapPrivateKey } from './crypto';
import type { MailboxStore, Role } from './store';

export const ACCESS_TTL_SECONDS = 3600;
export const CODE_TTL_SECONDS = 300;
export const ROLES: readonly Role[] = ['dispatcher', 'worker'];

/** Same rule as mailbox.redirect_uris_safe in the database: https, or http on a loopback address. */
export function isSafeRedirectUri(uri: string): boolean {
  if (typeof uri !== 'string' || uri.length > 2000) return false;
  return /^https:\/\/[^/?#]+/.test(uri) || /^http:\/\/(127\.0\.0\.1|localhost|\[::1\])(:[0-9]+)?(\/|$)/.test(uri);
}

const VERIFIER = /^[A-Za-z0-9\-._~]{43,128}$/;

/** PKCE S256: the verifier hashes to the challenge sent at the start. */
export function pkceMatches(verifier: string, challenge: string): boolean {
  if (!VERIFIER.test(verifier) || typeof challenge !== 'string' || challenge.length !== 43) return false;
  return createHash('sha256').update(verifier, 'ascii').digest('base64url') === challenge;
}

export class OAuthError extends Error {
  constructor(
    readonly code: 'invalid_request' | 'invalid_client' | 'invalid_grant' | 'unsupported_grant_type' | 'invalid_client_metadata' | 'invalid_redirect_uri',
    message: string,
    readonly status = 400
  ) {
    super(message);
  }
}

export interface Registration {
  client_id: string;
  client_name: string;
  redirect_uris: string[];
  token_endpoint_auth_method: 'none';
  grant_types: string[];
  response_types: string[];
  client_id_issued_at: number;
}

/** RFC 7591 dynamic client registration for a public client. */
export async function registerClient(store: MailboxStore, body: unknown): Promise<Registration> {
  const meta = (body ?? {}) as Record<string, unknown>;
  const uris = meta.redirect_uris;
  if (!Array.isArray(uris) || uris.length < 1 || uris.length > 10) {
    throw new OAuthError('invalid_redirect_uri', 'redirect_uris must list 1 to 10 addresses');
  }
  if (!uris.every((u) => typeof u === 'string' && isSafeRedirectUri(u))) {
    throw new OAuthError('invalid_redirect_uri', 'each redirect_uri must be https, or http on a loopback address');
  }
  const rawName = typeof meta.client_name === 'string' ? meta.client_name.trim() : '';
  const name = (rawName || 'AI agent').slice(0, 100);
  const clientId = `mbc_${randomBytes(18).toString('base64url')}`;
  await store.registerClient(clientId, name, uris as string[]);
  return {
    client_id: clientId,
    client_name: name,
    redirect_uris: uris as string[],
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    client_id_issued_at: Math.floor(Date.now() / 1000),
  };
}

/** Apps whose return address proves who they are. Any other app is shown as unverified. */
export const VERIFIED_REDIRECT_HOSTS = ['claude.ai', 'claude.com'];

export interface AuthorizeRequest {
  clientId: string;
  clientName: string;
  redirectUri: string;
  redirectHost: string;
  /** The return address is a known app's own (claude.ai). */
  verified: boolean;
  /** The return address is on the owner's own computer (desktop apps such as Grok Bot). */
  local: boolean;
  codeChallenge: string;
  state: string | null;
}

/**
 * Check a sign-in request before showing the consent page. Problems with the client or its return
 * address are shown on the page, never redirected — an unregistered address must not receive
 * anything.
 */
export async function validateAuthorize(
  store: MailboxStore,
  params: Record<string, string | undefined>,
  resource: string
): Promise<AuthorizeRequest> {
  if (params.response_type !== 'code') throw new OAuthError('invalid_request', 'response_type must be "code"');
  const clientId = params.client_id ?? '';
  const client = clientId ? await store.client(clientId) : null;
  if (!client) throw new OAuthError('invalid_client', 'This app is not registered with Oriva.');
  const redirectUri = params.redirect_uri ?? '';
  if (!client.redirectUris.includes(redirectUri)) throw new OAuthError('invalid_redirect_uri', 'This return address is not registered for the app.');
  if (params.code_challenge_method !== 'S256' || !params.code_challenge || params.code_challenge.length !== 43) {
    throw new OAuthError('invalid_request', 'A PKCE S256 code_challenge is required.');
  }
  if (params.resource && params.resource.replace(/\/+$/, '') !== resource.replace(/\/+$/, '')) {
    throw new OAuthError('invalid_request', 'This sign-in is for a different service.');
  }
  if (params.state && params.state.length > 500) throw new OAuthError('invalid_request', 'state is too long');
  const url = new URL(redirectUri);
  return {
    clientId,
    clientName: client.clientName,
    redirectUri,
    redirectHost: url.host,
    verified: url.protocol === 'https:' && VERIFIED_REDIRECT_HOSTS.includes(url.hostname),
    local: url.protocol === 'http:',
    codeChallenge: params.code_challenge,
    state: params.state || null,
  };
}

/** The owner pressed Allow: issue a one-time code and say where to send the browser. `issuer` is
 * added to the response (RFC 9207) so a client talking to several servers can tell which answered. */
export async function approve(store: MailboxStore, userId: string, req: AuthorizeRequest, role: Role, issuer: string, name?: string): Promise<string> {
  if (!ROLES.includes(role)) throw new OAuthError('invalid_request', 'Choose what this agent does.');
  // The name the owner typed on the Connect page; none sent (an older page) keeps the app's own name.
  const agentName = name === undefined ? null : name.trim();
  if (agentName !== null && (agentName.length < 1 || agentName.length > 100)) {
    throw new OAuthError('invalid_request', 'Give the agent a name of 1 to 100 characters.');
  }
  const code = newToken();
  await store.createCode({
    codeHash: hashToken(code), clientId: req.clientId, userId, role, redirectUri: req.redirectUri,
    challenge: req.codeChallenge, ttlSeconds: CODE_TTL_SECONDS, agentName,
  });
  const url = new URL(req.redirectUri);
  url.searchParams.set('code', code);
  if (req.state) url.searchParams.set('state', req.state);
  url.searchParams.set('iss', issuer);
  return url.toString();
}

/** The owner pressed Cancel. */
export function deny(req: AuthorizeRequest, issuer: string): string {
  const url = new URL(req.redirectUri);
  url.searchParams.set('error', 'access_denied');
  if (req.state) url.searchParams.set('state', req.state);
  url.searchParams.set('iss', issuer);
  return url.toString();
}

export interface TokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token: string;
}

function tokenPair() {
  return { access: newToken(), refresh: newToken() };
}

/** grant_type=authorization_code */
export async function exchangeCode(
  store: MailboxStore,
  p: { code?: string; code_verifier?: string; client_id?: string; redirect_uri?: string }
): Promise<TokenResponse> {
  if (!p.code || !p.code_verifier || !p.client_id || !p.redirect_uri) throw new OAuthError('invalid_request', 'code, code_verifier, client_id and redirect_uri are required');
  const taken = await store.takeCode(hashToken(p.code));
  // Every mismatch reads the same, so a caller learns nothing about which part was wrong.
  if (!taken || taken.expired || taken.clientId !== p.client_id || taken.redirectUri !== p.redirect_uri || !pkceMatches(p.code_verifier, taken.codeChallenge)) {
    throw new OAuthError('invalid_grant', 'The sign-in code is invalid or has expired.');
  }
  const keys = generateConnectionKeys();
  const { access, refresh } = tokenPair();
  await store.connect({
    userId: taken.userId, clientId: taken.clientId, role: taken.role, agentName: taken.agentName, publicKey: keys.publicKey,
    wrapped: wrapPrivateKey(keys.privateKey, access), wrappedRefresh: wrapPrivateKey(keys.privateKey, refresh),
    accessHash: hashToken(access), refreshHash: hashToken(refresh), accessTtlSeconds: ACCESS_TTL_SECONDS,
  });
  return { access_token: access, token_type: 'Bearer', expires_in: ACCESS_TTL_SECONDS, refresh_token: refresh };
}

/** grant_type=refresh_token — one use per refresh token. */
export async function refreshTokens(store: MailboxStore, p: { refresh_token?: string; client_id?: string }): Promise<TokenResponse> {
  if (!p.refresh_token) throw new OAuthError('invalid_request', 'refresh_token is required');
  const oldHash = hashToken(p.refresh_token);
  const record = await store.byRefresh(oldHash);
  if (!record) {
    // A refresh token that was already used has been copied: stop the connection so no copy works.
    if (await store.refreshReused(oldHash)) {
      throw new OAuthError('invalid_grant', 'This refresh token was already used, so the connection was stopped for safety. Connect the agent again.');
    }
    throw new OAuthError('invalid_grant', 'The refresh token is invalid.');
  }
  if (p.client_id && p.client_id !== record.clientId) throw new OAuthError('invalid_grant', 'The refresh token is invalid.');
  if (record.expired) throw new OAuthError('invalid_grant', 'The refresh token expired after 30 days without use. Connect the agent again.');
  let privateKey: Buffer;
  try {
    privateKey = unwrapPrivateKey(record.wrappedRefresh, p.refresh_token);
  } catch {
    throw new OAuthError('invalid_grant', 'The refresh token is invalid.');
  }
  const { access, refresh } = tokenPair();
  const swapped = await store.rotate({
    oldRefreshHash: oldHash, wrapped: wrapPrivateKey(privateKey, access), wrappedRefresh: wrapPrivateKey(privateKey, refresh),
    accessHash: hashToken(access), refreshHash: hashToken(refresh), accessTtlSeconds: ACCESS_TTL_SECONDS,
  });
  if (!swapped) throw new OAuthError('invalid_grant', 'The refresh token was already used.');
  return { access_token: access, token_type: 'Bearer', expires_in: ACCESS_TTL_SECONDS, refresh_token: refresh };
}

/** RFC 7009: revoking either token stops the agent. Always succeeds, whatever the token. */
export async function revokeToken(store: MailboxStore, token: string | undefined): Promise<void> {
  if (token) await store.revoke(hashToken(token));
}

/** The address the MCP endpoint lives at, and what every discovery document names. */
export function mailboxOrigin(requestUrl: string): string {
  const configured = (process.env.ORIVA_MAILBOX_ORIGIN ?? '').trim();
  return (configured || new URL(requestUrl).origin).replace(/\/+$/, '');
}
export const resourceUrl = (origin: string) => `${origin}/api/mailbox/mcp`;

export function authorizationServerMetadata(origin: string) {
  return {
    issuer: origin,
    authorization_endpoint: `${origin}/oauth`,
    token_endpoint: `${origin}/api/mailbox/oauth/token`,
    registration_endpoint: `${origin}/api/mailbox/oauth/register`,
    revocation_endpoint: `${origin}/api/mailbox/oauth/revoke`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none'],
    revocation_endpoint_auth_methods_supported: ['none'],
    scopes_supported: ['mailbox'],
    authorization_response_iss_parameter_supported: true,
  };
}

export function protectedResourceMetadata(origin: string) {
  return {
    resource: resourceUrl(origin),
    authorization_servers: [origin],
    bearer_methods_supported: ['header'],
    scopes_supported: ['mailbox'],
    resource_name: 'Oriva agent mailbox',
  };
}
