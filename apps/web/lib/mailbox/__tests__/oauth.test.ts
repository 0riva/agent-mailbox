/**
 * @jest-environment node
 *
 * Agent mailbox sign-in (o-core#2069): Connect with no key to copy — public clients, PKCE S256,
 * codes that work once, refresh tokens that work once and carry the agent's key forward.
 */
export {};

import { createHash, randomBytes } from 'node:crypto';

import { hashToken, unwrapPrivateKey } from '../crypto';
import {
  OAuthError,
  approve,
  authorizationServerMetadata,
  deny,
  exchangeCode,
  isSafeRedirectUri,
  pkceMatches,
  protectedResourceMetadata,
  refreshTokens,
  registerClient,
  revokeToken,
  validateAuthorize,
} from '../oauth';
import { memoryStore } from './helpers/memoryStore';

const ORIGIN = 'https://oriva.io';
const RESOURCE = `${ORIGIN}/api/mailbox/mcp`;
const USER = '02069000-0000-4000-8000-00000000000a';
const REDIRECT = 'https://claude.ai/api/mcp/auth_callback';

function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
}

async function signedUp() {
  const m = memoryStore();
  const reg = await registerClient(m.store, { client_name: 'Claude', redirect_uris: [REDIRECT] });
  return { ...m, reg };
}

async function connected(role: 'dispatcher' | 'worker' = 'dispatcher') {
  const s = await signedUp();
  const { verifier, challenge } = pkce();
  const req = await validateAuthorize(
    s.store,
    { response_type: 'code', client_id: s.reg.client_id, redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: 'S256', state: 'st-1', resource: RESOURCE },
    RESOURCE
  );
  const back = new URL(await approve(s.store, USER, req, role, ORIGIN));
  const tokens = await exchangeCode(s.store, { code: back.searchParams.get('code')!, code_verifier: verifier, client_id: s.reg.client_id, redirect_uri: REDIRECT });
  return { ...s, req, back, tokens, verifier };
}

const rejects = async (p: Promise<unknown>, code: string) => {
  await expect(p).rejects.toBeInstanceOf(OAuthError);
  await expect(p).rejects.toMatchObject({ code });
};

describe('return addresses', () => {
  it.each([
    ['https://claude.ai/api/mcp/auth_callback', true],
    ['http://127.0.0.1:18787/callback', true],
    ['http://localhost:8787/cb', true],
    ['http://[::1]/cb', true],
    ['http://evil.example/cb', false],
    ['http://localhost.evil.example/cb', false],
    ['javascript:alert(1)', false],
    ['https://', false],
  ])('%s → %s', (uri, ok) => {
    expect(isSafeRedirectUri(uri)).toBe(ok);
  });
});

describe('PKCE', () => {
  it('accepts only the verifier that hashes to the challenge', () => {
    const { verifier, challenge } = pkce();
    expect(pkceMatches(verifier, challenge)).toBe(true);
    expect(pkceMatches(pkce().verifier, challenge)).toBe(false);
    expect(pkceMatches('short', challenge)).toBe(false);
  });
});

describe('registration', () => {
  it('registers a public client and names it', async () => {
    const { reg } = await signedUp();
    expect(reg.client_id).toMatch(/^mbc_/);
    expect(reg.client_name).toBe('Claude');
    expect(reg.token_endpoint_auth_method).toBe('none');
  });

  it('refuses an unsafe return address', async () => {
    const m = memoryStore();
    await rejects(registerClient(m.store, { client_name: 'x', redirect_uris: ['http://evil.example/cb'] }), 'invalid_redirect_uri');
    await rejects(registerClient(m.store, { redirect_uris: [] }), 'invalid_redirect_uri');
  });
});

describe('the consent request', () => {
  it('refuses an unknown client, an unregistered return address, a missing PKCE, or another service', async () => {
    const s = await signedUp();
    const { challenge } = pkce();
    const base = { response_type: 'code', client_id: s.reg.client_id, redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: 'S256' };
    await rejects(validateAuthorize(s.store, { ...base, client_id: 'mbc_nope' }, RESOURCE), 'invalid_client');
    await rejects(validateAuthorize(s.store, { ...base, redirect_uri: 'https://other.example/cb' }, RESOURCE), 'invalid_redirect_uri');
    await rejects(validateAuthorize(s.store, { ...base, code_challenge_method: 'plain' }, RESOURCE), 'invalid_request');
    await rejects(validateAuthorize(s.store, { ...base, resource: 'https://elsewhere.example/mcp' }, RESOURCE), 'invalid_request');
  });

  it('shows the return host so a fake "Claude" is visible', async () => {
    const s = await signedUp();
    const req = await validateAuthorize(s.store, { response_type: 'code', client_id: s.reg.client_id, redirect_uri: REDIRECT, code_challenge: pkce().challenge, code_challenge_method: 'S256' }, RESOURCE);
    expect(req.redirectHost).toBe('claude.ai');
  });

  it('marks only a known app\'s own return address as verified, and a loopback one as local', async () => {
    const m = memoryStore();
    const reg = await registerClient(m.store, { client_name: 'Claude', redirect_uris: [REDIRECT, 'https://claude.ai.evil.example/cb', 'http://127.0.0.1:18787/cb'] });
    const check = (redirect_uri: string) =>
      validateAuthorize(m.store, { response_type: 'code', client_id: reg.client_id, redirect_uri, code_challenge: pkce().challenge, code_challenge_method: 'S256' }, RESOURCE);
    expect(await check(REDIRECT)).toMatchObject({ verified: true, local: false });
    expect(await check('https://claude.ai.evil.example/cb')).toMatchObject({ verified: false, local: false });
    expect(await check('http://127.0.0.1:18787/cb')).toMatchObject({ verified: false, local: true });
  });

  it('refuses an over-long state rather than dropping it', async () => {
    const s = await signedUp();
    await rejects(
      validateAuthorize(s.store, { response_type: 'code', client_id: s.reg.client_id, redirect_uri: REDIRECT, code_challenge: pkce().challenge, code_challenge_method: 'S256', state: 'x'.repeat(501) }, RESOURCE),
      'invalid_request'
    );
  });

  it('sends Cancel back as access_denied with the state', async () => {
    const s = await signedUp();
    const req = await validateAuthorize(s.store, { response_type: 'code', client_id: s.reg.client_id, redirect_uri: REDIRECT, code_challenge: pkce().challenge, code_challenge_method: 'S256', state: 'abc' }, RESOURCE);
    const url = new URL(deny(req, ORIGIN));
    expect(url.searchParams.get('error')).toBe('access_denied');
    expect(url.searchParams.get('state')).toBe('abc');
    expect(url.searchParams.get('iss')).toBe(ORIGIN);
  });
});

describe('Connect: code → tokens', () => {
  it('returns the code and state to the registered address, then issues a token pair', async () => {
    const { back, tokens } = await connected();
    expect(`${back.origin}${back.pathname}`).toBe(REDIRECT);
    expect(back.searchParams.get('state')).toBe('st-1');
    expect(back.searchParams.get('iss')).toBe(ORIGIN);
    expect(tokens.access_token).toMatch(/^omb_/);
    expect(tokens.refresh_token).toMatch(/^omb_/);
    expect(tokens.token_type).toBe('Bearer');
  });

  it('stores only hashes, and the private key wrapped under BOTH tokens', async () => {
    const { conns, tokens } = await connected();
    const c = [...conns.values()][0];
    expect(c.accessHash.equals(hashToken(tokens.access_token))).toBe(true);
    expect(c.refreshHash.equals(hashToken(tokens.refresh_token))).toBe(true);
    const viaAccess = unwrapPrivateKey(c.wrapped, tokens.access_token);
    expect(unwrapPrivateKey(c.wrappedRefresh, tokens.refresh_token).equals(viaAccess)).toBe(true);
  });

  it('names the agent as the owner chose on the Connect page, or as the app did when no name came', async () => {
    const s = await signedUp();
    const run = async (name?: string) => {
      const { verifier, challenge } = pkce();
      const req = await validateAuthorize(
        s.store,
        { response_type: 'code', client_id: s.reg.client_id, redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: 'S256', resource: RESOURCE },
        RESOURCE
      );
      const code = new URL(await approve(s.store, USER, req, 'worker', ORIGIN, name)).searchParams.get('code')!;
      await exchangeCode(s.store, { code, code_verifier: verifier, client_id: s.reg.client_id, redirect_uri: REDIRECT });
    };
    await run('  Grok Bot ');
    await run();
    expect([...s.conns.values()].map((c) => c.agentName)).toEqual(['Grok Bot', 'Claude']);
  });

  it('refuses a blank or over-long name', async () => {
    const s = await signedUp();
    const { challenge } = pkce();
    const req = await validateAuthorize(
      s.store,
      { response_type: 'code', client_id: s.reg.client_id, redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: 'S256', resource: RESOURCE },
      RESOURCE
    );
    await rejects(approve(s.store, USER, req, 'worker', ORIGIN, '   '), 'invalid_request');
    await rejects(approve(s.store, USER, req, 'worker', ORIGIN, 'x'.repeat(101)), 'invalid_request');
  });

  it('records the role the owner chose', async () => {
    const { conns } = await connected('worker');
    expect([...conns.values()][0].role).toBe('worker');
  });

  it('a code works once', async () => {
    const s = await signedUp();
    const { verifier, challenge } = pkce();
    const req = await validateAuthorize(s.store, { response_type: 'code', client_id: s.reg.client_id, redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: 'S256' }, RESOURCE);
    const code = new URL(await approve(s.store, USER, req, 'worker', ORIGIN)).searchParams.get('code')!;
    const args = { code, code_verifier: verifier, client_id: s.reg.client_id, redirect_uri: REDIRECT };
    await exchangeCode(s.store, args);
    await rejects(exchangeCode(s.store, args), 'invalid_grant');
  });

  it.each([
    ['a wrong verifier', { code_verifier: 'x'.repeat(43) }],
    ['another client', { client_id: 'mbc_other' }],
    ['another return address', { redirect_uri: 'https://claude.ai/other' }],
  ])('refuses %s (and the code is then spent)', async (_label, change) => {
    const s = await signedUp();
    const { verifier, challenge } = pkce();
    const req = await validateAuthorize(s.store, { response_type: 'code', client_id: s.reg.client_id, redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: 'S256' }, RESOURCE);
    const code = new URL(await approve(s.store, USER, req, 'worker', ORIGIN)).searchParams.get('code')!;
    await rejects(exchangeCode(s.store, { code, code_verifier: verifier, client_id: s.reg.client_id, redirect_uri: REDIRECT, ...change }), 'invalid_grant');
    await rejects(exchangeCode(s.store, { code, code_verifier: verifier, client_id: s.reg.client_id, redirect_uri: REDIRECT }), 'invalid_grant');
  });

  it('refuses an expired code', async () => {
    const s = await signedUp();
    const { verifier, challenge } = pkce();
    const req = await validateAuthorize(s.store, { response_type: 'code', client_id: s.reg.client_id, redirect_uri: REDIRECT, code_challenge: challenge, code_challenge_method: 'S256' }, RESOURCE);
    const code = new URL(await approve(s.store, USER, req, 'worker', ORIGIN)).searchParams.get('code')!;
    const t0 = Date.now();
    s.setNow(() => t0 + 301_000);
    await rejects(exchangeCode(s.store, { code, code_verifier: verifier, client_id: s.reg.client_id, redirect_uri: REDIRECT }), 'invalid_grant');
  });
});

describe('refresh', () => {
  it('issues a new pair, carries the same key forward, and retires the old tokens', async () => {
    const { store, conns, tokens, reg } = await connected();
    const before = unwrapPrivateKey([...conns.values()][0].wrapped, tokens.access_token);
    const next = await refreshTokens(store, { refresh_token: tokens.refresh_token, client_id: reg.client_id });
    const c = [...conns.values()][0];
    expect(unwrapPrivateKey(c.wrapped, next.access_token).equals(before)).toBe(true);
    expect(unwrapPrivateKey(c.wrappedRefresh, next.refresh_token).equals(before)).toBe(true);
    expect(await store.byAccess(hashToken(tokens.access_token))).toBeNull();
    expect(await store.byAccess(hashToken(next.access_token))).not.toBeNull();
  });

  it('a refresh token works once', async () => {
    const { store, tokens } = await connected();
    await refreshTokens(store, { refresh_token: tokens.refresh_token });
    await rejects(refreshTokens(store, { refresh_token: tokens.refresh_token }), 'invalid_grant');
  });

  it('a reused refresh token stops the connection, so neither copy works', async () => {
    const { store, tokens } = await connected();
    const next = await refreshTokens(store, { refresh_token: tokens.refresh_token });
    await rejects(refreshTokens(store, { refresh_token: tokens.refresh_token }), 'invalid_grant');
    expect(await store.byAccess(hashToken(next.access_token))).toBeNull();
    await rejects(refreshTokens(store, { refresh_token: next.refresh_token }), 'invalid_grant');
  });

  it('refuses a refresh token unused for 30 days', async () => {
    const { store, tokens, setNow } = await connected();
    const t0 = Date.now();
    setNow(() => t0 + 31 * 86_400_000);
    await rejects(refreshTokens(store, { refresh_token: tokens.refresh_token }), 'invalid_grant');
  });

  it('refuses another client\'s refresh token', async () => {
    const { store, tokens } = await connected();
    await rejects(refreshTokens(store, { refresh_token: tokens.refresh_token, client_id: 'mbc_other' }), 'invalid_grant');
  });
});

describe('revocation', () => {
  it('revoking either token stops the agent', async () => {
    const { store, tokens } = await connected();
    await revokeToken(store, tokens.refresh_token);
    expect(await store.byAccess(hashToken(tokens.access_token))).toBeNull();
    await rejects(refreshTokens(store, { refresh_token: tokens.refresh_token }), 'invalid_grant');
  });
});

describe('discovery documents', () => {
  it('point an agent from the resource to the sign-in endpoints', () => {
    const pr = protectedResourceMetadata(ORIGIN);
    expect(pr.resource).toBe(RESOURCE);
    expect(pr.authorization_servers).toEqual([ORIGIN]);
    const as = authorizationServerMetadata(ORIGIN);
    expect(as.authorization_endpoint).toBe(`${ORIGIN}/oauth`);
    expect(as.code_challenge_methods_supported).toEqual(['S256']);
    expect(as.token_endpoint_auth_methods_supported).toEqual(['none']);
    expect(as.authorization_response_iss_parameter_supported).toBe(true);
  });
});
