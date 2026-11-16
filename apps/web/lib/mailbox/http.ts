/**
 * HTTP helpers shared by the agent mailbox routes (o-core#2069). The sign-in and discovery
 * endpoints are public and cookie-free, so any origin may call them (agents run in other apps);
 * the consent page and its Allow/Cancel endpoint are same-origin only and are not covered here.
 */
import { NextResponse } from 'next/server';

import { OAuthError } from './oauth';

export const PUBLIC_CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type, MCP-Protocol-Version, Mcp-Session-Id',
  'Access-Control-Expose-Headers': 'WWW-Authenticate, Mcp-Session-Id',
  'Access-Control-Max-Age': '600',
} as const;

export const preflight = () => new NextResponse(null, { status: 204, headers: PUBLIC_CORS });

export function json(body: unknown, status = 200, extra: Record<string, string> = {}) {
  return NextResponse.json(body, { status, headers: { ...PUBLIC_CORS, 'Cache-Control': 'no-store', ...extra } });
}

/** RFC 6749 §5.2 error shape. Unexpected errors are logged and never echoed. */
export function oauthErrorResponse(error: unknown, where: string) {
  if (error instanceof OAuthError) return json({ error: error.code, error_description: error.message }, error.status);
  console.error(`[mailbox] ${where} failed`, error instanceof Error ? error.message : error);
  return json({ error: 'server_error', error_description: 'Something went wrong. Try again.' }, 500);
}

/** OAuth token and revocation requests are form-encoded; accept JSON too. */
export async function readParams(request: Request): Promise<Record<string, string>> {
  const type = request.headers.get('content-type') ?? '';
  if (type.includes('application/json')) {
    const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
    return Object.fromEntries(Object.entries(body).filter(([, v]) => typeof v === 'string')) as Record<string, string>;
  }
  const form = new URLSearchParams(await request.text());
  return Object.fromEntries(form.entries());
}
