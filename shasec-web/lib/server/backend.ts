// Server-only helpers: talk to the Kortex/shaapi API and hold the session in
// httpOnly cookies. Nothing here is ever bundled for the browser (route handlers
// and middleware import it), so the access token never reaches client JS.
import { cookies } from 'next/headers';
import type { NextRequest } from 'next/server';

export const API_URL = (process.env.SHAAPI_URL || 'http://localhost:8000').replace(/\/$/, '');
const REFRESH_COOKIE = process.env.SHAAPI_REFRESH_COOKIE || 'monshaapi_refresh_token';
const SECURE = process.env.COOKIE_SECURE === 'true';

export const ACCESS_COOKIE = 'kx_at';
export const REFRESH_COOKIE_LOCAL = 'kx_rt';

/** Original client IP, forwarded so the API's per-IP rate limits (login,
 * register) apply per visitor rather than to this server as a whole. */
export function clientIp(req: NextRequest): string {
  const fwd = req.headers.get('x-forwarded-for');
  if (fwd) return fwd.split(',')[0].trim();
  return req.headers.get('x-real-ip') || req.ip || '0.0.0.0';
}

export function apiFetch(path: string, init: RequestInit & { token?: string; ip?: string; refresh?: string } = {}) {
  const { token, ip, refresh, headers, ...rest } = init;
  const h = new Headers(headers);
  if (token) h.set('Authorization', `Bearer ${token}`);
  if (ip) h.set('X-Forwarded-For', ip);
  if (refresh) h.set('Cookie', `${REFRESH_COOKIE}=${refresh}`);
  return fetch(`${API_URL}/api/v1${path}`, { ...rest, headers: h, cache: 'no-store', redirect: 'manual' });
}

/** Pull the API's refresh-token cookie out of its Set-Cookie headers. */
export function refreshFrom(res: Response): string | null {
  const all = typeof (res.headers as any).getSetCookie === 'function'
    ? (res.headers as any).getSetCookie() as string[]
    : [res.headers.get('set-cookie') || ''];
  for (const c of all) {
    const m = c.match(new RegExp(`(?:^|,\\s*)${REFRESH_COOKIE}=([^;]+)`));
    if (m) return m[1];
  }
  return null;
}

export function setSession(accessToken: string, expiresAt: string | undefined, refresh: string | null) {
  const jar = cookies();
  const exp = expiresAt ? new Date(expiresAt) : new Date(Date.now() + 24 * 3600 * 1000);
  const base = { httpOnly: true, sameSite: 'lax' as const, secure: SECURE, path: '/' };
  jar.set(ACCESS_COOKIE, accessToken, { ...base, expires: exp });
  if (refresh) jar.set(REFRESH_COOKIE_LOCAL, refresh, { ...base, maxAge: 7 * 24 * 3600 });
}

export function clearSession() {
  const jar = cookies();
  jar.delete(ACCESS_COOKIE);
  jar.delete(REFRESH_COOKIE_LOCAL);
}

/** Try to rotate the session (the API only rotates while the access token is
 * still accepted). Returns the new access token or null. */
export async function tryRefresh(token: string, refresh: string | undefined, ip: string): Promise<string | null> {
  if (!refresh) return null;
  try {
    const res = await apiFetch('/auth/token/new', { method: 'POST', token, refresh, ip });
    const j = await res.json().catch(() => null);
    const at = j?.data?.access_token;
    if (!res.ok || !at) return null;
    setSession(at, j.data.access_token_expire_time, refreshFrom(res) || refresh);
    return at;
  } catch {
    return null;
  }
}

/** Message safe to show to a visitor: the API's own msg, never a stack/infra detail. */
export function publicError(status: number, json: any): string {
  const v = json?.data?.errors?.[0];
  if (status === 422 && v) return v.msg || v.ctx?.error || 'Données invalides';
  if (json?.msg && status < 500) return String(json.msg);
  if (status >= 500) return 'Le service est momentanément indisponible. Réessayez dans un instant.';
  return `Erreur ${status}`;
}
