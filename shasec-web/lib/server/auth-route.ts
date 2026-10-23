import { NextRequest, NextResponse } from 'next/server';
import { apiFetch, clientIp, publicError, refreshFrom, setSession } from './backend';

/** Shared body of /api/auth/login and /api/auth/register: call the API, keep
 * the tokens in httpOnly cookies, return only non-secret user info. */
export async function authenticate(req: NextRequest, mode: 'login' | 'register') {
  let body: { email?: string; password?: string };
  try { body = await req.json(); } catch { return NextResponse.json({ msg: 'Requête invalide' }, { status: 400 }); }
  const email = String(body.email || '').trim();
  const password = String(body.password || '');
  if (!email || !password) return NextResponse.json({ msg: 'Email et mot de passe requis' }, { status: 400 });

  const res = await apiFetch(`/auth/${mode}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
    ip: clientIp(req),
  }).catch(() => null);
  if (!res) return NextResponse.json({ msg: 'API injoignable' }, { status: 502 });

  const json = await res.json().catch(() => null);
  const token = json?.data?.access_token;
  if (!res.ok || !token) {
    const status = res.status >= 400 ? res.status : 400;
    return NextResponse.json({ msg: publicError(status, json) }, { status });
  }
  setSession(token, json.data.access_token_expire_time, refreshFrom(res));
  return NextResponse.json({ ok: true });
}
