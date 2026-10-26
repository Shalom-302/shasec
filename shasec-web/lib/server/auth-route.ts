import { NextRequest, NextResponse } from 'next/server';
import { apiFetch, clientIp, publicError, refreshFrom, setSession } from './backend';

/** Shared body of /api/auth/login and /api/auth/register: call the API, keep
 * the tokens in httpOnly cookies, return only non-secret user info.
 *
 * Sign-up with WhatsApp OTP: the API answers 200 with `{otp_required:true}` and
 * NO token — the account is created but unverified. We pass that through so the
 * UI shows the code screen; no session is set until /api/auth/verify-otp. */
export async function authenticate(req: NextRequest, mode: 'login' | 'register') {
  let body: { email?: string; password?: string; phone?: string };
  try { body = await req.json(); } catch { return NextResponse.json({ msg: 'Requête invalide' }, { status: 400 }); }
  const email = String(body.email || '').trim();
  const password = String(body.password || '');
  const phone = String(body.phone || '').trim();
  if (!email || !password) return NextResponse.json({ msg: 'Email et mot de passe requis' }, { status: 400 });

  const payload: Record<string, string> = { email, password };
  if (mode === 'register' && phone) payload.phone = phone;

  const res = await apiFetch(`/auth/${mode}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
    ip: clientIp(req),
  }).catch(() => null);
  if (!res) return NextResponse.json({ msg: 'API injoignable' }, { status: 502 });

  const json = await res.json().catch(() => null);

  // Registration that triggered an OTP: no token, account pending verification.
  if (res.ok && json?.data?.otp_required) {
    return NextResponse.json({ otp_required: true, email: json.data.email || email });
  }

  const token = json?.data?.access_token;
  if (!res.ok || !token) {
    const status = res.status >= 400 ? res.status : 400;
    // Surface the OTP-required login case so the client can route to the code screen.
    const msg = publicError(status, json);
    const otp = typeof json?.msg === 'string' && json.msg.includes('OTP_REQUIRED');
    return NextResponse.json({ msg, otp_required: otp || undefined, email: otp ? email : undefined }, { status });
  }
  setSession(token, json.data.access_token_expire_time, refreshFrom(res));
  return NextResponse.json({ ok: true });
}

/** Verify the WhatsApp code and open the session (same cookie handling as login). */
export async function verifyOtp(req: NextRequest) {
  let body: { email?: string; code?: string };
  try { body = await req.json(); } catch { return NextResponse.json({ msg: 'Requête invalide' }, { status: 400 }); }
  const email = String(body.email || '').trim();
  const code = String(body.code || '').trim();
  if (!email || !code) return NextResponse.json({ msg: 'Email et code requis' }, { status: 400 });

  const res = await apiFetch('/auth/verify-otp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, code }),
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

/** Ask the API to resend the WhatsApp code. No session involved. */
export async function resendOtp(req: NextRequest) {
  let body: { email?: string };
  try { body = await req.json(); } catch { return NextResponse.json({ msg: 'Requête invalide' }, { status: 400 }); }
  const email = String(body.email || '').trim();
  if (!email) return NextResponse.json({ msg: 'Email requis' }, { status: 400 });

  const res = await apiFetch('/auth/resend-otp', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
    ip: clientIp(req),
  }).catch(() => null);
  if (!res) return NextResponse.json({ msg: 'API injoignable' }, { status: 502 });
  const json = await res.json().catch(() => null);
  if (!res.ok) return NextResponse.json({ msg: publicError(res.status, json) }, { status: res.status });
  return NextResponse.json({ ok: true });
}
