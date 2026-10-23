import { NextRequest, NextResponse } from 'next/server';
import { ACCESS_COOKIE, apiFetch, clearSession, clientIp } from '@/lib/server/backend';

export async function POST(req: NextRequest) {
  const token = req.cookies.get(ACCESS_COOKIE)?.value;
  // Best effort: revoke server-side, then always drop the local session.
  if (token) await apiFetch('/auth/logout', { method: 'POST', token, ip: clientIp(req) }).catch(() => null);
  clearSession();
  return NextResponse.json({ ok: true });
}
