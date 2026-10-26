// Authenticated proxy: /api/k/<path> -> SHAAPI_URL/api/v1/<path>, with the
// Bearer token taken from the httpOnly session cookie. Only the product routes
// below are reachable; everything else (admin RBAC, logs, …) is refused here and,
// regardless, authorized again by the API itself.
import { NextRequest, NextResponse } from 'next/server';
import { ACCESS_COOKIE, REFRESH_COOKIE_LOCAL, apiFetch, clearSession, clientIp, publicError, tryRefresh } from '@/lib/server/backend';

const COLLECTIONS = new Set(['targets', 'scans']);
const ALLOWED = [/^auth\/me$/, /^targets(\/|$)/, /^scans(\/|$)/, /^credits(\/|$)/, /^notifications(\/|$)/, /^security\/proxy(\/|$)/, /^admin\/users(\/|$)/, /^admin\/overview$/, /^hermes\/chat$/];

async function forward(req: NextRequest, parts: string[]) {
  // Dot segments would be normalized by fetch and could escape the allowlist.
  if (parts.some(p => p === '.' || p === '..' || p === '')) {
    return NextResponse.json({ msg: 'Route non disponible' }, { status: 404 });
  }
  let path = parts.map(encodeURIComponent).join('/');
  if (!ALLOWED.some(re => re.test(path))) {
    return NextResponse.json({ msg: 'Route non disponible' }, { status: 404 });
  }
  // Next strips trailing slashes; the API's collection routes are "/targets/".
  if (COLLECTIONS.has(path)) path += '/';
  let token = req.cookies.get(ACCESS_COOKIE)?.value;
  if (!token) return NextResponse.json({ msg: 'Session expirée' }, { status: 401 });

  const ip = clientIp(req);
  const body = ['GET', 'HEAD'].includes(req.method) ? undefined : await req.text();
  const send = (t: string) => apiFetch(`/${path}${req.nextUrl.search}`, {
    method: req.method,
    headers: body !== undefined ? { 'Content-Type': req.headers.get('content-type') || 'application/json' } : undefined,
    body,
    token: t,
    ip,
  });

  let res: Response;
  try {
    res = await send(token);
    if (res.status === 401) {
      const fresh = await tryRefresh(token, req.cookies.get(REFRESH_COOKIE_LOCAL)?.value, ip);
      if (fresh) { token = fresh; res = await send(fresh); }
    }
  } catch {
    return NextResponse.json({ msg: 'API injoignable' }, { status: 502 });
  }

  if (res.status === 401) {
    clearSession();
    return NextResponse.json({ msg: 'Session expirée, reconnectez-vous.' }, { status: 401 });
  }

  const type = res.headers.get('content-type') || '';
  if (type.includes('application/json')) {
    const json = await res.json().catch(() => null);
    if (!res.ok) {
      // Keep the API's structured data (e.g. {target_id}, {cost}) but never a trace.
      return NextResponse.json({ msg: publicError(res.status, json), data: json?.data ?? null }, { status: res.status });
    }
    return NextResponse.json(json, { status: res.status });
  }
  // Binary (report download): stream through with its filename.
  const headers = new Headers({ 'Content-Type': type || 'application/octet-stream' });
  const cd = res.headers.get('content-disposition');
  if (cd) headers.set('Content-Disposition', cd);
  return new NextResponse(res.body, { status: res.status, headers });
}

type Ctx = { params: { path: string[] } };
export const GET = (req: NextRequest, { params }: Ctx) => forward(req, params.path);
export const POST = (req: NextRequest, { params }: Ctx) => forward(req, params.path);
export const PUT = (req: NextRequest, { params }: Ctx) => forward(req, params.path);
export const DELETE = (req: NextRequest, { params }: Ctx) => forward(req, params.path);
export const dynamic = 'force-dynamic';
