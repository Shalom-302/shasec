// Browser-side API client. Every call goes to the same-origin /api/k proxy; the
// session lives in httpOnly cookies the browser cannot read.

export class ApiError extends Error {
  constructor(public status: number, message: string, public data: any = null) {
    super(message);
  }
}

type QueryValue = string | number | undefined | null;
type Opts = { method?: string; body?: unknown; query?: Record<string, QueryValue | QueryValue[]> };

function qs(query?: Opts['query']) {
  if (!query) return '';
  const p = new URLSearchParams();
  // Arrays repeat the key (?pk=1&pk=2), which is how FastAPI reads list params.
  for (const [k, raw] of Object.entries(query)) {
    for (const v of Array.isArray(raw) ? raw : [raw]) if (v !== undefined && v !== null && v !== '') p.append(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : '';
}

function onExpired() {
  if (typeof window === 'undefined') return;
  const { pathname, search } = window.location;
  const login = pathname.startsWith('/admin') ? '/admin/login' : '/login';
  window.location.href = `${login}?expired=1&next=${encodeURIComponent(pathname + search)}`;
}

export async function api<T>(path: string, opts: Opts = {}): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`/api/k${path}${qs(opts.query)}`, {
      method: opts.method || 'GET',
      headers: opts.body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
  } catch {
    throw new ApiError(0, 'Connexion impossible. Vérifiez votre réseau.');
  }
  const json: any = await res.json().catch(() => null);
  if (res.status === 401) {
    onExpired();
    throw new ApiError(401, 'Session expirée, reconnectez-vous.');
  }
  if (!res.ok || (json && typeof json.code === 'number' && json.code >= 400)) {
    throw new ApiError(res.status, json?.msg || `Erreur ${res.status}`, json?.data ?? null);
  }
  return (json?.data ?? null) as T;
}

/** Auth calls go to dedicated routes that set/clear the session cookies.
 * Returns the parsed body so callers can detect `otp_required` on sign-up. */
export async function authCall(
  mode: 'login' | 'register' | 'logout',
  body?: { email: string; password: string; phone?: string },
): Promise<any> {
  const res = await fetch(`/api/auth/${mode}`, {
    method: 'POST',
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const json: any = await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, json?.msg || `Erreur ${res.status}`, json ?? null);
  return json;
}

/** Verify the WhatsApp sign-up code; on success the session cookie is set. */
export async function verifyOtp(email: string, code: string): Promise<void> {
  const res = await fetch('/api/auth/verify-otp', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, code }),
  });
  const json: any = await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, json?.msg || `Erreur ${res.status}`);
}

/** Ask for a new WhatsApp code. */
export async function resendOtp(email: string): Promise<void> {
  const res = await fetch('/api/auth/resend-otp', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  });
  const json: any = await res.json().catch(() => null);
  if (!res.ok) throw new ApiError(res.status, json?.msg || `Erreur ${res.status}`);
}

/** Download a binary through the proxy and hand it to the browser as a file. */
export async function download(path: string, fallbackName: string) {
  const res = await fetch(`/api/k${path}`);
  if (res.status === 401) { onExpired(); return; }
  if (!res.ok) {
    const json: any = await res.json().catch(() => null);
    throw new ApiError(res.status, json?.msg || `Erreur ${res.status}`, json?.data ?? null);
  }
  const blob = await res.blob();
  const cd = res.headers.get('content-disposition') || '';
  const name = /filename="?([^";]+)"?/.exec(cd)?.[1] || fallbackName;
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
