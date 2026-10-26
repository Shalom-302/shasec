import { NextRequest, NextResponse } from 'next/server';

// Private pages need a session cookie; the API still validates the token on
// every call (this is a UX gate, not the security boundary).
const PRIVATE = ['/dashboard', '/targets', '/scans', '/credits', '/settings', '/admin', '/operator'];
const AUTH_PAGES = ['/login', '/register'];
const ADMIN_LOGIN = '/admin/login';

export function middleware(req: NextRequest) {
  const { pathname, search } = req.nextUrl;
  const hasSession = !!req.cookies.get('kx_at')?.value;

  if (pathname === ADMIN_LOGIN) {
    if (!hasSession) return NextResponse.next();
    const url = req.nextUrl.clone();
    url.pathname = '/admin';
    url.search = '';
    return NextResponse.redirect(url);
  }
  if (PRIVATE.some(p => pathname === p || pathname.startsWith(`${p}/`)) && !hasSession) {
    const url = req.nextUrl.clone();
    url.pathname = pathname === '/admin' || pathname.startsWith('/admin/') ? ADMIN_LOGIN : '/login';
    url.search = `?next=${encodeURIComponent(pathname + search)}`;
    return NextResponse.redirect(url);
  }
  if (AUTH_PAGES.includes(pathname) && hasSession) {
    const url = req.nextUrl.clone();
    url.pathname = '/dashboard';
    url.search = '';
    return NextResponse.redirect(url);
  }
  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!api|_next|favicon.ico).*)'],
};
