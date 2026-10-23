'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useState } from 'react';
import { authCall } from '@/lib/api';
import { useSession } from './SessionProvider';

const NAV = [
  { href: '/dashboard', label: 'Dashboard' },
  { href: '/targets', label: 'Mes applications' },
  { href: '/scans', label: 'Scans' },
  { href: '/credits', label: 'Crédits & offres' },
  { href: '/settings', label: 'Compte' },
];
const ADMIN_NAV = [
  { href: '/admin', label: 'Administration' },
  { href: '/operator', label: 'Console opérateur' },
];

function CreditBadge() {
  const { balance, isAdmin } = useSession();
  if (!balance) return null;
  if (isAdmin) return <span className="rounded-full border border-kx-accent px-3 py-1 text-xs text-blue-200">Opérateur · illimité</span>;
  return (
    <Link href="/credits" className="rounded-full border border-kx-border bg-kx-panel2 px-3 py-1 text-xs hover:border-kx-accent">
      <b className="text-kx-text">{balance.credits}</b> <span className="text-kx-muted">crédit{balance.credits > 1 ? 's' : ''}</span>
      {balance.free_scans > 0 && (
        <span className="text-kx-muted"> · {balance.free_scans} scan{balance.free_scans > 1 ? 's' : ''} gratuit{balance.free_scans > 1 ? 's' : ''}</span>
      )}
    </Link>
  );
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const path = usePathname();
  const { user, isAdmin } = useSession();
  const [open, setOpen] = useState(false);
  const items = isAdmin ? [...NAV, ...ADMIN_NAV] : NAV;

  const logout = async () => {
    await authCall('logout').catch(() => null);
    window.location.href = '/login';
  };

  const nav = (
    <nav className="flex flex-col gap-1" aria-label="Navigation principale">
      {items.map(i => {
        const active = path === i.href || path.startsWith(`${i.href}/`);
        return (
          <Link
            key={i.href}
            href={i.href}
            onClick={() => setOpen(false)}
            aria-current={active ? 'page' : undefined}
            className={`rounded-lg px-3 py-2 text-sm ${active ? 'bg-kx-panel2 font-semibold text-kx-text' : 'text-kx-muted hover:bg-kx-panel2/60 hover:text-kx-text'}`}
          >
            {i.label}
          </Link>
        );
      })}
    </nav>
  );

  return (
    <div className="min-h-screen lg:flex">
      <aside className="hidden w-60 shrink-0 border-r border-kx-border bg-kx-panel px-4 py-5 lg:flex lg:flex-col">
        <Link href="/dashboard" className="mb-6 block px-3 text-lg font-bold tracking-tight">
          Kortex <span className="text-kx-accent">Security</span>
        </Link>
        {nav}
        <div className="mt-auto border-t border-kx-border px-3 pt-4 text-xs text-kx-muted">
          <p className="truncate" title={user?.email}>{user?.email}</p>
          <button onClick={logout} className="mt-2 text-kx-text hover:underline">Se déconnecter</button>
        </div>
      </aside>

      <div className="min-w-0 flex-1">
        <header className="sticky top-0 z-20 flex items-center justify-between gap-3 border-b border-kx-border bg-kx-bg/90 px-4 py-3 backdrop-blur sm:px-6">
          <div className="flex items-center gap-3 lg:hidden">
            <button className="btn-ghost px-3 py-1.5" onClick={() => setOpen(o => !o)} aria-expanded={open} aria-controls="mobile-nav">
              Menu
            </button>
            <span className="font-bold">Kortex <span className="text-kx-accent">Security</span></span>
          </div>
          <div className="ml-auto flex items-center gap-3">
            <CreditBadge />
          </div>
        </header>
        {open && (
          <div id="mobile-nav" className="border-b border-kx-border bg-kx-panel px-4 py-3 lg:hidden">
            {nav}
            <button onClick={logout} className="mt-2 px-3 text-sm text-kx-muted hover:text-kx-text">Se déconnecter</button>
          </div>
        )}
        <main className="mx-auto max-w-6xl px-4 py-6 sm:px-6 sm:py-8">{children}</main>
      </div>
    </div>
  );
}
