'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useState } from 'react';
import { authCall } from '@/lib/api';
import { IconCoins, IconGlobe, IconHome, IconLogout, IconMenu, IconPlus, IconRadar, IconShield, IconTerminal, IconUser, Logo } from './icons';
import { ActiveScans } from './ActiveScans';
import { NotificationBell } from './NotificationBell';
import { useSession } from './SessionProvider';

const NAV = [
  { href: '/dashboard', label: 'Vue d’ensemble', icon: IconHome },
  { href: '/targets', label: 'Mes applications', icon: IconGlobe },
  { href: '/scans', label: 'Scans', icon: IconRadar },
  { href: '/credits', label: 'Crédits & offres', icon: IconCoins },
  { href: '/settings', label: 'Compte', icon: IconUser },
];
const ADMIN_NAV = [
  { href: '/admin/requests', label: 'Demandes d’audit', icon: IconShield },
  { href: '/admin/users', label: 'Utilisateurs', icon: IconUser },
  { href: '/admin', label: 'Administration', icon: IconShield },
  { href: '/operator', label: 'Console opérateur', icon: IconTerminal },
];

function CreditPill() {
  const { balance, isAdmin } = useSession();
  if (!balance) return null;
  if (isAdmin) {
    return <span className="rounded-full bg-black px-3.5 py-1.5 text-xs font-medium text-white">Opérateur · illimité</span>;
  }
  return (
    <Link href="/credits" className="inline-flex items-center gap-2 rounded-full border border-kx-border bg-white px-3.5 py-1.5 text-xs shadow-sm transition hover:border-black/30">
      <IconCoins className="h-4 w-4 text-kx-muted" />
      <b className="text-kx-text">{balance.credits}</b>
      <span className="text-kx-muted">crédit{balance.credits > 1 ? 's' : ''}</span>
      {balance.free_scans > 0 && (
        <span className="rounded-full bg-kx-tealSoft px-2 py-0.5 font-medium text-teal-900">
          {balance.free_scans} gratuit{balance.free_scans > 1 ? 's' : ''}
        </span>
      )}
    </Link>
  );
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const path = usePathname();
  const { user, isAdmin } = useSession();
  const [open, setOpen] = useState(false);

  const logout = async () => {
    await authCall('logout').catch(() => null);
    window.location.href = '/login';
  };

  const link = (i: (typeof NAV)[number]) => {
    const active = path === i.href || (i.href !== '/admin' && path.startsWith(`${i.href}/`));
    const Icon = i.icon;
    return (
      <Link
        key={i.href}
        href={i.href}
        onClick={() => setOpen(false)}
        aria-current={active ? 'page' : undefined}
        className={`group flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition ${
          active ? 'bg-kx-bg font-semibold text-black' : 'text-kx-muted hover:bg-kx-panel2 hover:text-black'
        }`}
      >
        <Icon className={`h-5 w-5 ${active ? 'text-black' : 'text-kx-muted/70 group-hover:text-black'}`} />
        {i.label}
      </Link>
    );
  };

  const sidebar = (
    <div className="flex h-full flex-col">
      <Link href="/dashboard" className="mb-8 block px-2"><Logo /></Link>
      <Link href="/scans/new" onClick={() => setOpen(false)} className="btn mb-6 w-full">
        <IconPlus className="h-4 w-4" /> Nouveau scan
      </Link>
      <nav className="flex flex-col gap-1" aria-label="Navigation principale">
        {NAV.map(link)}
        {isAdmin && (
          <>
            <p className="mb-1 mt-6 px-3 text-[11px] font-semibold uppercase tracking-wider text-kx-muted/70">Opérateur</p>
            {ADMIN_NAV.map(link)}
          </>
        )}
      </nav>
      <div className="mt-auto border-t border-kx-border pt-4">
        <p className="truncate px-3 text-xs text-kx-muted" title={user?.email}>{user?.email}</p>
        <button onClick={logout} className="mt-2 flex w-full items-center gap-3 rounded-xl px-3 py-2 text-sm text-kx-muted hover:bg-kx-panel2 hover:text-black">
          <IconLogout className="h-5 w-5 text-kx-muted/70" /> Se déconnecter
        </button>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen lg:flex">
      <aside className="sticky top-0 hidden h-screen w-64 shrink-0 border-r border-kx-border bg-white px-4 py-6 lg:block">{sidebar}</aside>

      {open && (
        <div className="fixed inset-0 z-40 lg:hidden" role="dialog" aria-modal="true" aria-label="Menu">
          <button className="absolute inset-0 bg-kx-navy/50" aria-label="Fermer le menu" onClick={() => setOpen(false)} />
          <aside className="relative h-full w-72 max-w-[85vw] bg-white px-4 py-6">{sidebar}</aside>
        </div>
      )}

      <div className="min-w-0 flex-1">
        <header className="sticky top-0 z-20 flex items-center gap-3 border-b border-kx-border bg-white/85 px-4 py-3 backdrop-blur sm:px-8">
          <button className="rounded-lg p-2 text-kx-text hover:bg-kx-panel2 lg:hidden" onClick={() => setOpen(true)} aria-label="Ouvrir le menu">
            <IconMenu />
          </button>
          <span className="lg:hidden"><Logo /></span>
          <div className="ml-auto flex items-center gap-2"><ActiveScans /><NotificationBell /><CreditPill /></div>
        </header>
        <main className="mx-auto max-w-6xl px-4 py-8 sm:px-8 sm:py-10">{children}</main>
      </div>
    </div>
  );
}
