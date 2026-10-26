'use client';

import Link from 'next/link';
import AdminOnly from '@/components/AdminOnly';
import { GrantForm } from '@/components/admin/GrantForm';
import { IconArrow } from '@/components/icons';
import { Empty, ErrorBox, Loading, PageHeader } from '@/components/ui';
import { api } from '@/lib/api';
import { fmtDate } from '@/lib/format';
import type { AdminOverview } from '@/lib/types';
import { useAsync } from '@/lib/useAsync';

const ACTION_LABEL: Record<string, string> = {
  suspend: 'Compte suspendu', reactivate: 'Compte réactivé', credit_grant: 'Crédits attribués',
};

function Stat({ label, value, hint, href }: { label: string; value: React.ReactNode; hint?: string; href?: string }) {
  const body = (
    <>
      <p className="text-xs uppercase tracking-wide text-kx-muted">{label}</p>
      <p className="mt-1 font-display text-2xl font-semibold tabular-nums">{value}</p>
      {hint && <p className="text-xs text-kx-muted">{hint}</p>}
    </>
  );
  const cls = 'rounded-xl border border-kx-border bg-white p-4';
  return href
    ? <Link href={href} className={`${cls} block transition hover:border-black/30`}>{body}</Link>
    : <div className={cls}>{body}</div>;
}

function Overview() {
  const { data, error, loading, reload } = useAsync(() => api<AdminOverview>('/admin/overview'), []);

  if (loading) return <Loading />;
  if (error) return <ErrorBox message={error} onRetry={reload} />;
  if (!data) return null;

  return (
    <div className="space-y-8">
      {data.pending_requests > 0 && (
        <Link href="/admin/requests" className="alert-info flex items-center justify-between gap-3">
          <span><b>{data.pending_requests}</b> demande(s) d’audit en attente de validation.</span>
          <IconArrow className="h-4 w-4 shrink-0" />
        </Link>
      )}

      <section className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Comptes" value={data.users_total} hint={`+${data.users_new_7d} sur 7 jours`} href="/admin/users" />
        <Stat label="Comptes suspendus" value={data.users_suspended} href="/admin/users" />
        <Stat label="Scans aujourd’hui" value={data.scans_today} hint={`${data.scans_running} en cours`} />
        <Stat label="Demandes en attente" value={data.pending_requests} href="/admin/requests" />
        <Stat label="Crédits en circulation" value={data.credits_outstanding} hint="Soldes clients non expirés" />
        <Stat label="Crédits attribués" value={data.credits_granted_30d} hint="Manuellement, sur 30 jours" />
        <Stat label="Codes actifs" value={data.vouchers_active} href="/admin/credits" />
      </section>

      <GrantForm />

      <div className="grid gap-6 lg:grid-cols-2">
        <section className="card">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="card-title mb-0">Derniers inscrits</h2>
            <Link href="/admin/users" className="text-sm text-kx-muted hover:text-black">Tous les comptes</Link>
          </div>
          {data.recent_users.length === 0 ? <Empty title="Aucun compte" /> : (
            <ul className="divide-y divide-kx-border">
              {data.recent_users.map(u => (
                <li key={u.id} className="flex items-center justify-between gap-3 py-2.5 text-sm">
                  <Link href={`/admin/users/${u.id}`} className="truncate font-medium hover:underline">{u.email}</Link>
                  <span className="shrink-0 text-kx-muted">{fmtDate(u.join_time, false)}</span>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="card">
          <h2 className="card-title">Dernières actions admin</h2>
          {data.recent_actions.length === 0 ? <Empty title="Aucune action pour l’instant" /> : (
            <ul className="divide-y divide-kx-border">
              {data.recent_actions.map(a => (
                <li key={a.id} className="py-2.5 text-sm">
                  <div className="flex items-center justify-between gap-3">
                    <span className="font-medium">{ACTION_LABEL[a.action] ?? a.action}</span>
                    <span className="shrink-0 text-kx-muted">{fmtDate(a.created_time)}</span>
                  </div>
                  <p className="truncate text-kx-muted">
                    {a.target_user_id
                      ? <Link href={`/admin/users/${a.target_user_id}`} className="hover:underline">{a.target_email ?? `#${a.target_user_id}`}</Link>
                      : '—'}
                    {a.note ? ` · ${a.note}` : ''}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </div>
  );
}

export default function AdminPage() {
  return (
    <AdminOnly>
      <PageHeader title="Console administrateur" sub="Comptes, crédits et activité de la plateforme." />
      <Overview />
    </AdminOnly>
  );
}
