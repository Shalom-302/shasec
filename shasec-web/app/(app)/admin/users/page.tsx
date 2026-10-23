'use client';

import Link from 'next/link';
import { useState } from 'react';
import AdminOnly from '@/components/AdminOnly';
import { Empty, ErrorBox, Loading, PageHeader, Pager } from '@/components/ui';
import { RiskBadge } from '@/components/RiskBadge';
import { api } from '@/lib/api';
import { fmtDate } from '@/lib/format';
import type { AdminUserListItem, Page } from '@/lib/types';
import { useAsync } from '@/lib/useAsync';

const SIZE = 20;

function Users() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [q, setQ] = useState('');
  const [status, setStatus] = useState<'' | 'true' | 'false'>('');

  const { data, error, loading, reload } = useAsync(
    () => api<Page<AdminUserListItem>>('/admin/users', {
      query: { page, size: SIZE, query: q || undefined, status: status || undefined },
    }),
    [page, q, status],
  );

  const submit = (e: React.FormEvent) => { e.preventDefault(); setPage(1); setQ(search.trim()); };

  return (
    <>
      <PageHeader title="Utilisateurs" sub="Comptes clients, consommation et signaux de risque." />

      <form onSubmit={submit} className="mb-5 flex flex-wrap items-end gap-3">
        <div className="min-w-0 flex-1">
          <label className="label" htmlFor="u-search">Rechercher par email</label>
          <input id="u-search" className="input" value={search} onChange={e => setSearch(e.target.value)} placeholder="client@exemple.com" />
        </div>
        <div>
          <label className="label" htmlFor="u-status">Statut</label>
          <select id="u-status" className="input" value={status} onChange={e => { setPage(1); setStatus(e.target.value as any); }}>
            <option value="">Tous</option>
            <option value="true">Actifs</option>
            <option value="false">Suspendus</option>
          </select>
        </div>
        <button className="btn">Rechercher</button>
      </form>

      {loading && <Loading />}
      {error && <ErrorBox message={error} onRetry={reload} />}
      {data && data.items.length === 0 && <Empty title="Aucun compte">Aucun utilisateur ne correspond à ces critères.</Empty>}

      {data && data.items.length > 0 && (
        <div className="card overflow-x-auto p-0">
          <table className="table">
            <thead>
              <tr>
                <th>Compte</th><th>Statut</th><th className="text-right">Crédits</th>
                <th className="text-right">Scans</th><th className="text-right">En attente</th>
                <th>Risque</th><th>Inscription</th><th />
              </tr>
            </thead>
            <tbody>
              {data.items.map(u => (
                <tr key={u.id} className={u.status ? '' : 'bg-red-50/40'}>
                  <td>
                    <Link href={`/admin/users/${u.id}`} className="font-medium hover:underline">{u.email}</Link>
                    {u.is_admin && <span className="ml-2 rounded-full bg-black px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-white">Admin</span>}
                  </td>
                  <td>
                    {u.status
                      ? <span className="rounded-full bg-kx-tealSoft px-2.5 py-1 text-xs font-semibold text-teal-900">Actif</span>
                      : <span className="rounded-full bg-red-100 px-2.5 py-1 text-xs font-semibold text-red-700">Suspendu</span>}
                  </td>
                  <td className="text-right tabular-nums">
                    {u.is_admin ? '∞' : u.credits}
                    {!u.is_admin && u.free_scans > 0 && <span className="ml-1 text-xs text-teal-700">+{u.free_scans}g</span>}
                  </td>
                  <td className="text-right tabular-nums">
                    {u.scan_count}
                    {u.failed_scans > 0 && <span className="ml-1 text-xs text-red-600">({u.failed_scans} éch.)</span>}
                  </td>
                  <td className="text-right tabular-nums">{u.pending_requests || '—'}</td>
                  <td><RiskBadge level={u.risk_level} count={u.risk_count} /></td>
                  <td className="whitespace-nowrap text-sm text-kx-muted">{fmtDate(u.join_time, false)}</td>
                  <td className="text-right"><Link href={`/admin/users/${u.id}`} className="btn-ghost btn-sm">Détail</Link></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {data && <Pager page={data.page} totalPages={data.total_pages} onPage={setPage} />}
    </>
  );
}

export default function AdminUsersPage() {
  return <AdminOnly><Users /></AdminOnly>;
}
