'use client';

import Link from 'next/link';
import { useState } from 'react';
import { Empty, ErrorBox, Loading, Pager, PageHeader, StatusBadge, TextLink } from '@/components/ui';
import { api } from '@/lib/api';
import { BILLING_LABEL, fmtDate, hostOf, PROFILE_LABEL, STATUS_LABEL } from '@/lib/format';
import type { Page, Scan, ScanStatus, Target } from '@/lib/types';
import { useAsync } from '@/lib/useAsync';

export default function ScansPage() {
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState('');
  const [targetId, setTargetId] = useState('');
  const targets = useAsync(() => api<Page<Target>>('/targets', { query: { page: 1, size: 100 } }), []);
  const scans = useAsync(
    () => api<Page<Scan>>('/scans', { query: { page, size: 20, status, target_id: targetId } }),
    [page, status, targetId],
  );
  const host = (id: number) => {
    const t = targets.data?.items.find(x => x.id === id);
    return t ? hostOf(t.url) : `Cible #${id}`;
  };

  return (
    <>
      <PageHeader title="Scans" sub="Historique de vos audits et état des tâches." actions={<Link href="/scans/new" className="btn">Lancer un scan</Link>} />

      <div className="mb-4 flex flex-wrap gap-3">
        <div>
          <label className="label" htmlFor="f-status">Statut</label>
          <select id="f-status" className="input" value={status} onChange={e => { setStatus(e.target.value); setPage(1); }}>
            <option value="">Tous</option>
            {(Object.keys(STATUS_LABEL) as ScanStatus[]).map(s => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
          </select>
        </div>
        <div>
          <label className="label" htmlFor="f-target">Application</label>
          <select id="f-target" className="input" value={targetId} onChange={e => { setTargetId(e.target.value); setPage(1); }}>
            <option value="">Toutes</option>
            {targets.data?.items.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
          </select>
        </div>
      </div>

      {scans.loading && <Loading />}
      {scans.error && <ErrorBox message={scans.error} onRetry={scans.reload} />}
      {scans.data && scans.data.items.length === 0 && (
        <Empty title={status || targetId ? 'Aucun scan pour ces filtres' : 'Aucun scan pour l’instant'}
          action={!status && !targetId && <Link href="/scans/new" className="btn">Lancer un scan</Link>} />
      )}
      {scans.data && scans.data.items.length > 0 && (
        <div className="card overflow-x-auto p-0 sm:p-0">
          <table className="table">
            <thead><tr><th>#</th><th>Application</th><th>Profil</th><th>Facturation</th><th>Statut</th><th>Créé le</th><th /></tr></thead>
            <tbody>
              {scans.data.items.map(s => (
                <tr key={s.id}>
                  <td className="text-kx-muted">{s.id}</td>
                  <td className="font-medium">{host(s.target_id)}</td>
                  <td>{PROFILE_LABEL[s.profile]?.name || s.profile}</td>
                  <td className="text-kx-muted">
                    {BILLING_LABEL[s.billing] || s.billing}{s.credits_charged > 0 ? ` · ${s.credits_charged} cr.` : ''}
                  </td>
                  <td><StatusBadge status={s.status} /></td>
                  <td className="whitespace-nowrap text-kx-muted">{fmtDate(s.created_time)}</td>
                  <td className="text-right"><TextLink href={`/scans/${s.id}`}>Détail</TextLink></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {scans.data && <Pager page={page} totalPages={scans.data.total_pages} onPage={setPage} />}
    </>
  );
}
