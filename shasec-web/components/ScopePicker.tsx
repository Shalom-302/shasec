'use client';

import { useMemo, useState } from 'react';
import { BulkBar, RowBox, SelectAllBox, useSelection } from '@/components/bulk';
import { ErrorBox, Loading } from '@/components/ui';
import { api } from '@/lib/api';
import type { ScanAsset } from '@/lib/types';
import { useAsync } from '@/lib/useAsync';

/** Step 1→2 gate of a domain audit: the operator ticks which discovered hosts
 *  are in scope, then launches steps 2-4. Third-party / dead hosts can't be
 *  picked (the API refuses them too). */
export function ScopePicker({ scanId, onLaunched }: { scanId: number; onLaunched: () => void }) {
  const { data, error, loading, reload } = useAsync(() => api<ScanAsset[]>(`/scans/${scanId}/assets`), [scanId]);
  const assets = data || [];
  const selectable = useMemo(() => assets.filter(a => a.alive && !a.third_party).map(a => a.id), [assets]);
  const sel = useSelection(selectable);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  // Pre-tick the API's auto-selection the first time the list loads.
  const [seeded, setSeeded] = useState(false);
  if (!seeded && assets.length) {
    setSeeded(true);
    const pre = assets.filter(a => a.selected).map(a => a.id);
    if (pre.length) pre.forEach(id => !sel.has(id) && sel.toggle(id));
  }

  const launch = async () => {
    if (sel.count === 0) return;
    setBusy(true); setErr('');
    try {
      await api(`/scans/${scanId}/scope`, { method: 'POST', body: { asset_ids: sel.ids } });
      onLaunched();
    } catch (e: any) { setErr(e.message); setBusy(false); }
  };

  if (loading) return <Loading />;
  if (error) return <ErrorBox message={error} onRetry={reload} />;

  const alive = assets.filter(a => a.alive).length;

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-indigo-200 bg-indigo-50 p-4 text-sm text-indigo-900">
        <p className="font-semibold">Étape 1 terminée — cartographie du domaine</p>
        <p className="mt-1">
          {assets.length} hôte(s) découvert(s), {alive} actif(s). Sélectionnez ceux qui sont dans votre périmètre,
          puis lancez les étapes 2 à 4 (scan passif + actif, accès anonyme, validation). Les hôtes hébergés chez un
          tiers ou injoignables ne peuvent pas être audités.
        </p>
      </div>

      <BulkBar sel={sel}>
        <button className="btn" disabled={busy || sel.count === 0} onClick={launch}>
          {busy ? 'Lancement…' : `Lancer l’audit sur ${sel.count} hôte(s)`}
        </button>
      </BulkBar>
      {err && <ErrorBox message={err} />}

      <div className="card overflow-x-auto p-0">
        <table className="table">
          <thead>
            <tr>
              <th className="w-10"><SelectAllBox sel={sel} disabled={selectable.length === 0} /></th>
              <th>Hôte</th><th>Type</th><th>Statut HTTP</th><th>Source</th><th>Détails</th>
            </tr>
          </thead>
          <tbody>
            {assets.map(a => {
              const locked = !a.alive || !!a.third_party;
              return (
                <tr key={a.id} className={locked ? 'opacity-55' : ''}>
                  <td>
                    <RowBox sel={sel} id={a.id} label={`Sélectionner ${a.host}`} disabled={locked}
                      title={a.third_party ? `Hébergé chez ${a.third_party} — hors périmètre` : !a.alive ? 'Injoignable' : undefined} />
                  </td>
                  <td className="font-medium">{a.host}{a.title ? <span className="block text-xs font-normal text-kx-muted">{a.title}</span> : null}</td>
                  <td>{a.kind === 'api' ? 'API' : 'Site'}</td>
                  <td className="text-kx-muted">{a.alive ? (a.http_status ?? '—') : 'hors ligne'}</td>
                  <td className="text-kx-muted">{a.source}</td>
                  <td className="text-xs text-kx-muted">
                    {a.third_party ? <span className="rounded-full bg-amber-100 px-2 py-0.5 text-amber-800">tiers · {a.third_party}</span>
                      : a.server || a.ips || '—'}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
