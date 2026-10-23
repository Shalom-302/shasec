'use client';

import Link from 'next/link';
import { useState } from 'react';
import AdminOnly from '@/components/AdminOnly';
import { Empty, ErrorBox, Loading, PageHeader, TextLink } from '@/components/ui';
import { api } from '@/lib/api';
import { fmtDate, PROFILE_LABEL } from '@/lib/format';
import type { Page, Scan } from '@/lib/types';
import { useAsync } from '@/lib/useAsync';

function Requests() {
  const { data, error, loading, reload } = useAsync(
    () => api<Page<Scan>>('/scans/pending-approval', { query: { page: 1, size: 50 } }), [],
  );
  const [busy, setBusy] = useState<number | null>(null);
  const [notes, setNotes] = useState<Record<number, string>>({});
  const [msg, setMsg] = useState('');

  const act = async (id: number, action: 'approve' | 'reject') => {
    if (action === 'reject' && !confirm('Refuser cette demande ? Les crédits du client seront restitués.')) return;
    setBusy(id); setMsg('');
    try {
      await api(`/scans/${id}/${action}`, { method: 'POST', body: { note: notes[id]?.trim() || null } });
      setMsg(action === 'approve' ? `Demande #${id} approuvée, le scan va démarrer.` : `Demande #${id} refusée, crédits restitués.`);
      await reload();
    } catch (e: any) { setMsg(e.message); } finally { setBusy(null); }
  };

  return (
    <>
      <PageHeader title="Demandes d’audit avancé" sub="Validez les audits à tests actifs demandés par les clients." />
      {loading && <Loading />}
      {error && <ErrorBox message={error} onRetry={reload} />}
      {msg && <p className="alert-info mb-4">{msg}</p>}
      {data && data.items.length === 0 && <Empty title="Aucune demande en attente">Les nouvelles demandes d’audit avancé apparaîtront ici.</Empty>}
      {data && data.items.length > 0 && (
        <div className="space-y-4">
          {data.items.map(s => (
            <div key={s.id} className="card">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="font-display text-lg font-semibold">Scan #{s.id} · <TextLink href={`/scans/${s.id}`}>détail</TextLink></p>
                  <p className="text-sm text-kx-muted">
                    Profil {PROFILE_LABEL[s.profile]?.name || s.profile} · {s.credits_charged} crédits réservés · demandé le {fmtDate(s.created_time)}
                  </p>
                </div>
                <span className="rounded-full bg-indigo-50 px-3 py-1 text-xs font-semibold text-indigo-700">Tests actifs</span>
              </div>
              {s.scope_note && (
                <div className="mt-3 rounded-xl bg-kx-panel2 p-3 text-sm">
                  <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-kx-muted">Périmètre indiqué par le client</p>
                  {s.scope_note}
                </div>
              )}
              <div className="mt-4 flex flex-col gap-2 sm:flex-row">
                <input
                  className="input sm:flex-1"
                  placeholder="Note (motif de refus, condition d’approbation…)"
                  value={notes[s.id] || ''}
                  onChange={e => setNotes(n => ({ ...n, [s.id]: e.target.value }))}
                />
                <div className="flex gap-2">
                  <button className="btn" disabled={busy === s.id} onClick={() => act(s.id, 'approve')}>Approuver</button>
                  <button className="btn-danger" disabled={busy === s.id} onClick={() => act(s.id, 'reject')}>Refuser</button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
      <p className="mt-6 text-sm text-kx-muted">Pour vos propres audits (Kaanari), lancez directement un scan : <TextLink href="/scans/new">Lancer un scan</TextLink> — en tant qu’administrateur, aucune validation n’est requise.</p>
    </>
  );
}

export default function AdminRequestsPage() {
  return <AdminOnly><Requests /></AdminOnly>;
}
