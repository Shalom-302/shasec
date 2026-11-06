'use client';

import { useState } from 'react';
import AdminOnly from '@/components/AdminOnly';
import { Empty, ErrorBox, Loading, PageHeader, TextLink } from '@/components/ui';
import { api } from '@/lib/api';
import { fmtDate } from '@/lib/format';
import type { AgentAction } from '@/lib/types';
import { useAsync } from '@/lib/useAsync';

const TABS = [
  { id: 'pending', label: 'À valider' },
  { id: 'executed', label: 'Exécutées' },
  { id: 'rejected', label: 'Refusées' },
  { id: 'failed', label: 'Échecs' },
];

function AgentActions() {
  const [tab, setTab] = useState('pending');
  const { data, error, loading, reload } = useAsync(
    () => api<AgentAction[]>('/agent/admin/actions', { query: { status: tab } }), [tab]);
  const [busy, setBusy] = useState<number | null>(null);
  const [notes, setNotes] = useState<Record<number, string>>({});
  const [msg, setMsg] = useState('');

  const act = async (a: AgentAction, approve: boolean) => {
    const note = notes[a.id]?.trim() || '';
    if (!approve && !note) { setMsg('Indiquez un motif de refus : l’agent s’en sert pour apprendre.'); return; }
    if (approve && !confirm(`Exécuter ${a.kind === 'advanced_audit' ? 'l’AUDIT AVANCÉ (tests actifs)' : `le scan ${a.profile}`} sur ${a.target_url} ? Les crédits du client seront débités.`)) return;
    setBusy(a.id); setMsg('');
    try {
      const r = await api<{ status: string; scan_id?: number; note?: string }>(
        `/agent/admin/actions/${a.id}/${approve ? 'approve' : 'reject'}`, { method: 'POST', body: { note: note || null } });
      setMsg(r.status === 'executed' ? `Action #${a.id} exécutée : scan #${r.scan_id} lancé.`
        : r.status === 'failed' ? `Action #${a.id} validée mais échec : ${r.note || ''}` : `Action #${a.id} refusée.`);
      await reload();
    } catch (e: any) { setMsg(e.message); } finally { setBusy(null); }
  };

  return (
    <>
      <PageHeader title="Actions proposées par l’agent" sub="L’agent Premium ne lance rien seul : chaque scan ou audit qu’il propose attend votre décision. Vos refus motivés deviennent des leçons pour lui." />
      <div className="mb-4 flex flex-wrap gap-2">
        {TABS.map(t => (
          <button key={t.id} className={tab === t.id ? 'btn' : 'btn-ghost'} onClick={() => setTab(t.id)}>{t.label}</button>
        ))}
      </div>
      {loading && <Loading />}
      {error && <ErrorBox message={error} onRetry={reload} />}
      {msg && <p className="alert-info mb-4">{msg}</p>}
      {data && data.length === 0 && <Empty title="Rien ici">Les propositions de l’agent apparaîtront ici (et vous serez alerté sur WhatsApp).</Empty>}
      <div className="space-y-4">
        {data?.map(a => (
          <div key={a.id} className="card">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <p className="font-display text-lg font-semibold">#{a.id} · {a.kind === 'advanced_audit' ? 'Audit avancé (tests actifs)' : `Scan ${a.profile}`}</p>
                <p className="text-sm text-kx-muted">{a.user_email} · {a.target_url} · {fmtDate(a.created_time)}{a.origin === 'autopilot' ? ' · revue autonome' : ''}</p>
              </div>
              {a.kind === 'advanced_audit' && <span className="rounded-full bg-indigo-50 px-3 py-1 text-xs font-semibold text-indigo-700">Tests actifs</span>}
            </div>
            <div className="mt-3 rounded-xl bg-kx-panel2 p-3 text-sm">
              <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-kx-muted">Justification de l’agent</p>
              {a.reason}
              {a.scope_note && <p className="mt-2 text-kx-muted">Périmètre : {a.scope_note}</p>}
            </div>
            {a.review_note && <p className="mt-2 text-sm text-kx-muted">Note : {a.review_note}</p>}
            {a.scan_id && <p className="mt-2 text-sm"><TextLink href={`/scans/${a.scan_id}`}>Scan #{a.scan_id}</TextLink></p>}
            {a.status === 'pending' && (
              <div className="mt-4 flex flex-col gap-2 sm:flex-row">
                <input className="input sm:flex-1" placeholder="Note (obligatoire pour refuser : l’agent apprend de votre motif)"
                  value={notes[a.id] || ''} onChange={e => setNotes(n => ({ ...n, [a.id]: e.target.value }))} />
                <div className="flex gap-2">
                  <button className="btn" disabled={busy === a.id} onClick={() => act(a, true)}>Approuver</button>
                  <button className="btn-danger" disabled={busy === a.id} onClick={() => act(a, false)}>Refuser</button>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </>
  );
}

export default function AdminAgentPage() {
  return <AdminOnly><AgentActions /></AdminOnly>;
}
