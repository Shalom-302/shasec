'use client';

import { useState } from 'react';
import AdminOnly from '@/components/AdminOnly';
import { Empty, ErrorBox, Loading, PageHeader } from '@/components/ui';
import { api } from '@/lib/api';
import { fmtDate } from '@/lib/format';
import { useAsync } from '@/lib/useAsync';

type Aff = {
  id: number; code: string; email: string; full_name: string; payout_phone: string; payout_method: string;
  status: string; discount_pct: number; commission_pct: number; created_time: string; note?: string | null;
  referees: number; totals: Record<'pending' | 'available' | 'paid' | 'rejected', number>;
};
type Com = {
  id: number; amount: number; status: string; flags?: string | null; note?: string | null; available_at?: string | null;
  paid_at?: string | null; paid_ref?: string | null; created_time: string; affiliate_id: number; code: string;
  full_name: string; payout_method: string; payout_phone: string; referee_email: string; paid_amount: number;
  list_price?: number | null; payer_phone?: string | null; payment_date?: string | null;
};
const fcfa = (n: number) => `${(n || 0).toLocaleString('fr-FR')} F`;
const TABS = [
  ['available', 'À verser'], ['pending', 'En attente'], ['paid', 'Versées'], ['rejected', 'Refusées'], ['affiliates', 'Parrains'],
] as const;

function Affiliates() {
  const list = useAsync(() => api<{ items: Aff[]; min_payout: number }>('/affiliates/admin/list'), []);
  const [rates, setRates] = useState<Record<number, { d: string; c: string; note: string }>>({});
  const [msg, setMsg] = useState('');
  const review = async (a: Aff, status: string) => {
    const r = rates[a.id] || { d: String(a.discount_pct), c: String(a.commission_pct), note: '' };
    if (status !== 'approved' && !r.note.trim() && !confirm(`${status === 'suspended' ? 'Suspendre' : 'Refuser'} ${a.code} sans motif ?`)) return;
    try {
      await api(`/affiliates/admin/${a.id}/review`, { method: 'POST', body: { status, discount_pct: Number(r.d), commission_pct: Number(r.c), note: r.note || null } });
      setMsg(`${a.code} : ${status}.`); list.reload();
    } catch (e: any) { setMsg(e.message); }
  };
  if (list.loading) return <Loading />;
  if (list.error) return <ErrorBox message={list.error} onRetry={list.reload} />;
  const items = list.data!.items;
  return (
    <div className="space-y-4">
      {msg && <p className="alert-info">{msg}</p>}
      {items.length === 0 && <Empty title="Aucun parrain">Les demandes apparaîtront ici (alerte WhatsApp à chaque demande).</Empty>}
      {items.map(a => {
        const r = rates[a.id] || { d: String(a.discount_pct), c: String(a.commission_pct), note: '' };
        const set = (k: 'd' | 'c' | 'note', v: string) => setRates(x => ({ ...x, [a.id]: { ...r, [k]: v } }));
        return (
          <div key={a.id} className="card space-y-3">
            <div className="flex flex-wrap items-start justify-between gap-2">
              <div className="min-w-0">
                <p className="font-display text-lg font-semibold"><span className="font-mono">{a.code}</span> · {a.full_name}</p>
                <p className="break-all text-sm text-kx-muted">{a.email} · {a.payout_method} {a.payout_phone} · demandé le {fmtDate(a.created_time, false)}</p>
              </div>
              <span className="rounded-full bg-kx-panel2 px-3 py-1 text-xs font-semibold">{a.status}</span>
            </div>
            <p className="text-sm">{a.referees} filleul(s) · versé {fcfa(a.totals.paid)} · à verser {fcfa(a.totals.available)} · en attente {fcfa(a.totals.pending)} · refusé {fcfa(a.totals.rejected)}</p>
            <div className="grid gap-2 sm:grid-cols-[110px_110px_1fr_auto]">
              <label className="text-xs text-kx-muted">Réduction %<input className="input mt-1" inputMode="numeric" value={r.d} onChange={e => set('d', e.target.value)} /></label>
              <label className="text-xs text-kx-muted">Commission %<input className="input mt-1" inputMode="numeric" value={r.c} onChange={e => set('c', e.target.value)} /></label>
              <label className="text-xs text-kx-muted">Note<input className="input mt-1" value={r.note} onChange={e => set('note', e.target.value)} placeholder="Motif / remarque" /></label>
              <div className="flex flex-wrap items-end gap-2">
                <button className="btn btn-sm" onClick={() => review(a, 'approved')}>{a.status === 'approved' ? 'Mettre à jour' : 'Approuver'}</button>
                {a.status === 'approved' && <button className="btn-danger btn-sm" onClick={() => review(a, 'suspended')}>Suspendre</button>}
                {a.status === 'pending' && <button className="btn-danger btn-sm" onClick={() => review(a, 'rejected')}>Refuser</button>}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function Commissions({ status }: { status: string }) {
  const { data, error, loading, reload } = useAsync(() => api<Com[]>('/affiliates/admin/commissions', { query: { status } }), [status]);
  const [refs, setRefs] = useState<Record<number, string>>({});
  const [busy, setBusy] = useState<number | null>(null);
  const [msg, setMsg] = useState('');
  const act = async (c: Com, action: 'paid' | 'rejected' | 'available') => {
    const ref = (refs[c.id] || '').trim();
    if (action === 'paid' && !ref) { setMsg('Saisissez la référence du transfert avant de marquer comme versée.'); return; }
    if (action === 'paid' && !confirm(`Confirmer le versement de ${fcfa(c.amount)} à ${c.full_name} (${c.payout_method} ${c.payout_phone}) ?`)) return;
    let note: string | null = null;
    if (action === 'rejected') { note = prompt('Motif du refus (visible dans l’historique) :') || ''; if (!note.trim()) return; }
    setBusy(c.id); setMsg('');
    try {
      await api(`/affiliates/admin/commissions/${c.id}`, { method: 'POST', body: { action, paid_ref: ref || null, note } });
      setMsg(action === 'paid' ? `Commission #${c.id} marquée versée.` : action === 'rejected' ? `Commission #${c.id} refusée.` : `Commission #${c.id} validée.`);
      await reload();
    } catch (e: any) { setMsg(e.message); } finally { setBusy(null); }
  };
  if (loading) return <Loading />;
  if (error) return <ErrorBox message={error} onRetry={reload} />;
  const items = data || [];
  const byAff = items.reduce<Record<string, number>>((m, c) => ({ ...m, [`${c.code} · ${c.full_name} · ${c.payout_method} ${c.payout_phone}`]: (m[`${c.code} · ${c.full_name} · ${c.payout_method} ${c.payout_phone}`] || 0) + c.amount }), {});
  return (
    <div className="space-y-4">
      {msg && <p className="alert-info">{msg}</p>}
      {status === 'available' && Object.keys(byAff).length > 0 && (
        <section className="card">
          <h2 className="card-title">Total à verser par parrain</h2>
          <ul className="space-y-1 text-sm">{Object.entries(byAff).map(([k, v]) => <li key={k} className="flex justify-between gap-3"><span className="break-all">{k}</span><b className="shrink-0">{fcfa(v)}</b></li>)}</ul>
        </section>
      )}
      {items.length === 0 && <Empty title="Rien ici">{status === 'available' ? 'Aucune commission validée à verser.' : 'Aucune commission dans cet état.'}</Empty>}
      {items.map(c => (
        <div key={c.id} className="card space-y-2">
          <div className="flex flex-wrap items-start justify-between gap-2">
            <p className="font-display text-lg font-semibold">{fcfa(c.amount)} · <span className="font-mono">{c.code}</span></p>
            <span className="text-xs text-kx-muted">#{c.id} · {fmtDate(c.created_time)}</span>
          </div>
          <p className="break-all text-sm text-kx-muted">
            Filleul {c.referee_email} a payé {fcfa(c.paid_amount)}{c.list_price ? ` (prix ${fcfa(c.list_price)})` : ''} depuis {c.payer_phone || '—'}
          </p>
          <p className="text-sm">Verser à <b>{c.full_name}</b> · {c.payout_method} <b>{c.payout_phone}</b></p>
          {c.flags && <p className="alert-err">⚠️ {c.flags}</p>}
          {c.note && <p className="text-sm text-kx-muted">Note : {c.note}</p>}
          {c.status === 'pending' && c.available_at && <p className="text-xs text-kx-muted">Fin de l’attente : {fmtDate(c.available_at, false)} (et le filleul doit avoir utilisé ses crédits).</p>}
          {c.paid_ref && <p className="text-sm">Versée le {fmtDate(c.paid_at || '', false)} · réf. <span className="font-mono">{c.paid_ref}</span></p>}
          {(c.status === 'available' || c.status === 'pending') && (
            <div className="flex flex-col gap-2 sm:flex-row">
              <input className="input sm:flex-1" placeholder="Référence du transfert (Wave / Orange Money…)" value={refs[c.id] || ''} onChange={e => setRefs(x => ({ ...x, [c.id]: e.target.value }))} />
              <div className="flex flex-wrap gap-2">
                <button className="btn btn-sm" disabled={busy === c.id} onClick={() => act(c, 'paid')}>Marquer versée</button>
                {c.status === 'pending' && <button className="btn-ghost btn-sm" disabled={busy === c.id} onClick={() => act(c, 'available')}>Valider maintenant</button>}
                <button className="btn-danger btn-sm" disabled={busy === c.id} onClick={() => act(c, 'rejected')}>Refuser</button>
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function Page() {
  const [tab, setTab] = useState<(typeof TABS)[number][0]>('available');
  return (
    <>
      <PageHeader title="Parrains & versements" sub="Rien n’est versé automatiquement : vous validez les parrains, vous versez vous-même et vous saisissez la référence du transfert." />
      <div className="mb-4 flex flex-wrap gap-2">
        {TABS.map(([id, label]) => <button key={id} className={tab === id ? 'btn btn-sm' : 'btn-ghost btn-sm'} onClick={() => setTab(id)}>{label}</button>)}
      </div>
      {tab === 'affiliates' ? <Affiliates /> : <Commissions status={tab} />}
    </>
  );
}

export default function AdminAffiliatesPage() {
  return <AdminOnly><Page /></AdminOnly>;
}
