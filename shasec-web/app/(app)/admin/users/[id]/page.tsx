'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { useState } from 'react';
import AdminOnly from '@/components/AdminOnly';
import { RiskBadge } from '@/components/RiskBadge';
import { Empty, ErrorBox, Loading, PageHeader, StatusBadge, TextLink } from '@/components/ui';
import { api } from '@/lib/api';
import { fmtDate, PROFILE_LABEL } from '@/lib/format';
import type { AdminAudit, AdminUserDetail, CreditTransaction, Page, Scan } from '@/lib/types';
import { useAsync } from '@/lib/useAsync';

const SEV_CLS: Record<string, string> = {
  low: 'border-amber-200 bg-amber-50 text-amber-900',
  medium: 'border-orange-200 bg-orange-50 text-orange-900',
  high: 'border-red-200 bg-red-50 text-red-900',
};
const ACTION_LABEL: Record<string, string> = {
  suspend: 'Compte suspendu', reactivate: 'Compte réactivé', credit_grant: 'Crédits attribués',
};

function Stat({ label, value, hint }: { label: string; value: React.ReactNode; hint?: string }) {
  return (
    <div className="rounded-xl border border-kx-border bg-white p-4">
      <p className="text-xs uppercase tracking-wide text-kx-muted">{label}</p>
      <p className="mt-1 font-display text-2xl font-semibold tabular-nums">{value}</p>
      {hint && <p className="text-xs text-kx-muted">{hint}</p>}
    </div>
  );
}

function Detail({ uid }: { uid: number }) {
  const { data: u, error, loading, reload } = useAsync(() => api<AdminUserDetail>(`/admin/users/${uid}`), [uid]);
  const scans = useAsync(() => api<Page<Scan>>(`/admin/users/${uid}/scans`, { query: { page: 1, size: 10 } }), [uid]);
  const txns = useAsync(() => api<Page<CreditTransaction>>(`/admin/users/${uid}/transactions`, { query: { page: 1, size: 10 } }), [uid]);
  const audit = useAsync(() => api<Page<AdminAudit>>(`/admin/users/${uid}/audit`, { query: { page: 1, size: 20 } }), [uid]);

  const [reason, setReason] = useState('');
  const [note, setNote] = useState('');
  const [amount, setAmount] = useState(20);
  const [days, setDays] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const reloadAll = async () => { await Promise.all([reload(), audit.reload(), txns.reload()]); };

  const act = async (fn: () => Promise<void>, ok: string) => {
    setBusy(true); setMsg(null);
    try { await fn(); setMsg({ ok: true, text: ok }); await reloadAll(); }
    catch (e: any) { setMsg({ ok: false, text: e.message }); }
    finally { setBusy(false); }
  };

  const suspend = () => {
    if (reason.trim().length < 3) { setMsg({ ok: false, text: 'Indiquez un motif (3 caractères min.).' }); return; }
    if (!confirm('Suspendre ce compte ? Ses sessions seront coupées immédiatement et il ne pourra plus se connecter.')) return;
    act(() => api(`/admin/users/${uid}/suspend`, { method: 'POST', body: { reason: reason.trim() } }), 'Compte suspendu. Le client en est notifié.')
      .then(() => setReason(''));
  };
  const reactivate = () =>
    act(() => api(`/admin/users/${uid}/reactivate`, { method: 'POST', body: { note: note.trim() || null } }), 'Compte réactivé.')
      .then(() => setNote(''));
  const grant = (e: React.FormEvent) => {
    e.preventDefault();
    act(() => api(`/admin/users/${uid}/credits`, { method: 'POST', body: { amount, expires_in_days: days ? Number(days) : null, note: note.trim() || null } }),
      `${amount} crédit(s) attribué(s).`).then(() => setNote(''));
  };

  if (loading) return <Loading />;
  if (error) return <ErrorBox message={error} onRetry={reload} />;
  if (!u) return null;

  return (
    <>
      <PageHeader
        title={u.email}
        sub={<>Inscrit le {fmtDate(u.join_time, false)} · dernière connexion {fmtDate(u.last_login_time)} · <TextLink href="/admin/users">retour à la liste</TextLink></>}
        actions={
          u.status
            ? <span className="rounded-full bg-kx-tealSoft px-3 py-1.5 text-sm font-semibold text-teal-900">Actif</span>
            : <span className="rounded-full bg-red-100 px-3 py-1.5 text-sm font-semibold text-red-700">Suspendu</span>
        }
      />

      {msg && <p className={`mb-4 ${msg.ok ? 'alert-ok' : 'alert-err'}`} role="status">{msg.text}</p>}

      {u.is_admin && (
        <div className="mb-6 rounded-xl border border-kx-border bg-kx-panel2 p-4 text-sm text-kx-muted">
          Ce compte est un <b className="text-kx-text">administrateur</b> : crédits illimités, non facturé, et non suspendable depuis cette interface.
        </div>
      )}

      {/* Aggregates */}
      <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="Crédits" value={u.is_admin ? '∞' : u.credits} hint={u.free_scans ? `${u.free_scans} scan(s) gratuit(s)` : undefined} />
        <Stat label="Scans" value={u.scan_count} hint={u.failed_scans ? `${u.failed_scans} en échec` : undefined} />
        <Stat label="Demandes en attente" value={u.pending_requests} />
        <Stat label="Applications" value={`${u.authorized_targets}/${u.targets_count}`} hint="autorisées / totales" />
      </div>

      {/* Risk signals */}
      <section className="mb-6">
        <div className="mb-2 flex items-center gap-3">
          <h2 className="font-display text-lg font-semibold">Signaux de risque</h2>
          <RiskBadge level={u.risk_level} count={u.risk_count} />
        </div>
        {u.signals.length === 0
          ? <p className="text-sm text-kx-muted">Aucun comportement à signaler. {u.active_requests_total > 0 && `${u.active_requests_total} audit(s) actif(s) demandé(s) sur ${u.distinct_active_domains} cible(s).`}</p>
          : (
            <div className="space-y-2">
              {u.signals.map(s => (
                <div key={s.code} className={`rounded-xl border p-3 text-sm ${SEV_CLS[s.severity] || SEV_CLS.low}`}>
                  <p className="font-semibold">{s.label}</p>
                  <p>{s.detail}</p>
                </div>
              ))}
            </div>
          )}
      </section>

      {/* Actions */}
      {!u.is_admin && (
        <section className="mb-8 grid gap-4 lg:grid-cols-2">
          <div className="card space-y-3">
            <h2 className="card-title mb-0">{u.status ? 'Suspendre le compte' : 'Réactiver le compte'}</h2>
            {u.status ? (
              <>
                <p className="text-sm text-kx-muted">Coupe immédiatement ses sessions et bloque la connexion. Le client voit le motif.</p>
                <textarea className="input min-h-20" value={reason} onChange={e => setReason(e.target.value)} maxLength={500} placeholder="Motif de la suspension (activité suspecte, abus, non-paiement…)" />
                <button className="btn-danger" disabled={busy} onClick={suspend}>Suspendre</button>
              </>
            ) : (
              <>
                <p className="text-sm text-kx-muted">Rétablit l’accès au compte. Le client est notifié.</p>
                <input className="input" value={note} onChange={e => setNote(e.target.value)} maxLength={500} placeholder="Note (optionnel)" />
                <button className="btn" disabled={busy} onClick={reactivate}>Réactiver</button>
              </>
            )}
          </div>

          <form onSubmit={grant} className="card space-y-3">
            <h2 className="card-title mb-0">Attribuer des crédits</h2>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="label" htmlFor="g-amount">Crédits</label>
                <input id="g-amount" type="number" min={1} className="input" value={amount} onChange={e => setAmount(Math.max(1, Number(e.target.value) || 0))} />
              </div>
              <div>
                <label className="label" htmlFor="g-days">Expire après N jours</label>
                <input id="g-days" type="number" min={1} className="input" value={days} onChange={e => setDays(e.target.value)} placeholder="Jamais" />
              </div>
            </div>
            <input className="input" value={note} onChange={e => setNote(e.target.value)} maxLength={255} placeholder="Motif (optionnel)" />
            <button className="btn" disabled={busy}>Attribuer</button>
          </form>
        </section>
      )}

      {/* Recent scans */}
      <section className="mb-8">
        <h2 className="mb-2 font-display text-lg font-semibold">Scans récents</h2>
        {scans.loading && <Loading />}
        {scans.error && <ErrorBox message={scans.error} onRetry={scans.reload} />}
        {scans.data && scans.data.items.length === 0 && <Empty title="Aucun scan">Ce compte n’a lancé aucun scan.</Empty>}
        {scans.data && scans.data.items.length > 0 && (
          <div className="card overflow-x-auto p-0">
            <table className="table">
              <thead><tr><th>#</th><th>Profil</th><th>Type</th><th>Statut</th><th>Date</th><th /></tr></thead>
              <tbody>
                {scans.data.items.map(s => (
                  <tr key={s.id}>
                    <td className="tabular-nums">{s.id}</td>
                    <td>{PROFILE_LABEL[s.profile]?.name || s.profile}</td>
                    <td>{s.allow_active_exploitation ? <span className="rounded-full bg-indigo-50 px-2 py-0.5 text-xs font-semibold text-indigo-700">Actif</span> : <span className="text-xs text-kx-muted">Passif</span>}</td>
                    <td><StatusBadge status={s.status} /></td>
                    <td className="whitespace-nowrap text-sm text-kx-muted">{fmtDate(s.created_time)}</td>
                    <td className="text-right"><TextLink href={`/scans/${s.id}`}>voir</TextLink></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Credit history */}
      <section className="mb-8">
        <h2 className="mb-2 font-display text-lg font-semibold">Historique des crédits</h2>
        {txns.loading && <Loading />}
        {txns.data && txns.data.items.length === 0 && <p className="text-sm text-kx-muted">Aucun mouvement de crédits.</p>}
        {txns.data && txns.data.items.length > 0 && (
          <div className="card overflow-x-auto p-0">
            <table className="table">
              <thead><tr><th>Date</th><th>Mouvement</th><th className="text-right">Montant</th><th>Note</th></tr></thead>
              <tbody>
                {txns.data.items.map(t => (
                  <tr key={t.id}>
                    <td className="whitespace-nowrap text-sm text-kx-muted">{fmtDate(t.created_time)}</td>
                    <td>{t.reason === 'grant' ? 'Attribution' : t.reason === 'scan_debit' ? 'Débit scan' : 'Remboursement'}</td>
                    <td className={`text-right tabular-nums font-medium ${t.delta >= 0 ? 'text-teal-700' : 'text-red-600'}`}>{t.delta >= 0 ? `+${t.delta}` : t.delta}</td>
                    <td className="text-sm text-kx-muted">{t.note || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Admin action log */}
      <section>
        <h2 className="mb-2 font-display text-lg font-semibold">Journal des actions admin</h2>
        {audit.loading && <Loading />}
        {audit.data && audit.data.items.length === 0 && <p className="text-sm text-kx-muted">Aucune action administrative sur ce compte.</p>}
        {audit.data && audit.data.items.length > 0 && (
          <ol className="space-y-2">
            {audit.data.items.map(a => (
              <li key={a.id} className="flex flex-wrap items-baseline gap-x-3 rounded-xl border border-kx-border bg-white px-4 py-2.5 text-sm">
                <span className="font-medium">{ACTION_LABEL[a.action] || a.action}</span>
                <span className="text-kx-muted">{fmtDate(a.created_time)}</span>
                {a.note && <span className="w-full text-kx-muted">{a.note}</span>}
              </li>
            ))}
          </ol>
        )}
      </section>
    </>
  );
}

export default function AdminUserDetailPage() {
  const { id } = useParams<{ id: string }>();
  return <AdminOnly><Detail uid={Number(id)} /></AdminOnly>;
}
