'use client';

import { useState } from 'react';
import AdminOnly from '@/components/AdminOnly';
import { ErrorBox, Loading, PageHeader } from '@/components/ui';
import { api } from '@/lib/api';
import { fmtDate } from '@/lib/format';
import type { Voucher } from '@/lib/types';
import { useAsync } from '@/lib/useAsync';

function VoucherAdmin() {
  const list = useAsync(() => api<Voucher[]>('/credits/vouchers'), []);
  const [count, setCount] = useState(1);
  const [credits, setCredits] = useState(20);
  const [maxUses, setMaxUses] = useState(1);
  const [validUntil, setValidUntil] = useState('');
  const [validityDays, setValidityDays] = useState('');
  const [note, setNote] = useState('');
  const [created, setCreated] = useState<Voucher[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  const generate = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setErr('');
    try {
      const v = await api<Voucher[]>('/credits/vouchers', {
        method: 'POST',
        body: {
          count, credits, max_redemptions: maxUses, note: note || null,
          valid_until: validUntil ? new Date(`${validUntil}T23:59:59`).toISOString() : null,
          credit_validity_days: validityDays ? Number(validityDays) : null,
        },
      });
      setCreated(v);
      await list.reload();
    } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };

  const disable = async (id: number) => {
    if (!confirm('Désactiver ce code ?')) return;
    try { await api(`/credits/vouchers/${id}/disable`, { method: 'POST' }); await list.reload(); }
    catch (e: any) { setErr(e.message); }
  };

  return (
    <section className="space-y-6">
      <form onSubmit={generate} className="card space-y-4">
        <h2 className="card-title mb-0">Générer des codes crédit</h2>
        <div className="grid gap-4 sm:grid-cols-3">
          <Num id="v-count" label="Nombre de codes" value={count} set={setCount} min={1} max={500} />
          <Num id="v-credits" label="Crédits par code" value={credits} set={setCredits} min={1} />
          <Num id="v-uses" label="Utilisations max. par code" value={maxUses} set={setMaxUses} min={1} />
          <div>
            <label className="label" htmlFor="v-until">Code valable jusqu’au (optionnel)</label>
            <input id="v-until" type="date" className="input" value={validUntil} onChange={e => setValidUntil(e.target.value)} />
          </div>
          <div>
            <label className="label" htmlFor="v-days">Crédits expirent après N jours (optionnel)</label>
            <input id="v-days" type="number" min={1} className="input" value={validityDays} onChange={e => setValidityDays(e.target.value)} placeholder="Jamais" />
          </div>
          <div>
            <label className="label" htmlFor="v-note">Note interne</label>
            <input id="v-note" className="input" value={note} onChange={e => setNote(e.target.value)} maxLength={255} placeholder="Campagne, client…" />
          </div>
        </div>
        {err && <p className="alert-err" role="alert">{err}</p>}
        <button className="btn" disabled={busy}>{busy ? 'Génération…' : 'Générer'}</button>
        {created.length > 0 && (
          <div className="alert-ok">
            <p className="mb-2 font-semibold">{created.length} code(s) généré(s) :</p>
            <pre className="whitespace-pre-wrap font-mono text-xs">{created.map(v => v.code).join('\n')}</pre>
          </div>
        )}
      </form>

      <GrantForm />

      <div className="card">
        <h2 className="card-title">Codes existants</h2>
        {list.loading && <Loading />}
        {list.error && <ErrorBox message={list.error} onRetry={list.reload} />}
        {list.data && (
          <div className="overflow-x-auto">
            <table className="table">
              <thead><tr><th>Code</th><th>Crédits</th><th>Utilisations</th><th>Valable jusqu’au</th><th>Validité crédits</th><th>Note</th><th /></tr></thead>
              <tbody>
                {list.data.map(v => (
                  <tr key={v.id} className={v.is_active ? '' : 'opacity-50'}>
                    <td className="font-mono text-xs">{v.code}</td>
                    <td>{v.credits}</td>
                    <td>{v.redemption_count} / {v.max_redemptions}</td>
                    <td className="text-kx-muted">{v.valid_until ? fmtDate(v.valid_until, false) : '—'}</td>
                    <td className="text-kx-muted">{v.credit_validity_days ? `${v.credit_validity_days} j` : 'Illimitée'}</td>
                    <td className="text-kx-muted">{v.note || '—'}</td>
                    <td className="text-right">{v.is_active ? <button className="btn-danger" onClick={() => disable(v.id)}>Désactiver</button> : 'Inactif'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}

function GrantForm() {
  const [email, setEmail] = useState('');
  const [credits, setCredits] = useState(20);
  const [days, setDays] = useState('');
  const [note, setNote] = useState('');
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const grant = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setMsg(null);
    try {
      await api('/credits/grant', { method: 'POST', body: { email, credits, expires_in_days: days ? Number(days) : null, note: note || null } });
      setMsg({ ok: true, text: `${credits} crédit(s) attribué(s) à ${email}.` });
      setEmail(''); setNote('');
    } catch (e: any) { setMsg({ ok: false, text: e.message }); } finally { setBusy(false); }
  };

  return (
    <form onSubmit={grant} className="card space-y-4">
      <h2 className="card-title mb-0">Attribuer des crédits à un compte</h2>
      <div className="grid gap-4 sm:grid-cols-4">
        <div className="sm:col-span-2">
          <label className="label" htmlFor="g-email">Email du compte</label>
          <input id="g-email" type="email" required className="input" value={email} onChange={e => setEmail(e.target.value)} />
        </div>
        <Num id="g-credits" label="Crédits" value={credits} set={setCredits} min={1} />
        <div>
          <label className="label" htmlFor="g-days">Expire après N jours</label>
          <input id="g-days" type="number" min={1} className="input" value={days} onChange={e => setDays(e.target.value)} placeholder="Jamais" />
        </div>
      </div>
      <div>
        <label className="label" htmlFor="g-note">Motif</label>
        <input id="g-note" className="input" value={note} onChange={e => setNote(e.target.value)} maxLength={255} />
      </div>
      {msg && <p className={msg.ok ? 'alert-ok' : 'alert-err'} role="status">{msg.text}</p>}
      <button className="btn" disabled={busy || !email}>{busy ? 'Attribution…' : 'Attribuer'}</button>
    </form>
  );
}

function Num({ id, label, value, set, min, max }: { id: string; label: string; value: number; set: (n: number) => void; min?: number; max?: number }) {
  return (
    <div>
      <label className="label" htmlFor={id}>{label}</label>
      <input id={id} type="number" className="input" min={min} max={max} value={value} onChange={e => set(Math.max(min ?? 0, Number(e.target.value) || 0))} />
    </div>
  );
}

export default function AdminPage() {
  return (
    <AdminOnly>
      <PageHeader title="Administration" sub="Codes crédit et attributions manuelles." />
      <VoucherAdmin />
    </AdminOnly>
  );
}
