'use client';

import { useState } from 'react';
import AdminOnly from '@/components/AdminOnly';
import { GrantForm, Num } from '@/components/admin/GrantForm';
import { BulkBar, RowBox, SelectAllBox, useSelection } from '@/components/bulk';
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

  const sel = useSelection(list.data?.filter(v => v.is_active).map(v => v.id) ?? []);
  const [disabling, setDisabling] = useState(false);
  const disable = async (ids: number[]) => {
    if (!confirm(ids.length === 1 ? 'Désactiver ce code ?' : `Désactiver ces ${ids.length} codes ?`)) return;
    setErr(''); setDisabling(true);
    try { await api('/credits/vouchers/disable', { method: 'POST', body: { ids } }); await list.reload(); }
    catch (e: any) { setErr(e.message); }
    finally { setDisabling(false); }
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
        {list.data && (<>
          <BulkBar sel={sel}>
            <button className="btn-danger" disabled={disabling} onClick={() => disable(sel.ids)}>
              {disabling ? 'Désactivation…' : 'Désactiver la sélection'}
            </button>
          </BulkBar>
          <div className="overflow-x-auto">
            <table className="table">
              <thead><tr><th className="w-10"><SelectAllBox sel={sel} disabled={!list.data.some(v => v.is_active)} /></th><th>Code</th><th>Crédits</th><th>Utilisations</th><th>Valable jusqu’au</th><th>Validité crédits</th><th>Note</th><th /></tr></thead>
              <tbody>
                {list.data.map(v => (
                  <tr key={v.id} className={v.is_active ? '' : 'opacity-50'}>
                    <td><RowBox sel={sel} id={v.id} label={`Sélectionner le code ${v.code}`} disabled={!v.is_active} /></td>
                    <td className="font-mono text-xs">{v.code}</td>
                    <td>{v.credits}</td>
                    <td>{v.redemption_count} / {v.max_redemptions}</td>
                    <td className="text-kx-muted">{v.valid_until ? fmtDate(v.valid_until, false) : '—'}</td>
                    <td className="text-kx-muted">{v.credit_validity_days ? `${v.credit_validity_days} j` : 'Illimitée'}</td>
                    <td className="text-kx-muted">{v.note || '—'}</td>
                    <td className="text-right">{v.is_active ? <button className="btn-danger" onClick={() => disable([v.id])}>Désactiver</button> : 'Inactif'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>)}
      </div>
    </section>
  );
}

export default function AdminCreditsPage() {
  return (
    <AdminOnly>
      <PageHeader title="Crédits & codes" sub="Codes crédit et attributions manuelles." />
      <VoucherAdmin />
    </AdminOnly>
  );
}
