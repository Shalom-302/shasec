'use client';

import { useState } from 'react';
import { ErrorBox, Loading, PageHeader } from '@/components/ui';
import { api } from '@/lib/api';
import { fmtDate } from '@/lib/format';
import type { AffiliateSummary } from '@/lib/types';
import { useAsync } from '@/lib/useAsync';

const METHODS = [['wave', 'Wave'], ['orange', 'Orange Money'], ['mtn', 'MTN MoMo'], ['moov', 'Moov Money']] as const;
const C_STATUS: Record<string, { label: string; cls: string }> = {
  pending: { label: 'En attente', cls: 'bg-amber-50 text-amber-800' },
  available: { label: 'Validée · à verser', cls: 'bg-indigo-50 text-indigo-700' },
  paid: { label: 'Versée', cls: 'bg-teal-50 text-teal-800' },
  rejected: { label: 'Refusée', cls: 'bg-red-50 text-red-700' },
};
const fcfa = (n: number) => `${n.toLocaleString('fr-FR')} F`;

function Terms({ d }: { d: AffiliateSummary['defaults'] }) {
  return (
    <ul className="list-disc space-y-1 pl-5 text-sm text-kx-muted">
      <li>Vos filleuls tapent votre code au paiement et obtiennent une réduction ; vous touchez une commission en argent sur chacun de leurs achats pendant {d.months} mois.</li>
      <li>Chaque commission reste <b>en attente {d.hold_days} jours</b> et n’est validée que si le filleul utilise réellement ses crédits.</li>
      <li>Les versements sont faits <b>manuellement par Kortex</b> sur le numéro Mobile Money indiqué, à votre nom, à partir de {fcfa(d.min_payout)}.</li>
      <li>Interdits : utiliser son propre code, créer des comptes fictifs, payer avec son propre numéro. Toute fraude annule les commissions et le compte parrain.</li>
      <li>Kortex peut refuser, suspendre ou annuler une commission en cas de doute. Les crédits ne sont jamais convertibles en argent.</li>
    </ul>
  );
}

function ApplyForm({ d, onDone }: { d: AffiliateSummary['defaults']; onDone: () => void }) {
  const [code, setCode] = useState('');
  const [name, setName] = useState('');
  const [phone, setPhone] = useState('');
  const [method, setMethod] = useState('wave');
  const [accept, setAccept] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr('');
    const c = code.trim().toUpperCase();
    if (!/^[A-Z0-9]{4,12}$/.test(c)) return setErr('Code : 4 à 12 lettres ou chiffres, sans espace (ex. SHALOM).');
    if (name.trim().length < 3) return setErr('Indiquez votre nom complet, tel qu’il apparaît sur votre compte Mobile Money.');
    if (!/^\+?\d[\d\s]{7,}$/.test(phone.trim())) return setErr('Numéro de versement invalide.');
    if (!accept) return setErr('Acceptez les conditions du programme.');
    setBusy(true);
    try {
      await api('/affiliates/apply', { method: 'POST', body: { code: c, full_name: name.trim(), payout_phone: phone.trim(), payout_method: method, accept_terms: true } });
      onDone();
    } catch (e: any) { setErr(e.message); setBusy(false); }
  };

  return (
    <form onSubmit={submit} className="card max-w-2xl space-y-4" noValidate>
      <h2 className="card-title mb-0">Devenir parrain Kortex Defender</h2>
      <p className="text-sm">
        Vos filleuls obtiennent <b>-{d.discount_pct ?? 30} %</b> avec votre code, et vous touchez <b>{d.commission_pct ?? 20} % du prix</b> de chacun de leurs achats
        (ex. pack à 1 000 F : le filleul paie {1000 - (1000 * (d.discount_pct ?? 30)) / 100} F, vous gagnez {(1000 * (d.commission_pct ?? 20)) / 100} F).
      </p>
      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <label className="label" htmlFor="a-code">Votre code promo souhaité</label>
          <input id="a-code" className="input font-mono uppercase" maxLength={12} placeholder="SHALOM" value={code} onChange={e => setCode(e.target.value)} autoComplete="off" />
        </div>
        <div>
          <label className="label" htmlFor="a-name">Nom complet (titulaire Mobile Money)</label>
          <input id="a-name" className="input" maxLength={120} value={name} onChange={e => setName(e.target.value)} autoComplete="name" />
        </div>
        <div>
          <label className="label" htmlFor="a-method">Versement par</label>
          <select id="a-method" className="input" value={method} onChange={e => setMethod(e.target.value)}>
            {METHODS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </div>
        <div>
          <label className="label" htmlFor="a-phone">Numéro de versement</label>
          <input id="a-phone" className="input" type="tel" inputMode="tel" placeholder="07 12 34 56 78" value={phone} onChange={e => setPhone(e.target.value)} autoComplete="tel" />
        </div>
      </div>
      <div className="rounded-xl border border-kx-border p-4">
        <p className="mb-2 text-sm font-semibold">Conditions du programme</p>
        <Terms d={d} />
        <label className="mt-3 flex cursor-pointer items-start gap-2.5 text-sm">
          <input type="checkbox" className="mt-0.5 h-4 w-4 accent-black" checked={accept} onChange={e => setAccept(e.target.checked)} />
          <span>J’accepte ces conditions et je certifie que le numéro de versement est à mon nom.</span>
        </label>
      </div>
      {err && <p className="alert-err" role="alert">{err}</p>}
      <button className="btn" disabled={busy}>{busy ? 'Envoi…' : 'Envoyer ma demande'}</button>
      <p className="text-xs text-kx-muted">Votre demande est validée manuellement par l’équipe Kortex.</p>
    </form>
  );
}

export default function AffiliatePage() {
  const r = useAsync(() => api<AffiliateSummary>('/affiliates/me'), []);
  const [copied, setCopied] = useState('');
  const copy = async (t: string, w: string) => { try { await navigator.clipboard.writeText(t); setCopied(w); setTimeout(() => setCopied(''), 2000); } catch { /* ignore */ } };

  if (r.loading) return <Loading />;
  if (r.error) return <ErrorBox message={r.error} onRetry={r.reload} />;
  const d = r.data!;
  const a = d.affiliate;

  return (
    <>
      <PageHeader title="Parrainage" sub="Faites connaître Kortex Defender et gagnez une commission sur les achats de vos filleuls." />
      {!a && <ApplyForm d={d.defaults} onDone={r.reload} />}
      {a && a.status === 'pending' && (
        <section className="card max-w-2xl space-y-2">
          <h2 className="card-title mb-0">Demande en cours de validation</h2>
          <p className="text-sm">Votre code <b className="font-mono">{a.code}</b> sera actif dès validation par l’équipe Kortex. Vous serez notifié.</p>
          <p className="text-sm text-kx-muted">Versements : {a.payout_method} · {a.payout_phone} · {a.full_name}</p>
        </section>
      )}
      {a && (a.status === 'suspended' || a.status === 'rejected') && (
        <p className="alert-err max-w-2xl">Votre code parrain est {a.status === 'suspended' ? 'suspendu' : 'refusé'}. Contactez l’équipe Kortex pour plus d’informations.</p>
      )}
      {a && a.status === 'approved' && (
        <div className="space-y-6">
          <div className="grid gap-6 lg:grid-cols-3">
            <section className="card space-y-3 lg:col-span-2">
              <h2 className="card-title mb-0">Votre code promo</h2>
              <div className="flex flex-wrap items-center gap-3">
                <span className="rounded-xl bg-black px-4 py-2 font-mono text-2xl font-bold tracking-widest text-white">{a.code}</span>
                <button className="btn-ghost" onClick={() => copy(a.code, 'code')}>{copied === 'code' ? 'Copié ✓' : 'Copier le code'}</button>
              </div>
              <p className="text-sm">Vos filleuls ont <b>-{a.discount_pct} %</b> · vous touchez <b>{a.commission_pct} %</b> du prix de chaque achat.</p>
              <div className="flex flex-col gap-2 sm:flex-row">
                <input className="input font-mono text-xs" readOnly value={a.link} onFocus={e => e.currentTarget.select()} aria-label="Lien" />
                <button className="btn-ghost shrink-0" onClick={() => copy(a.link, 'link')}>{copied === 'link' ? 'Copié ✓' : 'Copier le lien'}</button>
              </div>
              <a className="btn inline-flex" target="_blank" rel="noopener noreferrer"
                href={`https://wa.me/?text=${encodeURIComponent(`Audite la sécurité de ton site avec Kortex Defender : -${a.discount_pct} % avec mon code ${a.code} → ${a.link}`)}`}>
                Partager sur WhatsApp
              </a>
            </section>
            <section className="card space-y-2">
              <h2 className="card-title mb-0">Vos gains</h2>
              <p><span className="text-2xl font-extrabold">{fcfa(d.totals?.paid ?? 0)}</span> <span className="text-sm text-kx-muted">versés</span></p>
              <p className="text-sm">{fcfa(d.totals?.available ?? 0)} validés, à verser</p>
              <p className="text-sm text-kx-muted">{fcfa(d.totals?.pending ?? 0)} en attente</p>
              <p className="text-sm text-kx-muted">{d.referees ?? 0} filleul(s)</p>
              <p className="pt-1 text-xs text-kx-muted">Versement {a.payout_method} sur {a.payout_phone}, à partir de {fcfa(d.defaults.min_payout)}.</p>
            </section>
          </div>
          <section className="card">
            <h2 className="card-title">Commissions</h2>
            {(d.commissions?.length ?? 0) === 0 && <p className="text-sm text-kx-muted">Aucune commission pour l’instant.</p>}
            {(d.commissions?.length ?? 0) > 0 && (
              <div className="overflow-x-auto">
                <table className="table">
                  <thead><tr><th>Date</th><th>Montant</th><th>Statut</th><th>Info</th></tr></thead>
                  <tbody>
                    {d.commissions!.map(c => (
                      <tr key={c.id}>
                        <td className="whitespace-nowrap text-kx-muted">{fmtDate(c.created_time, false)}</td>
                        <td className="font-semibold">{fcfa(c.amount)}</td>
                        <td><span className={`rounded-full px-2 py-0.5 text-xs font-semibold ${C_STATUS[c.status]?.cls || ''}`}>{C_STATUS[c.status]?.label || c.status}</span></td>
                        <td className="text-xs text-kx-muted">
                          {c.status === 'pending' && c.available_at ? `validable à partir du ${fmtDate(c.available_at, false)}` : c.paid_at ? `versée le ${fmtDate(c.paid_at, false)}` : ''}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
          <section className="card"><h2 className="card-title">Rappel des conditions</h2><Terms d={d.defaults} /></section>
        </div>
      )}
    </>
  );
}
