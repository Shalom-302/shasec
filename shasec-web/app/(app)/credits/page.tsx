'use client';

import { useState } from 'react';
import { useSession } from '@/components/SessionProvider';
import { ErrorBox, Loading, Pager, PageHeader } from '@/components/ui';
import { api } from '@/lib/api';
import { fmtDate } from '@/lib/format';
import type { CreditGrant, CreditTransaction, Page } from '@/lib/types';
import { useAsync } from '@/lib/useAsync';

const PLANS = [
  {
    name: 'Free', tag: 'Découverte', price: '0 FCFA', note: 'Les 3 scans gratuits sont utilisables une seule fois par compte.',
    items: ['3 scans de découverte gratuits par compte', 'Résultats essentiels dans le dashboard', 'Aucun rapport téléchargeable', 'Aucune alerte de surveillance'],
  },
  {
    name: 'Starter', tag: 'Paiement à l’utilisation', price: '2 000 FCFA', note: 'Les crédits achetés n’expirent pas.',
    items: ['20 crédits Kortex Security', 'Rapports de sécurité détaillés', 'Alertes sur les nouvelles vulnérabilités', 'Notifications dashboard et email'],
  },
  {
    name: 'Premium', tag: 'Offre recommandée', price: '5 000 FCFA / mois', highlight: true,
    note: 'Crédits mensuels valables pendant le cycle d’abonnement.',
    items: ['60 crédits mensuels', 'Surveillance planifiée d’un domaine', 'Rapports détaillés et historique', 'Alertes WhatsApp, email et dashboard', 'Priorité dans la file de scans'],
  },
  {
    name: 'Premium Plus', tag: 'Sur devis', price: 'Tarif personnalisé', note: 'Chaque devis précise le périmètre, les quotas et le support.',
    items: ['Plusieurs domaines ou applications', 'Quotas de crédits personnalisés', 'Audits avancés selon le périmètre autorisé', 'Collaboration multi-utilisateurs'],
  },
];

const SOURCE_LABEL: Record<string, string> = {
  signup: 'Offert à l’inscription', voucher: 'Code crédit', purchase: 'Achat', subscription: 'Abonnement', admin: 'Attribution',
};
const REASON_LABEL: Record<string, string> = { grant: 'Crédit', scan_debit: 'Scan', scan_refund: 'Remboursement' };

export default function CreditsPage() {
  const { balance, isAdmin, refreshBalance } = useSession();
  const [page, setPage] = useState(1);
  const grants = useAsync(() => api<CreditGrant[]>('/credits/me/grants'), []);
  const txs = useAsync(() => api<Page<CreditTransaction>>('/credits/me/transactions', { query: { page, size: 15 } }), [page]);

  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const redeem = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setMsg(null);
    try {
      const g = await api<CreditGrant>('/credits/redeem', { method: 'POST', body: { code: code.trim() } });
      setMsg({ ok: true, text: `${g.amount} crédit${g.amount > 1 ? 's' : ''} ajouté${g.amount > 1 ? 's' : ''}${g.expires_at ? `, valables jusqu’au ${fmtDate(g.expires_at, false)}` : ''}.` });
      setCode('');
      await Promise.all([refreshBalance(), grants.reload(), txs.reload()]);
    } catch (e: any) {
      setMsg({ ok: false, text: e.message });
    } finally { setBusy(false); }
  };

  return (
    <>
      <PageHeader title="Crédits & offres" sub="Votre solde, vos codes et l’historique de consommation." />

      <div className="grid gap-6 lg:grid-cols-3">
        <section className="card">
          <h2 className="card-title">Solde</h2>
          {!balance ? <Loading /> : isAdmin ? (
            <p className="text-sm">Compte opérateur : scans non facturés.</p>
          ) : (
            <div className="space-y-2">
              <p><span className="text-3xl font-extrabold">{balance.credits}</span> <span className="text-kx-muted">crédit{balance.credits > 1 ? 's' : ''}</span></p>
              <p className="text-sm text-kx-muted">{balance.free_scans} scan{balance.free_scans > 1 ? 's' : ''} de découverte restant{balance.free_scans > 1 ? 's' : ''}</p>
              {balance.next_expiry && <p className="text-xs text-amber-300">Des crédits expirent le {fmtDate(balance.next_expiry, false)}</p>}
              <p className="pt-2 text-xs text-kx-muted">
                Coût d’un scan : rapide {balance.pricing.fast} · standard {balance.pricing.standard} · approfondi {balance.pricing.deep} crédit(s).
              </p>
            </div>
          )}
        </section>

        <form onSubmit={redeem} className="card space-y-3 lg:col-span-2">
          <h2 className="card-title mb-0">Utiliser un code crédit</h2>
          <div className="flex flex-col gap-2 sm:flex-row">
            <label htmlFor="code" className="sr-only">Code</label>
            <input id="code" className="input font-mono uppercase" placeholder="KX-XXXX-XXXX-XXXX" value={code} onChange={e => setCode(e.target.value)} autoComplete="off" />
            <button className="btn shrink-0" disabled={busy || code.trim().length < 4}>{busy ? 'Validation…' : 'Valider'}</button>
          </div>
          {msg && <p className={msg.ok ? 'alert-ok' : 'alert-err'} role="status">{msg.text}</p>}
        </form>
      </div>

      <section className="mt-8">
        <h2 className="mb-1 text-lg font-bold">Offres</h2>
        <p className="mb-4 alert-info">Paiement en ligne bientôt disponible. En attendant, contactez-nous pour obtenir un code crédit.</p>
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {PLANS.map(p => (
            <div key={p.name} className={`card flex flex-col ${p.highlight ? 'border-kx-accent' : ''}`}>
              <p className="text-xs uppercase tracking-wide text-kx-muted">{p.tag}</p>
              <h3 className="text-lg font-bold">{p.name}</h3>
              <p className="mb-3 text-xl font-extrabold">{p.price}</p>
              <ul className="mb-4 list-disc space-y-1 pl-4 text-sm text-kx-muted">{p.items.map(i => <li key={i}>{i}</li>)}</ul>
              <p className="mt-auto text-xs text-kx-muted">{p.note}</p>
            </div>
          ))}
        </div>
      </section>

      {!isAdmin && (
        <section className="card mt-8">
          <h2 className="card-title">Crédits actifs</h2>
          {grants.loading && <Loading />}
          {grants.error && <ErrorBox message={grants.error} onRetry={grants.reload} />}
          {grants.data && grants.data.length === 0 && <p className="text-sm text-kx-muted">Aucun crédit actif.</p>}
          {grants.data && grants.data.length > 0 && (
            <div className="overflow-x-auto">
              <table className="table">
                <thead><tr><th>Origine</th><th>Type</th><th>Restant</th><th>Expire</th></tr></thead>
                <tbody>
                  {grants.data.map(g => (
                    <tr key={g.id}>
                      <td>{SOURCE_LABEL[g.source] || g.source}{g.note && g.source !== 'signup' ? <span className="text-kx-muted"> · {g.note}</span> : null}</td>
                      <td className="text-kx-muted">{g.kind === 'free_scan' ? 'Scans gratuits' : 'Crédits'}</td>
                      <td>{g.remaining} / {g.amount}</td>
                      <td className="text-kx-muted">{g.expires_at ? fmtDate(g.expires_at, false) : 'Jamais'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      <section className="card mt-6">
        <h2 className="card-title">Historique</h2>
        {txs.loading && <Loading />}
        {txs.error && <ErrorBox message={txs.error} onRetry={txs.reload} />}
        {txs.data && txs.data.items.length === 0 && <p className="text-sm text-kx-muted">Aucun mouvement.</p>}
        {txs.data && txs.data.items.length > 0 && (
          <div className="overflow-x-auto">
            <table className="table">
              <thead><tr><th>Date</th><th>Opération</th><th>Détail</th><th className="text-right">Mouvement</th></tr></thead>
              <tbody>
                {txs.data.items.map(t => (
                  <tr key={t.id}>
                    <td className="whitespace-nowrap text-kx-muted">{fmtDate(t.created_time)}</td>
                    <td>{REASON_LABEL[t.reason] || t.reason}</td>
                    <td className="text-kx-muted">{t.scan_id ? `Scan #${t.scan_id}` : t.note || '—'}</td>
                    <td className={`text-right font-mono ${t.delta > 0 ? 'text-green-300' : 'text-kx-text'}`}>
                      {t.delta > 0 ? '+' : ''}{t.delta} {t.kind === 'free_scan' ? 'scan gratuit' : 'cr.'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {txs.data && <Pager page={page} totalPages={txs.data.total_pages} onPage={setPage} />}
      </section>
    </>
  );
}
