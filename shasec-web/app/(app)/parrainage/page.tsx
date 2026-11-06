'use client';

import { useState } from 'react';
import { ErrorBox, Loading, PageHeader } from '@/components/ui';
import { api } from '@/lib/api';
import type { ReferralSummary } from '@/lib/types';
import { useAsync } from '@/lib/useAsync';

export default function ReferralPage() {
  const r = useAsync(() => api<ReferralSummary>('/referrals/me'), []);
  const [copied, setCopied] = useState('');

  const copy = async (text: string, what: string) => {
    try { await navigator.clipboard.writeText(text); setCopied(what); setTimeout(() => setCopied(''), 2000); } catch { /* ignore */ }
  };

  const d = r.data;
  const share = d ? `Je sécurise mes sites avec Kortex Defender : audit de sécurité de tes applications web et API, 3 scans offerts. Inscris-toi avec mon lien : ${d.link}` : '';

  return (
    <>
      <PageHeader title="Parrainage" sub="Invitez d’autres développeurs et gagnez des crédits sur chacun de leurs achats." />
      {r.loading && <Loading />}
      {r.error && <ErrorBox message={r.error} onRetry={r.reload} />}
      {d && (
        <div className="grid gap-6 lg:grid-cols-3">
          <section className="card space-y-4 lg:col-span-2">
            <h2 className="card-title mb-0">Votre lien</h2>
            <div className="flex flex-col gap-2 sm:flex-row">
              <input className="input font-mono text-sm" readOnly value={d.link} onFocus={e => e.currentTarget.select()} aria-label="Lien de parrainage" />
              <button className="btn shrink-0" onClick={() => copy(d.link, 'link')}>{copied === 'link' ? 'Copié ✓' : 'Copier le lien'}</button>
            </div>
            <p className="text-sm">
              Votre code : <b className="font-mono text-base">{d.code}</b>{' '}
              <button className="text-kx-muted underline underline-offset-4 hover:text-black" onClick={() => copy(d.code, 'code')}>{copied === 'code' ? 'copié ✓' : 'copier'}</button>
            </p>
            <a className="btn inline-block" target="_blank" rel="noopener noreferrer"
              href={`https://wa.me/?text=${encodeURIComponent(share)}`}>Partager sur WhatsApp</a>
            <div className="rounded-xl bg-kx-bg p-4 text-sm text-kx-muted">
              <p className="mb-1 font-semibold text-kx-text">Comment ça marche</p>
              <ol className="list-decimal space-y-1 pl-4">
                <li>Votre filleul crée son compte avec votre lien (ou saisit votre code lors de son premier achat).</li>
                <li>À chaque achat confirmé{d.first_purchase_only ? ' (premier achat uniquement)' : ''}, vous recevez <b>{d.reward_percent} %</b> des crédits achetés : 1 000 F → {10 * d.reward_percent / 100} crédits, 2 000 F → {20 * d.reward_percent / 100} crédits, 5 000 F → {60 * d.reward_percent / 100} crédits.</li>
                <li>Les crédits arrivent automatiquement, vous êtes notifié.</li>
              </ol>
            </div>
          </section>
          <section className="card space-y-3">
            <h2 className="card-title mb-0">Vos gains</h2>
            <p><span className="text-3xl font-extrabold">{d.credits_earned}</span> <span className="text-kx-muted">crédits gagnés</span></p>
            <p className="text-sm text-kx-muted">{d.referees} filleul{d.referees > 1 ? 's' : ''} inscrit{d.referees > 1 ? 's' : ''}</p>
          </section>
        </div>
      )}
    </>
  );
}
