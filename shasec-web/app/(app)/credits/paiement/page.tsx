'use client';

import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { Suspense, useEffect, useState } from 'react';
import { useSession } from '@/components/SessionProvider';
import { PageHeader, Spinner } from '@/components/ui';
import { api } from '@/lib/api';
import type { Payment } from '@/lib/types';

// Return page after the MoneyFusion checkout. The API verifies the payment with
// MoneyFusion on every poll, so this works even if the webhook is late or lost.
const POLL_MS = 4000;
const MAX_POLLS = 45; // ~3 minutes, then the background reconciler takes over

function PaymentReturn() {
  const ref = useSearchParams().get('ref') || '';
  const { refreshBalance } = useSession();
  const [p, setP] = useState<Payment | null>(null);
  const [err, setErr] = useState('');
  const [polls, setPolls] = useState(0);

  useEffect(() => {
    if (!ref) { setErr('Référence de paiement absente.'); return; }
    let stop = false;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async (n: number) => {
      try {
        const res = await api<Payment>(`/payments/${encodeURIComponent(ref)}`);
        if (stop) return;
        setP(res); setPolls(n);
        if (res.status === 'paid') { refreshBalance(); return; }
        if (res.status !== 'pending' || n >= MAX_POLLS) return;
      } catch (e: any) {
        if (!stop) setErr(e.message);
        return;
      }
      timer = setTimeout(() => tick(n + 1), POLL_MS);
    };
    tick(1);
    return () => { stop = true; clearTimeout(timer); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ref]);

  return (
    <>
      <PageHeader title="Paiement" sub="Confirmation de votre achat de crédits." />
      <section className="card max-w-xl space-y-4">
        {err && <p className="alert-err" role="alert">{err}</p>}
        {!err && !p && <p className="flex items-center gap-2 text-sm"><Spinner /> Vérification du paiement…</p>}
        {p?.status === 'paid' && (
          <p className="alert-ok" role="status">Paiement confirmé : <b>+{p.credits} crédits</b> ajoutés à votre compte. Merci !</p>
        )}
        {p?.status === 'pending' && polls < MAX_POLLS && (
          <p className="flex items-center gap-2 text-sm"><Spinner /> Paiement en attente de confirmation par l’opérateur… Ne fermez pas cette page.</p>
        )}
        {p?.status === 'pending' && polls >= MAX_POLLS && (
          <p className="alert-info">La confirmation prend plus de temps que prévu. Vos crédits seront ajoutés automatiquement dès réception (vous recevrez une notification).</p>
        )}
        {p?.status === 'failed' && <p className="alert-err">Le paiement a échoué ou a été annulé. Aucun montant n’a été crédité.</p>}
        {p?.status === 'mismatch' && <p className="alert-err">Le montant reçu ne correspond pas à l’offre. Contactez le support avec la référence <code>{p.x_id}</code>.</p>}
        {p?.status === 'expired' && <p className="alert-err">Ce paiement a expiré. Relancez un achat depuis la page Crédits.</p>}
        {p && <p className="text-xs text-kx-muted">Référence : <code>{p.x_id}</code> · {p.amount} FCFA · {p.credits} crédits</p>}
        <Link href="/credits" className="btn inline-block">Retour aux crédits</Link>
      </section>
    </>
  );
}

export default function PaymentReturnPage() {
  return <Suspense><PaymentReturn /></Suspense>;
}
