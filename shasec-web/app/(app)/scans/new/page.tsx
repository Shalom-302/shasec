'use client';

import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { Suspense, useEffect, useState } from 'react';
import { useSession } from '@/components/SessionProvider';
import { Empty, ErrorBox, Loading, PageHeader, TextLink } from '@/components/ui';
import { api } from '@/lib/api';
import { PROFILE_LABEL } from '@/lib/format';
import type { CreditBalance, Page, Scan, ScanProfile, Target } from '@/lib/types';
import { useAsync } from '@/lib/useAsync';

type Billing = { kind: 'admin' | 'credits' | 'free' | 'blocked'; text: string };

/** Mirrors the server's rule (credit_service.charge_scan) for the preview only;
 * the API decides and debits. */
function previewBilling(b: CreditBalance | null, profile: ScanProfile): Billing {
  if (!b) return { kind: 'blocked', text: 'Solde indisponible' };
  if (b.is_admin) return { kind: 'admin', text: 'Compte opérateur : non facturé' };
  const cost = b.pricing[profile];
  if (b.credits >= cost) return { kind: 'credits', text: `${cost} crédit${cost > 1 ? 's' : ''} · rapport détaillé inclus` };
  if (b.free_scans > 0 && b.pricing.free_profiles.includes(profile)) {
    return { kind: 'free', text: '1 scan gratuit · résultats essentiels, sans rapport téléchargeable' };
  }
  if (b.free_scans > 0) return { kind: 'blocked', text: `Ce profil nécessite ${cost} crédits (non couvert par les scans gratuits).` };
  return { kind: 'blocked', text: `Crédits insuffisants : ce scan coûte ${cost} crédit${cost > 1 ? 's' : ''}.` };
}

function NewScan() {
  const router = useRouter();
  const params = useSearchParams();
  const { balance, refreshBalance } = useSession();
  const targets = useAsync(() => api<Page<Target>>('/targets', { query: { page: 1, size: 100 } }), []);
  const authorized = (targets.data?.items || []).filter(t => t.is_authorized);
  const [targetId, setTargetId] = useState(params.get('target') || '');
  const [profile, setProfile] = useState<ScanProfile>('standard');
  const [advanced, setAdvanced] = useState(false);
  // 'single' = this URL only; 'domain' = map subdomains, then audit the chosen ones.
  const [scope, setScope] = useState<'single' | 'domain'>('single');
  const [testToken, setTestToken] = useState('');
  const MAP_FEE = 2; // CREDITS_AUDIT_MAP (display only; server bills)
  const [scopeNote, setScopeNote] = useState('');
  const [step, setStep] = useState<'form' | 'confirm'>('form');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const SURCHARGE = 4; // CREDITS_ACTIVE_SURCHARGE (display only; server bills)

  useEffect(() => {
    if (!targetId && authorized.length === 1) setTargetId(String(authorized[0].id));
  }, [authorized, targetId]);

  const target = authorized.find(t => String(t.id) === targetId);
  const advCost = (balance?.pricing[profile] ?? 0) + SURCHARGE;
  const advBlocked = !balance?.is_admin && (balance?.credits ?? 0) < advCost;
  const perHost = (balance?.pricing[profile] ?? 0) + (advanced ? SURCHARGE : 0);
  const domainBlocked = !balance?.is_admin && (balance?.credits ?? 0) < MAP_FEE;
  const billing = scope === 'domain'
    ? (balance?.is_admin
        ? { kind: 'admin' as const, text: 'Compte opérateur : non facturé' }
        : domainBlocked
          ? { kind: 'blocked' as const, text: `Crédits insuffisants : la cartographie du domaine coûte ${MAP_FEE} crédits.` }
          : { kind: 'credits' as const, text: `${MAP_FEE} crédits pour découvrir les sous-domaines, puis ${perHost} crédit(s) par sous-domaine que vous choisirez d’auditer${advanced ? ' (tests actifs après validation d’un expert)' : ''}.` })
    : advanced
    ? (balance?.is_admin
        ? { kind: 'admin' as const, text: 'Compte opérateur : non facturé' }
        : advBlocked
          ? { kind: 'blocked' as const, text: `Crédits insuffisants : un audit avancé coûte ${advCost} crédits.` }
          : { kind: 'credits' as const, text: `${advCost} crédits · tests actifs, après validation d’un administrateur` })
    : previewBilling(balance, profile);

  const launch = async () => {
    if (busy || !target) return;
    setBusy(true); setErr('');
    try {
      if (scope === 'domain') {
        const audit = await api<Scan>('/scans/domain-audit', {
          method: 'POST', body: { target_id: target.id, profile, request_active: advanced,
            auth_token: advanced && testToken.trim() ? testToken.trim() : null, scope_note: scopeNote.trim() || null },
        });
        await refreshBalance();
        router.push(`/scans/${audit.id}`);
        return;
      }
      if (advanced) {
        const req = await api<Scan>('/scans/advanced', {
          method: 'POST', body: { target_id: target.id, profile, scope_note: scopeNote.trim() || null },
        });
        await refreshBalance();
        router.push(`/scans/${req.id}`);
        return;
      }
      const created = await api<Scan>('/scans', { method: 'POST', body: { target_id: target.id, profile } });
      try {
        await api<Scan>(`/scans/${created.id}/start`, { method: 'POST' });
      } catch (e) {
        await api('/scans', { method: 'DELETE', query: { pk: created.id } }).catch(() => null);
        throw e;
      }
      await refreshBalance();
      router.push(`/scans/${created.id}`);
    } catch (e: any) {
      setErr(e.message);
      setStep('form');
      setBusy(false);
    }
  };

  if (targets.loading) return <Loading />;
  if (targets.error) return <ErrorBox message={targets.error} onRetry={targets.reload} />;

  if (authorized.length === 0) {
    return (
      <>
        <PageHeader title="Lancer un scan" />
        <Empty title="Aucune application autorisée" action={<Link href="/targets" className="btn">Mes applications</Link>}>
          Ajoutez une application et attestez votre autorisation pour pouvoir la scanner.
        </Empty>
      </>
    );
  }

  return (
    <>
      <p className="mb-2 text-sm"><TextLink href="/scans">← Scans</TextLink></p>
      <PageHeader title="Lancer un scan" sub="Audit d’une application autorisée." />

      {step === 'form' ? (
        <div className="card max-w-2xl space-y-5">
          <div>
            <label className="label" htmlFor="s-target">Application</label>
            <select id="s-target" className="input" value={targetId} onChange={e => setTargetId(e.target.value)}>
              <option value="">Choisir…</option>
              {authorized.map(t => <option key={t.id} value={t.id}>{t.name} — {t.url}</option>)}
            </select>
            <p className="hint">Seules les applications autorisées au scan apparaissent ici.</p>
          </div>

          <fieldset>
            <legend className="label">Portée</legend>
            <div className="grid gap-2 sm:grid-cols-2">
              {([['single', 'Cette adresse', 'Audit de l’URL de l’application.'],
                ['domain', 'Tout le domaine', 'Découverte des sous-domaines, puis audit OWASP de chacun de ceux que vous choisissez.']] as const).map(([v, n, h]) => (
                <label key={v} className={`cursor-pointer rounded-lg border p-3 text-sm ${scope === v ? 'border-kx-accent bg-kx-panel2' : 'border-kx-border'}`}>
                  <input type="radio" name="scope" value={v} checked={scope === v} onChange={() => setScope(v)} className="sr-only" />
                  <span className="block font-semibold">{n}</span>
                  <span className="block text-xs text-kx-muted">{h}</span>
                </label>
              ))}
            </div>
          </fieldset>

          <fieldset>
            <legend className="label">Profil</legend>
            <div className="grid gap-2 sm:grid-cols-3">
              {(Object.keys(PROFILE_LABEL) as ScanProfile[]).map(p => {
                const cost = balance?.pricing[p];
                const freeOk = balance?.pricing.free_profiles.includes(p);
                return (
                  <label key={p} className={`cursor-pointer rounded-lg border p-3 text-sm ${profile === p ? 'border-kx-accent bg-kx-panel2' : 'border-kx-border'}`}>
                    <input type="radio" name="profile" value={p} checked={profile === p} onChange={() => setProfile(p)} className="sr-only" />
                    <span className="block font-semibold">{PROFILE_LABEL[p].name}</span>
                    <span className="block text-xs text-kx-muted">{PROFILE_LABEL[p].hint}</span>
                    {!balance?.is_admin && cost !== undefined && (
                      <span className="mt-2 block text-xs">{cost} crédit{cost > 1 ? 's' : ''}{freeOk ? ' · ou 1 scan gratuit' : ''}</span>
                    )}
                  </label>
                );
              })}
            </div>
          </fieldset>

          <div className="rounded-xl border border-kx-border p-4">
            <label className="flex cursor-pointer items-start gap-3">
              <input type="checkbox" className="mt-0.5 h-4 w-4 accent-black" checked={advanced} onChange={e => setAdvanced(e.target.checked)} />
              <span className="text-sm">
                <b>Audit avancé (tests actifs)</b> — recherche de failles XSS, CSRF, contrôle d’accès (BOLA/BFLA) et injections.
                <span className="mt-1 block text-xs text-kx-muted">
                  +{SURCHARGE} crédits. Soumis à la validation d’un administrateur avant de démarrer (vous êtes notifié de la décision).
                </span>
              </span>
            </label>
            {advanced && (
              <div className="mt-3">
                <label className="label" htmlFor="scope">Périmètre / justification (transmis à l’administrateur)</label>
                <textarea id="scope" className="input min-h-20" value={scopeNote} onChange={e => setScopeNote(e.target.value)}
                  maxLength={2000} placeholder="Ex. : application interne de mon entreprise, autorisation du responsable technique…" />
                <label className="label mt-3" htmlFor="token">Jeton d’un compte de test (facultatif, recommandé)</label>
                <input id="token" className="input font-mono text-xs" value={testToken} onChange={e => setTestToken(e.target.value)}
                  autoComplete="off" placeholder="eyJhbGciOi… (Bearer token d’un compte de test, jamais de production)" />
                <p className="hint">Sans compte de test, BOLA/IDOR et le contrôle d’accès (OWASP A01) ne peuvent pas être vérifiés. Le jeton n’est jamais enregistré en base et n’est utilisé que pendant l’audit.</p>
              </div>
            )}
          </div>

          <p className={billing.kind === 'blocked' ? 'alert-err' : 'alert-info'}>
            {billing.text}
            {billing.kind === 'blocked' && <> · <TextLink href="/credits">Obtenir des crédits</TextLink></>}
          </p>
          {err && <p className="alert-err" role="alert">{err}</p>}
          <button className="btn" disabled={!target || billing.kind === 'blocked'} onClick={() => setStep('confirm')}>
            Continuer
          </button>
        </div>
      ) : (
        <div className="card max-w-2xl space-y-4">
          <h2 className="card-title">Récapitulatif</h2>
          <dl className="space-y-2 text-sm">
            <div className="flex justify-between gap-4"><dt className="text-kx-muted">Application</dt><dd className="text-right">{target?.name}<br /><span className="font-mono text-xs text-kx-muted">{target?.url}</span></dd></div>
            <div className="flex justify-between gap-4"><dt className="text-kx-muted">Profil</dt><dd>{PROFILE_LABEL[profile].name}{advanced ? ' · audit avancé (tests actifs)' : ''}</dd></div>
            <div className="flex justify-between gap-4"><dt className="text-kx-muted">Portée</dt><dd>{scope === 'domain' ? 'Domaine complet (sous-domaines à choisir)' : 'Cette adresse'}</dd></div>
            <div className="flex justify-between gap-4"><dt className="text-kx-muted">Facturation</dt><dd className="text-right">{billing.text}</dd></div>
          </dl>
          {advanced && (
            <p className="alert-info">
              Votre demande sera transmise à un administrateur pour validation. Les crédits sont réservés dès maintenant
              et restitués si la demande est refusée.
            </p>
          )}
          <p className="text-xs text-kx-muted">
            En lançant ce scan, vous confirmez être propriétaire de cette application ou disposer d’une autorisation
            explicite pour l’auditer. En cas d’échec technique, les crédits sont restitués.
          </p>
          <div className="flex gap-2">
            <button className="btn" onClick={launch} disabled={busy}>{busy ? 'Envoi…' : scope === 'domain' ? 'Lancer la cartographie' : advanced ? 'Envoyer la demande' : 'Confirmer et lancer'}</button>
            <button className="btn-ghost" onClick={() => setStep('form')} disabled={busy}>Modifier</button>
          </div>
        </div>
      )}
    </>
  );
}

export default function NewScanPage() {
  return <Suspense fallback={<Loading />}><NewScan /></Suspense>;
}
