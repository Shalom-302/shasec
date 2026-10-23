'use client';

import Link from 'next/link';
import { IconArrow, IconCheck } from '@/components/icons';
import { useSession } from '@/components/SessionProvider';
import { ErrorBox, Loading, PageHeader, StatusBadge, TextLink } from '@/components/ui';
import { api } from '@/lib/api';
import { SEV_FR, SEV_ORDER } from '@/lib/findings';
import { fmtDate, hostOf, PROFILE_LABEL } from '@/lib/format';
import type { Finding, Page, Scan, Target } from '@/lib/types';
import { useAsync } from '@/lib/useAsync';

type Overview = {
  scans: Page<Scan>;
  targets: Page<Target>;
  lastCompleted: Scan | null;
  findings: Finding[] | null;
};

const SEV_TEXT: Record<string, string> = {
  critical: 'text-sev-critical', high: 'text-sev-high', medium: 'text-kx-text', low: 'text-kx-text', info: 'text-kx-muted',
};
const SEV_DOT: Record<string, string> = {
  critical: 'bg-sev-critical', high: 'bg-sev-high', medium: 'bg-sev-medium', low: 'bg-sev-low', info: 'bg-sev-info',
};

export default function DashboardPage() {
  const { balance, isAdmin } = useSession();
  const { data, error, loading, reload } = useAsync<Overview>(async () => {
    const [scans, targets, done] = await Promise.all([
      api<Page<Scan>>('/scans', { query: { page: 1, size: 5 } }),
      api<Page<Target>>('/targets', { query: { page: 1, size: 100 } }),
      api<Page<Scan>>('/scans', { query: { page: 1, size: 1, status: 'completed' } }),
    ]);
    const lastCompleted = done.items[0] ?? null;
    const findings = lastCompleted ? await api<Finding[]>(`/scans/${lastCompleted.id}/findings`) : null;
    return { scans, targets, lastCompleted, findings };
  }, []);

  const targetName = (id: number) => {
    const t = data?.targets.items.find(x => x.id === id);
    return t ? hostOf(t.url) : `Cible #${id}`;
  };

  const counts: Record<string, number> = {};
  (data?.findings || []).forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
  const verified = data?.targets.items.filter(t => t.is_authorized).length ?? 0;

  return (
    <>
      <PageHeader
        title="Vue d’ensemble"
        sub="L’état de sécurité de vos applications, en un coup d’œil."
        actions={<>
          <Link href="/targets" className="btn-ghost">Ajouter une application</Link>
          <Link href="/scans/new" className="btn">Lancer un scan</Link>
        </>}
      />

      {loading && <Loading />}
      {error && <ErrorBox message={error} onRetry={reload} />}

      {data && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Stat label="Scans réalisés" value={data.scans.total} />
            <Stat label="Applications" value={data.targets.total} hint={`${verified} autorisée${verified > 1 ? 's' : ''}`} />
            {isAdmin ? (
              <Stat label="Compte" value="Opérateur" />
            ) : (
              <>
                <Stat label="Crédits" value={balance?.credits ?? '—'} href="/credits" />
                <Stat label="Scans gratuits restants" value={balance?.free_scans ?? '—'} href="/credits" />
              </>
            )}
          </div>

          <Onboarding
            hasTarget={data.targets.total > 0}
            hasVerified={verified > 0}
            hasScan={data.scans.total > 0}
            firstTargetId={data.targets.items[0]?.id}
          />

          <section className="card">
            <div className="mb-3 flex items-center justify-between">
              <h2 className="card-title mb-0">Derniers scans</h2>
              <TextLink href="/scans">Tout l’historique</TextLink>
            </div>
            {data.scans.items.length === 0 ? (
              <p className="py-4 text-sm text-kx-muted">Aucun scan pour l’instant.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="table">
                  <thead><tr><th>Cible</th><th>Profil</th><th>Statut</th><th>Date</th><th /></tr></thead>
                  <tbody>
                    {data.scans.items.map(s => (
                      <tr key={s.id}>
                        <td className="font-medium">{targetName(s.target_id)}</td>
                        <td className="text-kx-muted">{PROFILE_LABEL[s.profile]?.name || s.profile}</td>
                        <td><StatusBadge status={s.status} /></td>
                        <td className="whitespace-nowrap text-kx-muted">{fmtDate(s.created_time)}</td>
                        <td className="text-right"><TextLink href={`/scans/${s.id}`}>Détail</TextLink></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section className="card">
            <h2 className="card-title">Vulnérabilités du dernier scan terminé</h2>
            {!data.lastCompleted ? (
              <p className="text-sm text-kx-muted">Aucun scan terminé pour l’instant.</p>
            ) : (
              <>
                <p className="mb-3 text-sm text-kx-muted">
                  {targetName(data.lastCompleted.target_id)} · {fmtDate(data.lastCompleted.completed_at)} ·{' '}
                  <TextLink href={`/scans/${data.lastCompleted.id}`}>voir le détail</TextLink>
                </p>
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
                  {SEV_ORDER.map(s => (
                    <div key={s} className="rounded-xl border border-kx-border bg-white p-4">
                      <div className="mb-2 flex items-center gap-2 text-xs font-medium uppercase tracking-wide text-kx-muted">
                        <span className={`h-2.5 w-2.5 rounded-full ${SEV_DOT[s]}`} />{SEV_FR[s]}
                      </div>
                      <div className={`font-display text-3xl font-semibold ${SEV_TEXT[s]}`}>{counts[s] || 0}</div>
                    </div>
                  ))}
                </div>
              </>
            )}
          </section>
        </div>
      )}
    </>
  );
}

function Stat({ label, value, hint, href }: { label: string; value: React.ReactNode; hint?: string; href?: string }) {
  const body = (
    <>
      <div className="text-sm text-kx-muted">{label}</div>
      <div className="mt-1 font-display text-3xl font-semibold">{value}</div>
      {hint && <div className="mt-1 text-xs text-kx-muted">{hint}</div>}
    </>
  );
  return href
    ? <Link href={href} className="card block transition hover:-translate-y-0.5 hover:border-kx-navy/20">{body}</Link>
    : <div className="card">{body}</div>;
}

function Onboarding({ hasTarget, hasVerified, hasScan, firstTargetId }: {
  hasTarget: boolean; hasVerified: boolean; hasScan: boolean; firstTargetId?: number;
}) {
  if (hasTarget && hasVerified && hasScan) return null;
  const steps = [
    { done: hasTarget, title: 'Ajoutez votre application', text: 'L’URL de votre site ou de votre API.', href: '/targets', cta: 'Ajouter' },
    { done: hasVerified, title: 'Autorisez le scan', text: 'Attestez votre autorisation et acceptez les conditions.', href: firstTargetId ? `/targets/${firstTargetId}` : '/targets', cta: 'Autoriser' },
    { done: hasScan, title: 'Lancez votre premier scan', text: 'Résultats en quelques minutes.', href: '/scans/new', cta: 'Scanner' },
  ];
  const current = steps.findIndex(s => !s.done);
  return (
    <section className="overflow-hidden rounded-2xl bg-kx-navy p-6 text-white shadow-card sm:p-8">
      <p className="text-xs font-semibold uppercase tracking-wider text-white/55">Bien démarrer</p>
      <h2 className="mt-1 font-display text-2xl font-semibold">Votre premier audit en 3 étapes</h2>
      <ol className="mt-6 grid gap-3 md:grid-cols-3">
        {steps.map((s, i) => (
          <li key={s.title} className={`rounded-xl p-4 ${i === current ? 'bg-white text-kx-text' : 'bg-white/5'}`}>
            <div className="flex items-center gap-3">
              <span className={`grid h-8 w-8 shrink-0 place-items-center rounded-full text-sm font-bold ${
                s.done ? 'bg-kx-teal text-white' : i === current ? 'bg-black text-white' : 'bg-white/10 text-white/60'}`}>
                {s.done ? <IconCheck className="h-4 w-4" /> : i + 1}
              </span>
              <span className="font-semibold">{s.title}</span>
            </div>
            <p className={`mt-2 text-sm ${i === current ? 'text-kx-muted' : 'text-white/60'}`}>{s.text}</p>
            {i === current && (
              <Link href={s.href} className="btn btn-sm mt-4">{s.cta} <IconArrow className="h-4 w-4" /></Link>
            )}
          </li>
        ))}
      </ol>
    </section>
  );
}
