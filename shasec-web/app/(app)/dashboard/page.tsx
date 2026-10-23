'use client';

import Link from 'next/link';
import { useSession } from '@/components/SessionProvider';
import { Empty, ErrorBox, Loading, PageHeader, StatusBadge, TextLink } from '@/components/ui';
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
  critical: 'text-sev-critical', high: 'text-sev-high', medium: 'text-sev-medium', low: 'text-sev-low', info: 'text-sev-info',
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
        title="Dashboard"
        sub="Vue d’ensemble de vos applications et de vos audits."
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
            <Stat label="Applications" value={data.targets.total} hint={`${verified} vérifiée${verified > 1 ? 's' : ''}`} />
            {isAdmin ? (
              <Stat label="Compte" value="Opérateur" />
            ) : (
              <>
                <Stat label="Crédits" value={balance?.credits ?? '—'} href="/credits" />
                <Stat label="Scans gratuits restants" value={balance?.free_scans ?? '—'} href="/credits" />
              </>
            )}
          </div>

          {data.targets.total === 0 && (
            <Empty
              title="Commencez par ajouter votre application"
              action={<Link href="/targets" className="btn">Ajouter une application</Link>}
            >
              Ajoutez l’URL de votre site ou API, prouvez que vous en êtes propriétaire, puis lancez votre premier scan.
            </Empty>
          )}

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
                    <div key={s} className="rounded-lg border border-kx-border bg-kx-panel2 p-3 text-center">
                      <div className={`text-2xl font-extrabold ${SEV_TEXT[s]}`}>{counts[s] || 0}</div>
                      <div className="text-[11px] uppercase tracking-wide text-kx-muted">{SEV_FR[s]}</div>
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
      <div className="text-2xl font-bold">{value}</div>
      <div className="text-xs text-kx-muted">{label}{hint ? ` · ${hint}` : ''}</div>
    </>
  );
  return href
    ? <Link href={href} className="card block hover:border-kx-accent">{body}</Link>
    : <div className="card">{body}</div>;
}
