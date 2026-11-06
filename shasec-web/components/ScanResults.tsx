'use client';

// Client-facing results of a scan: verdict, OWASP Top 10 score and coverage,
// verified proofs, subdomains. Built from GET /scans/{id}/summary.
import { ErrorBox, Loading, SeverityBadge } from '@/components/ui';
import { api } from '@/lib/api';
import { useAsync } from '@/lib/useAsync';

type Item = { title: string; severity: string; verified: boolean; kind: 'proof' | 'finding' };
type Coverage = {
  code: string; name: string; state: 'vulnerable' | 'tested' | 'partial' | 'not_tested';
  findings: number; proofs: number; confirmed: number; note: string; worst: string | null; items: Item[];
};
type Host = {
  host: string; kind?: string | null; title?: string | null; scanned: boolean;
  counts: Record<string, number>; top: string[]; third_party?: string | null;
  owasp?: { score: number; tested: number; partial: number; vulnerable: number; untested: number };
  coverage?: { code: string; state: Coverage['state']; worst: string | null; note: string }[];
};
type Proof = { id: number; module: string; title: string; severity: string; confirmed: boolean; owasp?: string | null; impact?: string | null; request?: string; response?: string };
export type ScanSummary = {
  verdict: { level: string; text: string };
  counts: Record<'critical' | 'high' | 'medium' | 'low', number>;
  informational: number; verified: number; active: boolean; profile: string;
  owasp: { score: number; tested: number; partial: number; vulnerable: number; untested: number };
  coverage: Coverage[]; hosts: Host[]; subdomains_scanned: boolean;
  top: { kind: string; title: string; severity: string; verified: boolean; owasp?: string | null; detail?: string | null }[];
  proofs: Proof[]; skipped: { module: string; reason: string }[];
};

const VERDICT_CLS: Record<string, string> = {
  critical: 'border-red-300 bg-red-50 text-red-900', high: 'border-orange-300 bg-orange-50 text-orange-900',
  medium: 'border-amber-300 bg-amber-50 text-amber-900', low: 'border-teal-300 bg-teal-50 text-teal-900',
  none: 'border-teal-300 bg-teal-50 text-teal-900',
};
const STATE: Record<Coverage['state'], { label: string; cls: string; icon: string }> = {
  vulnerable: { label: 'Vulnérable', cls: 'bg-red-50 text-red-700', icon: '✗' },
  tested: { label: 'Sûr (testé)', cls: 'bg-teal-50 text-teal-800', icon: '✓' },
  partial: { label: 'Partiellement testé', cls: 'bg-amber-50 text-amber-800', icon: '◐' },
  not_tested: { label: 'Non testé', cls: 'bg-kx-panel2 text-kx-muted', icon: '–' },
};
const SEV_LABEL: Record<string, string> = { critical: 'Critiques', high: 'Élevées', medium: 'Moyennes', low: 'Faibles' };

function scoreColor(n: number) {
  return n >= 80 ? 'text-teal-700' : n >= 50 ? 'text-amber-700' : 'text-red-700';
}

export function ScanResults({ scanId }: { scanId: number | string }) {
  const s = useAsync(() => api<ScanSummary>(`/scans/${scanId}/summary`), [scanId]);
  if (s.loading) return <section className="card mt-6"><Loading label="Analyse des résultats…" /></section>;
  if (s.error) return <section className="card mt-6"><ErrorBox message={s.error} onRetry={s.reload} /></section>;
  const d = s.data!;
  const total = d.counts.critical + d.counts.high + d.counts.medium + d.counts.low;

  return (
    <>
      {/* Verdict + OWASP score */}
      <section className={`mt-6 rounded-2xl border p-5 ${VERDICT_CLS[d.verdict.level] || VERDICT_CLS.none}`}>
        <div className="grid gap-5 md:grid-cols-[1fr_auto] md:items-center">
          <div>
            <p className="text-xs font-semibold uppercase tracking-wide opacity-70">Verdict</p>
            <p className="mt-1 font-display text-xl font-semibold">{d.verdict.text}</p>
            <div className="mt-3 flex flex-wrap gap-2 text-sm">
              {(['critical', 'high', 'medium', 'low'] as const).map(k => (
                <span key={k} className="rounded-full bg-white/70 px-3 py-1"><b>{d.counts[k]}</b> {SEV_LABEL[k]}</span>
              ))}
              <span className="rounded-full bg-white/70 px-3 py-1"><b>{d.verified}</b> vérifiée{d.verified > 1 ? 's' : ''} par preuve</span>
              <span className="rounded-full bg-white/40 px-3 py-1 opacity-80">{d.informational} info. (inventaire)</span>
            </div>
          </div>
          <div className="rounded-2xl bg-white/80 px-6 py-4 text-center">
            <p className="text-xs font-semibold uppercase tracking-wide text-kx-muted">Score OWASP Top 10</p>
            <p className={`font-display text-5xl font-bold ${scoreColor(d.owasp.score)}`}>{d.owasp.score}<span className="text-2xl">%</span></p>
            <p className="text-xs text-kx-muted">{d.owasp.tested - d.owasp.vulnerable} sûre(s) · {d.owasp.vulnerable} vulnérable(s) · {d.owasp.partial} partielle(s) · {d.owasp.untested} non testée(s)</p>
          </div>
        </div>
        {d.owasp.untested + d.owasp.partial > 0 && (
          <p className="mt-3 text-xs opacity-80">
            Une catégorie non testée compte 0 : on ne déclare jamais « sûr » ce qui n’a pas été vérifié.
            {!d.active ? ' Un audit avancé (tests actifs) augmente la couverture.' : ' Pour couvrir BOLA/IDOR et l’authentification, fournissez des comptes de test.'}
          </p>
        )}
      </section>

      {/* Priorities */}
      {total > 0 && (
        <section className="card mt-6">
          <h2 className="card-title">À corriger en priorité</h2>
          <ol className="space-y-2">
            {d.top.map((t, i) => (
              <li key={i} className="flex items-start gap-3 text-sm">
                <SeverityBadge severity={t.severity} />
                <div className="min-w-0 flex-1">
                  <p className="font-medium">{t.title}{t.verified && <span className="ml-2 rounded-full bg-red-600 px-2 py-0.5 text-[10px] font-bold uppercase text-white">Vérifiée</span>}</p>
                  {t.detail && <p className="line-clamp-2 text-kx-muted">{t.detail}</p>}
                </div>
                {t.owasp && <span className="shrink-0 rounded-full bg-kx-panel2 px-2 py-0.5 text-[11px]">{t.owasp}</span>}
              </li>
            ))}
          </ol>
        </section>
      )}

      {/* OWASP coverage */}
      <section className="card mt-6">
        <h2 className="card-title">Couverture OWASP Top 10 (2021)</h2>
        <div className="space-y-2">
          {d.coverage.map(c => (
            <details key={c.code} className="rounded-lg border border-kx-border" open={c.state === 'vulnerable' && (c.worst === 'critical' || c.worst === 'high')}>
              <summary className="flex cursor-pointer flex-wrap items-center gap-3 px-3 py-2.5">
                <span className="w-10 font-mono text-sm font-semibold">{c.code}</span>
                <span className="flex-1 text-sm font-medium">{c.name}</span>
                {c.worst && <SeverityBadge severity={c.worst} />}
                <span className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${STATE[c.state].cls}`}>{STATE[c.state].icon} {STATE[c.state].label}</span>
              </summary>
              <div className="space-y-2 border-t border-kx-border px-3 py-3 text-sm">
                <p className="text-kx-muted">{c.note}</p>
                {c.items.length > 0 && (
                  <ul className="space-y-1">
                    {c.items.map((it, i) => (
                      <li key={i} className="flex items-center gap-2">
                        <SeverityBadge severity={it.severity} />
                        <span>{it.title}</span>
                        {it.verified && <span className="rounded-full bg-red-600 px-2 py-0.5 text-[10px] font-bold uppercase text-white">Vérifiée</span>}
                        {it.kind === 'proof' && !it.verified && <span className="text-xs text-kx-muted">(test actif)</span>}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </details>
          ))}
        </div>
      </section>

      {/* Proofs */}
      {d.active && (
        <section className="card mt-6">
          <h2 className="card-title">Tests actifs : preuves d’exploitation</h2>
          {d.proofs.length === 0 && <p className="text-sm text-kx-muted">Aucune faille exploitable démontrée par les tests actifs.</p>}
          <div className="space-y-2">
            {d.proofs.map(p => (
              <details key={p.id} className="rounded-lg border border-kx-border">
                <summary className="flex cursor-pointer items-center gap-3 px-3 py-2.5">
                  <SeverityBadge severity={p.severity} />
                  <span className="flex-1 font-medium">{p.title}</span>
                  {p.confirmed
                    ? <span className="rounded-full bg-red-600 px-2 py-0.5 text-[10px] font-bold uppercase text-white">Vérifiée</span>
                    : <span className="text-xs text-kx-muted">à confirmer</span>}
                  <span className="hidden rounded-full border border-kx-border px-2 py-0.5 text-[11px] text-kx-muted sm:inline">{p.module}</span>
                </summary>
                <div className="space-y-2 border-t border-kx-border px-3 py-3 text-sm">
                  {p.impact && <p><b>Impact démontré :</b> <span className="text-kx-muted">{p.impact}</span></p>}
                  {p.request && <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-kx-panel2 p-2 font-mono text-xs">{p.request}</pre>}
                  {p.response && <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-kx-panel2 p-2 font-mono text-xs">{p.response}</pre>}
                </div>
              </details>
            ))}
          </div>
          {d.skipped.length > 0 && (
            <div className="mt-4 rounded-xl bg-amber-50 p-3 text-sm text-amber-900">
              <p className="font-semibold">Tests non exécutés</p>
              <ul className="mt-1 list-disc pl-5">{d.skipped.map(x => <li key={x.module}><b>{x.module}</b> : {x.reason}</li>)}</ul>
            </div>
          )}
        </section>
      )}

      {/* Per-subdomain OWASP matrix (domain audit) */}
      {d.hosts.some(h => h.coverage) && (
        <section className="card mt-6">
          <h2 className="card-title">OWASP Top 10 par sous-domaine</h2>
          <div className="overflow-x-auto">
            <table className="table text-center">
              <thead>
                <tr>
                  <th className="text-left">Sous-domaine</th>
                  <th>Score</th>
                  {d.coverage.map(c => <th key={c.code} title={c.name}>{c.code}</th>)}
                </tr>
              </thead>
              <tbody>
                {d.hosts.filter(h => h.coverage).map(h => (
                  <tr key={h.host}>
                    <td className="text-left font-mono text-xs">{h.host}</td>
                    <td className={`font-bold ${scoreColor(h.owasp!.score)}`}>{h.owasp!.score}%</td>
                    {h.coverage!.map(c => (
                      <td key={c.code} title={`${c.code} — ${STATE[c.state].label}. ${c.note}`}>
                        <span className={`inline-block min-w-8 rounded-md px-1.5 py-0.5 text-xs font-semibold ${
                          c.state === 'vulnerable' && (c.worst === 'critical' || c.worst === 'high') ? 'bg-red-600 text-white' : STATE[c.state].cls}`}>
                          {STATE[c.state].icon}
                        </span>
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-2 text-xs text-kx-muted">✗ vulnérable (rouge plein : critique/élevée) · ✓ testé, rien trouvé · ◐ partiellement testé · – non testé. Survolez une case pour le détail.</p>
        </section>
      )}

      {/* Subdomains */}
      <section className="card mt-6">
        <h2 className="card-title">Sous-domaines découverts · {d.hosts.length}</h2>
        {!d.subdomains_scanned && d.hosts.length > 1 && (
          <p className="alert-info mb-3">Ce scan a analysé l’adresse principale. Les sous-domaines ci-dessous ont été découverts mais pas tous audités : un audit de domaine complet les analyse un par un.</p>
        )}
        <div className="overflow-x-auto">
          <table className="table">
            <thead><tr><th>Hôte</th><th>Type</th><th>Audité</th><th>Failles</th></tr></thead>
            <tbody>
              {d.hosts.map(h => (
                <tr key={h.host}>
                  <td className="font-mono text-xs">{h.host}{h.title && <span className="block font-sans text-kx-muted">{h.title}</span>}</td>
                  <td className="text-kx-muted">{h.kind === 'api' ? 'API' : h.kind === 'website' || h.kind === 'frontend' ? 'Site' : h.kind || '—'}{h.third_party ? ` · ${h.third_party}` : ''}</td>
                  <td>{h.scanned ? '✓' : <span className="text-kx-muted">non</span>}</td>
                  <td>
                    {Object.keys(h.counts).length === 0
                      ? <span className="text-kx-muted">{h.scanned ? 'aucune' : '—'}</span>
                      : <span className="flex flex-wrap gap-1">{Object.entries(h.counts).map(([k, v]) => <span key={k} className="flex items-center gap-1"><SeverityBadge severity={k} /> {v}</span>)}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
