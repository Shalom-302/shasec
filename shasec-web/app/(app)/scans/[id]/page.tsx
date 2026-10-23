'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { useEffect, useMemo, useRef, useState } from 'react';
import { ScanProgress } from '@/components/ScanProgress';
import { ErrorBox, Loading, PageHeader, SeverityBadge, StatusBadge, TextLink } from '@/components/ui';
import { api, download } from '@/lib/api';
import { groupFindings, SEV_FR, SEV_ORDER } from '@/lib/findings';
import { BILLING_LABEL, fmtDate, isActive, isTerminal, PROFILE_LABEL } from '@/lib/format';
import { notifyScanFinished } from '@/lib/notify';
import type { AIAnalysis, Finding, Progress, Scan, Target } from '@/lib/types';
import { useAsync } from '@/lib/useAsync';

const POLL_RUNNING_MS = 3000;
const POLL_QUEUED_MS = 6000;

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const scan = useAsync(() => api<Scan>(`/scans/${id}`), [id]);
  const target = useAsync(
    () => (scan.data ? api<Target>(`/targets/${scan.data.target_id}`) : Promise.resolve(null)),
    [scan.data?.target_id],
  );
  const [progress, setProgress] = useState<Progress | null>(null);
  const [pollErr, setPollErr] = useState('');
  // The DB status (returned with the progress) is authoritative; the event log adds detail.
  const status = progress?.db_status || (progress && isTerminal(progress.status) ? progress.status : scan.data?.status);
  const done = isTerminal(status);
  const lastStatus = useRef<string | undefined>(undefined);

  // Status transitions: refresh the scan row (started_at…), notify when it ends.
  useEffect(() => {
    const prev = lastStatus.current;
    lastStatus.current = status;
    if (!prev || prev === status || !scan.data) return;
    scan.reload();
    if (isActive(prev) && isTerminal(status)) notifyScanFinished(scan.data.id, status!, target.data?.name);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status]);

  // Poll progress while the scan runs; stop on completion/failure or unmount.
  useEffect(() => {
    if (!scan.data) return;
    let stop = false;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      try {
        const p = await api<Progress>(`/scans/${id}/progress`);
        if (stop) return;
        setProgress(p);
        setPollErr('');
        if (isTerminal(p.db_status || p.status)) return;
        if (!stop) timer = setTimeout(tick, (p.db_status || p.status) === 'queued' ? POLL_QUEUED_MS : POLL_RUNNING_MS);
        return;
      } catch (e: any) {
        if (!stop) setPollErr(e.message);
      }
      if (!stop) timer = setTimeout(tick, POLL_QUEUED_MS);
    };
    if (isTerminal(scan.data.status)) {
      api<Progress>(`/scans/${id}/progress`).then(p => !stop && setProgress(p)).catch(() => null);
    } else {
      tick();
    }
    return () => { stop = true; clearTimeout(timer); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, scan.data?.id]);

  const findings = useAsync(
    () => (done ? api<Finding[]>(`/scans/${id}/findings`) : Promise.resolve(null)), [id, done],
  );
  const analysis = useAsync(
    () => (status === 'completed' ? api<AIAnalysis | null>(`/scans/${id}/analysis`) : Promise.resolve(null)), [id, status],
  );

  const [cancelling, setCancelling] = useState(false);
  const cancel = async () => {
    if (!confirm(status === 'queued' ? 'Annuler ce scan ? Les crédits seront restitués.' : 'Arrêter ce scan ?')) return;
    setCancelling(true);
    try {
      await api(`/scans/${id}/cancel`, { method: 'POST' });
      setProgress(await api<Progress>(`/scans/${id}/progress`));
    }
    catch (e: any) { setPollErr(e.message); }
    finally { setCancelling(false); }
  };

  if (scan.loading && !scan.data) return <Loading />;
  if (scan.error) return <ErrorBox message={scan.error} onRetry={scan.reload} />;
  const s = scan.data!;

  return (
    <>
      <p className="mb-2 text-sm"><TextLink href="/scans">← Scans</TextLink></p>
      <PageHeader
        title={`Scan #${s.id}`}
        sub={target.data ? <><Link href={`/targets/${target.data.id}`} className="hover:underline">{target.data.name}</Link> · <span className="font-mono">{target.data.url}</span></> : undefined}
        actions={!done && <button className="btn-ghost" onClick={cancel} disabled={cancelling}>{status === 'queued' ? 'Annuler' : 'Arrêter le scan'}</button>}
      />

      <div className="grid gap-6 lg:grid-cols-3">
        <section className="card space-y-2 text-sm">
          <h2 className="card-title">Informations</h2>
          <Row k="Statut" v={<StatusBadge status={status || s.status} />} />
          <Row k="Profil" v={PROFILE_LABEL[s.profile]?.name || s.profile} />
          <Row k="Facturation" v={`${BILLING_LABEL[s.billing] || s.billing}${s.credits_charged ? ` · ${s.credits_charged} crédit(s)` : ''}`} />
          <Row k="Créé le" v={fmtDate(s.created_time)} />
          {s.started_at && <Row k="Démarré le" v={fmtDate(s.started_at)} />}
          {s.completed_at && <Row k="Terminé le" v={fmtDate(s.completed_at)} />}
        </section>

        <section className="card lg:col-span-2">
          <h2 className="card-title">Progression</h2>
          <ScanProgress scan={s} progress={progress} status={status} />
          {status === 'failed' && (
            <p className="alert-err mt-3">
              {s.review_note && s.error?.startsWith('Demande refusée')
                ? `Demande d’audit refusée : ${s.review_note}.`
                : `Le scan n’a pas abouti${s.error === 'Cancelled by user' ? ' (annulé à votre demande)' : s.error ? ` : ${s.error}` : ''}.`}
              {s.billing !== 'admin' && s.error !== 'Cancelled by user' && ' Les crédits débités ont été restitués.'}
            </p>
          )}
          {pollErr && <div className="mt-3"><ErrorBox message={pollErr} /></div>}
        </section>
      </div>

      {status === 'completed' && <AnalysisCard state={analysis} />}
      {done && <FindingsCard state={findings} />}
      {status === 'completed' && <ReportsCard scan={s} />}
    </>
  );
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return <div className="flex items-center justify-between gap-3"><span className="text-kx-muted">{k}</span><span className="text-right">{v}</span></div>;
}

function AnalysisCard({ state }: { state: ReturnType<typeof useAsync<AIAnalysis | null>> }) {
  return (
    <section className="card mt-6">
      <h2 className="card-title">Analyse IA</h2>
      {state.loading && <Loading />}
      {state.error && <ErrorBox message={state.error} onRetry={state.reload} />}
      {!state.loading && !state.error && !state.data && <p className="text-sm text-kx-muted">Aucune analyse IA disponible pour ce scan.</p>}
      {state.data && (
        <div className="space-y-4 text-sm">
          <p><span className="text-3xl font-extrabold">{state.data.score}</span><span className="text-kx-muted"> / 100 · score de sécurité</span></p>
          {state.data.summary && <Block title="Synthèse" text={state.data.summary} />}
          {state.data.impacts && <Block title="Impacts" text={state.data.impacts} />}
          {state.data.recommendations && <Block title="Recommandations" text={state.data.recommendations} />}
        </div>
      )}
    </section>
  );
}

function Block({ title, text }: { title: string; text: string }) {
  return <div><h3 className="mb-1 font-semibold">{title}</h3><p className="whitespace-pre-line text-kx-muted">{text}</p></div>;
}

function FindingsCard({ state }: { state: ReturnType<typeof useAsync<Finding[] | null>> }) {
  const [sev, setSev] = useState('');
  const items = state.data || [];
  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    items.forEach(f => { c[f.severity] = (c[f.severity] || 0) + 1; });
    return c;
  }, [items]);
  const grouped = useMemo(() => groupFindings(sev ? items.filter(f => f.severity === sev) : items), [items, sev]);

  return (
    <section className="card mt-6">
      <h2 className="card-title">Vulnérabilités détectées</h2>
      {state.loading && <Loading />}
      {state.error && <ErrorBox message={state.error} onRetry={state.reload} />}
      {state.data && items.length === 0 && <p className="text-sm text-kx-muted">Aucune vulnérabilité détectée.</p>}
      {items.length > 0 && (
        <>
          <div className="mb-4 flex flex-wrap gap-2" role="group" aria-label="Filtrer par gravité">
            <button className={sev === '' ? 'btn btn-sm' : 'btn-ghost btn-sm'} onClick={() => setSev('')}>Toutes · {items.length}</button>
            {SEV_ORDER.filter(s => counts[s]).map(s => (
              <button key={s} className={sev === s ? 'btn btn-sm' : 'btn-ghost btn-sm'} onClick={() => setSev(s)}>
                {SEV_FR[s]} · {counts[s]}
              </button>
            ))}
          </div>
          <div className="space-y-2">
            {grouped.map(g => (
              <details key={g.key} className="rounded-lg border border-kx-border">
                <summary className="flex cursor-pointer items-center gap-3 px-3 py-2.5">
                  <SeverityBadge severity={g.severity} />
                  <span className="flex-1 font-medium">{g.fr}{g.count > 1 ? ` · ${g.count}×` : ''}</span>
                  <span className="hidden rounded-full border border-kx-border px-2 py-0.5 text-[11px] text-kx-muted sm:inline">{g.plugin}</span>
                </summary>
                <div className="space-y-2 border-t border-kx-border px-3 py-3 text-sm">
                  {g.why && <p><b>Pourquoi c’est un risque :</b> <span className="text-kx-muted">{g.why}</span></p>}
                  {g.fix && <p><b>Correctif :</b> <span className="text-kx-muted">{g.fix}</span></p>}
                  {g.fr !== g.title && <p className="text-xs text-kx-muted">Intitulé de l’outil : {g.title}</p>}
                  {g.samples.length > 0 && (
                    <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-kx-border bg-kx-panel2 p-2 font-mono text-xs">
                      {g.samples.join('\n')}{g.count > g.samples.length ? `\n… (+${g.count - g.samples.length})` : ''}
                    </pre>
                  )}
                </div>
              </details>
            ))}
          </div>
        </>
      )}
    </section>
  );
}

function ReportsCard({ scan }: { scan: Scan }) {
  const [busy, setBusy] = useState('');
  const [err, setErr] = useState('');
  const get = async (format: 'pdf' | 'html' | 'json') => {
    setBusy(format); setErr('');
    try { await download(`/scans/${scan.id}/report/download?format=${format}&lang=fr`, `rapport-scan-${scan.id}.${format}`); }
    catch (e: any) { setErr(e.message); }
    finally { setBusy(''); }
  };

  return (
    <section className="card mt-6">
      <h2 className="card-title">Rapport</h2>
      {scan.billing === 'free' ? (
        <p className="alert-info">
          Les rapports détaillés sont inclus dans les scans payés en crédits.{' '}
          <TextLink href="/credits">Voir les offres</TextLink>
        </p>
      ) : (
        <>
          <div className="flex flex-wrap gap-2">
            <button className="btn" disabled={!!busy} onClick={() => get('pdf')}>{busy === 'pdf' ? 'Génération…' : 'Télécharger le PDF'}</button>
            <button className="btn-ghost" disabled={!!busy} onClick={() => get('html')}>{busy === 'html' ? 'Génération…' : 'HTML'}</button>
            <button className="btn-ghost" disabled={!!busy} onClick={() => get('json')}>{busy === 'json' ? 'Génération…' : 'JSON'}</button>
          </div>
          {err && <div className="mt-3"><ErrorBox message={err} /></div>}
        </>
      )}
    </section>
  );
}
