'use client';

import { useEffect, useState } from 'react';
import { fmtDuration, stepLabel } from '@/lib/format';
import { askNotifications, notificationsGranted, notificationsSupported } from '@/lib/notify';
import type { Progress, Scan } from '@/lib/types';
import { IconCheck } from './icons';

// Macro-phases as emitted by the pipeline (backend/app/shasec/service/progress.py).
const PHASES = ['Initialisation', 'Reconnaissance & scan', 'Corrélation des résultats', 'Validation contrôlée', 'Analyse IA', 'Terminé'];

export function ScanProgress({ scan, progress, status }: { scan: Scan; progress: Progress | null; status?: string }) {
  const [now, setNow] = useState(Date.now());
  const [notif, setNotif] = useState(false);
  const active = status === 'queued' || status === 'running' || status === 'awaiting_approval';

  useEffect(() => { setNotif(notificationsGranted()); }, []);
  useEffect(() => {
    if (!active) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [active]);

  if (!progress) return <p className="text-sm text-kx-muted">Lecture de la progression…</p>;

  const failed = status === 'failed';
  const phaseIdx = Math.max(0, PHASES.indexOf(progress.current_phase));
  const steps = (progress.steps || []).slice().reverse();

  return (
    <div className="space-y-5">
      {status === 'awaiting_approval' && (
        <div className="rounded-xl border border-indigo-200 bg-indigo-50 p-4 text-sm text-indigo-900">
          <p className="font-semibold">En attente de validation</p>
          <p className="mt-1">Votre demande d’audit avancé (tests actifs) a été transmise à un administrateur. Vous serez notifié dès qu’elle est validée, et le scan démarrera automatiquement. Les crédits sont réservés et restitués en cas de refus.</p>
        </div>
      )}
      {status === 'queued' && (
        <div className="rounded-xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
          <p className="font-semibold">
            En file d’attente{progress.queue_position ? ` · position ${progress.queue_position}` : ''}
          </p>
          <p className="mt-1">Les scans sont traités les uns après les autres pour garantir des résultats fiables. Le vôtre démarrera automatiquement.</p>
        </div>
      )}

      <div>
        <div className="mb-2 flex items-baseline justify-between gap-3">
          <span className="font-display text-lg font-semibold">{failed ? 'Échec' : progress.current_phase}</span>
          <span className="font-mono text-sm text-kx-muted">
            {progress.percent}%{active && scan.started_at ? ` · ${fmtDuration(scan.started_at, now)}` : ''}
            {!active && scan.started_at && scan.completed_at ? ` · ${fmtDuration(scan.started_at, new Date(scan.completed_at).getTime())}` : ''}
          </span>
        </div>
        <div className="h-2 overflow-hidden rounded-full bg-kx-panel2" role="progressbar" aria-valuenow={progress.percent} aria-valuemin={0} aria-valuemax={100}>
          <div className={`h-full rounded-full transition-all duration-700 ${failed ? 'bg-sev-critical' : 'bg-black'} ${status === 'running' ? 'animate-pulse' : ''}`}
            style={{ width: `${Math.max(progress.percent, status === 'running' ? 3 : 0)}%` }} />
        </div>
      </div>

      {/* Phase stepper */}
      <ol className="grid grid-cols-3 gap-2 sm:grid-cols-6" aria-label="Phases du scan">
        {PHASES.map((p, i) => {
          const done = !failed && (status === 'completed' || i < phaseIdx);
          const current = !failed && status !== 'completed' && status !== 'queued' && i === phaseIdx;
          return (
            <li key={p} className="text-center">
              <span className={`mx-auto mb-1.5 grid h-7 w-7 place-items-center rounded-full text-xs font-bold ${
                done ? 'bg-black text-white' : current ? 'border-2 border-black text-black' : 'bg-kx-panel2 text-kx-muted'}`}>
                {done ? <IconCheck className="h-3.5 w-3.5" /> : i + 1}
              </span>
              <span className={`block text-[11px] leading-tight ${current || done ? 'text-kx-text' : 'text-kx-muted'}`}>{p}</span>
            </li>
          );
        })}
      </ol>

      {progress.scanners?.total > 0 && (
        <div className="text-sm">
          <p className="mb-2 text-kx-muted">Analyseurs : <b className="text-kx-text">{progress.scanners.done}/{progress.scanners.total}</b> terminés</p>
          {progress.scanners.running.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {progress.scanners.running.map(n => (
                <span key={n} className="inline-flex items-center gap-1.5 rounded-full bg-kx-panel2 px-2.5 py-1 font-mono text-xs">
                  <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-black" />{n}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Live log */}
      <div>
        <div className="mb-2 flex items-center justify-between">
          <h3 className="text-sm font-semibold">Journal du scan</h3>
          {active && notificationsSupported() && !notif && (
            <button className="btn-ghost btn-sm" onClick={async () => setNotif(await askNotifications())}>M’avertir à la fin</button>
          )}
          {active && notif && <span className="text-xs text-kx-muted">Vous serez averti à la fin du scan.</span>}
        </div>
        {steps.length === 0 ? (
          <p className="text-sm text-kx-muted">En attente des premiers événements…</p>
        ) : (
          <ol className="max-h-72 space-y-0 overflow-auto rounded-xl border border-kx-border">
            {steps.map((st, i) => (
              <li key={i} className={`flex gap-3 border-b border-kx-border px-3 py-2 text-sm last:border-b-0 ${i === 0 && active ? 'bg-kx-panel2' : ''}`}>
                <span className="shrink-0 font-mono text-xs leading-5 text-kx-muted">
                  {st.ts ? new Date(st.ts).toLocaleTimeString('fr-FR') : ''}
                </span>
                <span className="min-w-0">
                  <span className="font-medium">{stepLabel(st.event, st.plugin)}</span>
                  {st.message && st.message !== stepLabel(st.event, st.plugin) && (
                    <span className="block break-words text-kx-muted">{st.message}</span>
                  )}
                </span>
              </li>
            ))}
          </ol>
        )}
      </div>
    </div>
  );
}
