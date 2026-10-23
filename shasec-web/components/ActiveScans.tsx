'use client';

import Link from 'next/link';
import { useEffect, useRef, useState } from 'react';
import { api } from '@/lib/api';
import { notifyScanFinished } from '@/lib/notify';
import type { Page, Scan } from '@/lib/types';
import { useSession } from './SessionProvider';

const POLL_MS = 15000;
type Toast = { id: number; ok: boolean };

/** Top-bar indicator of queued/running scans + a toast (and browser
 * notification) when one of them finishes, wherever the user is in the app. */
export function ActiveScans() {
  const { refreshBalance } = useSession();
  const [active, setActive] = useState<Scan[]>([]);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const known = useRef<Set<number> | null>(null);

  useEffect(() => {
    let stop = false;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      try {
        const [running, queued] = await Promise.all([
          api<Page<Scan>>('/scans', { query: { status: 'running', page: 1, size: 20 } }),
          api<Page<Scan>>('/scans', { query: { status: 'queued', page: 1, size: 20 } }),
        ]);
        if (stop) return;
        const now = [...running.items, ...queued.items];
        const ids = new Set(now.map(s => s.id));
        if (known.current) {
          const ended = [...known.current].filter(id => !ids.has(id));
          for (const id of ended) {
            const s = await api<Scan>(`/scans/${id}`).catch(() => null);
            if (!s) continue;
            setToasts(t => [...t, { id, ok: s.status === 'completed' }]);
            notifyScanFinished(id, s.status);
          }
          if (ended.length) refreshBalance();
        }
        known.current = ids;
        setActive(now);
      } catch { /* indicator is best effort */ }
      if (!stop) timer = setTimeout(tick, POLL_MS);
    };
    tick();
    return () => { stop = true; clearTimeout(timer); };
  }, [refreshBalance]);

  const runningCount = active.filter(s => s.status === 'running').length;
  const queuedCount = active.length - runningCount;

  return (
    <>
      {active.length > 0 && (
        <Link
          href={active.length === 1 ? `/scans/${active[0].id}` : '/scans'}
          className="inline-flex items-center gap-2 rounded-full bg-black px-3.5 py-1.5 text-xs font-medium text-white"
        >
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-white" />
          {runningCount > 0 && `${runningCount} scan${runningCount > 1 ? 's' : ''} en cours`}
          {runningCount > 0 && queuedCount > 0 && ' · '}
          {queuedCount > 0 && `${queuedCount} en file`}
        </Link>
      )}
      <div className="fixed bottom-4 right-4 z-50 flex w-80 max-w-[calc(100vw-2rem)] flex-col gap-2" aria-live="polite">
        {toasts.map(t => (
          <div key={t.id} className="flex items-start gap-3 rounded-2xl border border-kx-border bg-white p-4 shadow-card">
            <span className={`mt-1 h-2.5 w-2.5 shrink-0 rounded-full ${t.ok ? 'bg-kx-teal' : 'bg-sev-critical'}`} />
            <div className="min-w-0 flex-1 text-sm">
              <p className="font-semibold">Scan #{t.id} {t.ok ? 'terminé' : 'en échec'}</p>
              <Link href={`/scans/${t.id}`} className="underline underline-offset-4" onClick={() => setToasts(x => x.filter(y => y.id !== t.id))}>
                {t.ok ? 'Voir les résultats' : 'Voir le détail'}
              </Link>
            </div>
            <button className="text-kx-muted hover:text-black" aria-label="Fermer" onClick={() => setToasts(x => x.filter(y => y.id !== t.id))}>×</button>
          </div>
        ))}
      </div>
    </>
  );
}
