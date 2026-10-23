'use client';

import { useRouter } from 'next/navigation';
import { useEffect, useRef, useState } from 'react';
import { api } from '@/lib/api';
import { fmtDate } from '@/lib/format';
import type { Notification, Page } from '@/lib/types';

const POLL_MS = 20000;

export function NotificationBell() {
  const router = useRouter();
  const [count, setCount] = useState(0);
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState<Notification[]>([]);
  const [loading, setLoading] = useState(false);
  const box = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let stop = false;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      try {
        const r = await api<{ count: number }>('/notifications/me/unread-count');
        if (!stop) setCount(r.count);
      } catch { /* bell is best effort */ }
      if (!stop) timer = setTimeout(tick, POLL_MS);
    };
    tick();
    return () => { stop = true; clearTimeout(timer); };
  }, []);

  useEffect(() => {
    const onClick = (e: MouseEvent) => { if (box.current && !box.current.contains(e.target as Node)) setOpen(false); };
    document.addEventListener('mousedown', onClick);
    return () => document.removeEventListener('mousedown', onClick);
  }, []);

  const toggle = async () => {
    const next = !open;
    setOpen(next);
    if (next) {
      setLoading(true);
      try { setItems((await api<Page<Notification>>('/notifications/me', { query: { page: 1, size: 12 } })).items); }
      catch { /* shown empty */ }
      finally { setLoading(false); }
    }
  };

  const openItem = async (n: Notification) => {
    if (!n.is_read) { await api(`/notifications/${n.id}/read`, { method: 'POST' }).catch(() => null); setCount(c => Math.max(0, c - 1)); }
    setOpen(false);
    if (n.link) router.push(n.link);
  };

  const markAll = async () => {
    await api('/notifications/read-all', { method: 'POST' }).catch(() => null);
    setItems(xs => xs.map(x => ({ ...x, is_read: true })));
    setCount(0);
  };

  return (
    <div className="relative" ref={box}>
      <button onClick={toggle} className="relative grid h-9 w-9 place-items-center rounded-full border border-kx-border bg-white hover:border-black/30" aria-label="Notifications" aria-expanded={open}>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="h-5 w-5">
          <path d="M18 8a6 6 0 1 0-12 0c0 7-3 9-3 9h18s-3-2-3-9" /><path d="M13.7 21a2 2 0 0 1-3.4 0" />
        </svg>
        {count > 0 && (
          <span className="absolute -right-1 -top-1 grid h-4 min-w-4 place-items-center rounded-full bg-sev-critical px-1 text-[10px] font-bold text-white">
            {count > 9 ? '9+' : count}
          </span>
        )}
      </button>
      {open && (
        <div className="absolute right-0 top-11 z-50 w-80 max-w-[calc(100vw-2rem)] overflow-hidden rounded-2xl border border-kx-border bg-white shadow-card">
          <div className="flex items-center justify-between border-b border-kx-border px-4 py-2.5">
            <span className="text-sm font-semibold">Notifications</span>
            {count > 0 && <button className="text-xs text-kx-muted hover:text-black" onClick={markAll}>Tout marquer lu</button>}
          </div>
          <div className="max-h-96 overflow-auto">
            {loading && <p className="px-4 py-6 text-center text-sm text-kx-muted">Chargement…</p>}
            {!loading && items.length === 0 && <p className="px-4 py-6 text-center text-sm text-kx-muted">Aucune notification.</p>}
            {!loading && items.map(n => (
              <button key={n.id} onClick={() => openItem(n)}
                className={`flex w-full gap-3 border-b border-kx-border px-4 py-3 text-left last:border-b-0 hover:bg-kx-panel2 ${n.is_read ? '' : 'bg-indigo-50/40'}`}>
                <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${n.is_read ? 'bg-transparent' : 'bg-indigo-500'}`} />
                <span className="min-w-0 flex-1">
                  <span className="block text-sm font-medium">{n.title}</span>
                  {n.body && <span className="mt-0.5 block text-xs text-kx-muted">{n.body}</span>}
                  <span className="mt-1 block text-[11px] text-kx-muted">{fmtDate(n.created_time)}</span>
                </span>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
