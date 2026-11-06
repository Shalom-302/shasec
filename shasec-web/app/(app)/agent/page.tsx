'use client';

import Link from 'next/link';
import { useEffect, useRef, useState } from 'react';
import { ErrorBox, Loading, PageHeader, Spinner } from '@/components/ui';
import { api } from '@/lib/api';
import { fmtDate } from '@/lib/format';
import type { AgentAction, AgentMemory, AgentMessage, AgentStatus } from '@/lib/types';
import { useAsync } from '@/lib/useAsync';

const ACTION_STATUS: Record<string, { label: string; cls: string }> = {
  pending: { label: 'En attente de validation', cls: 'bg-amber-50 text-amber-800' },
  executing: { label: 'En cours', cls: 'bg-indigo-50 text-indigo-700' },
  executed: { label: 'Validée · lancée', cls: 'bg-teal-50 text-teal-800' },
  rejected: { label: 'Refusée', cls: 'bg-red-50 text-red-700' },
  failed: { label: 'Échec', cls: 'bg-red-50 text-red-700' },
};
const MEMORY_LABEL: Record<string, string> = { fact: 'Contexte', preference: 'Préférence', lesson: 'Leçon' };

function Bubble({ m }: { m: AgentMessage }) {
  if (m.role === 'system_event') {
    return <p className="mx-auto max-w-xl rounded-xl bg-kx-bg px-3 py-2 text-center text-xs text-kx-muted">{m.content}</p>;
  }
  const mine = m.role === 'user';
  const text = m.origin === 'autopilot' && mine ? 'Revue autonome quotidienne' : m.content;
  return (
    <div className={`flex ${mine ? 'justify-end' : 'justify-start'}`}>
      <div className={`max-w-[85%] whitespace-pre-wrap rounded-2xl px-4 py-2.5 text-sm ${mine ? 'bg-black text-white' : 'border border-kx-border bg-white'}`}>
        {text}
        <p className={`mt-1 text-[10px] ${mine ? 'text-white/60' : 'text-kx-muted'}`}>{fmtDate(m.created_time)}{m.origin === 'autopilot' ? ' · autonome' : ''}</p>
      </div>
    </div>
  );
}

export default function AgentPage() {
  const st = useAsync(() => api<AgentStatus>('/agent/status'), []);
  const msgs = useAsync(() => api<AgentMessage[]>('/agent/messages'), []);
  const actions = useAsync(() => api<AgentAction[]>('/agent/actions'), []);
  const mem = useAsync(() => api<AgentMemory[]>('/agent/memory'), []);
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [pending, setPending] = useState('');
  const end = useRef<HTMLDivElement>(null);

  useEffect(() => { end.current?.scrollIntoView({ behavior: 'smooth' }); }, [msgs.data, pending]);

  const send = async (e: React.FormEvent) => {
    e.preventDefault();
    const m = text.trim();
    if (!m) return;
    setBusy(true); setErr(''); setPending(m); setText('');
    try {
      await api('/agent/chat', { method: 'POST', body: { message: m } });
      await Promise.all([msgs.reload(), actions.reload(), mem.reload(), st.reload()]);
    } catch (e: any) { setErr(e.message); setText(m); } finally { setBusy(false); setPending(''); }
  };

  const toggleAutopilot = async () => {
    if (!st.data) return;
    await api('/agent/autopilot', { method: 'PUT', body: { enabled: !st.data.autopilot } }).catch(() => null);
    st.reload();
  };

  const forget = async (id: number) => {
    await api(`/agent/memory/${id}`, { method: 'DELETE' }).catch(() => null);
    mem.reload();
  };

  if (st.loading) return <Loading />;
  if (st.error) return <ErrorBox message={st.error} onRetry={st.reload} />;
  const s = st.data!;

  if (!s.premium) {
    return (
      <>
        <PageHeader title="Agent Kortex" sub="Votre analyste sécurité personnel, piloté par l’IA." />
        <section className="card max-w-2xl space-y-3">
          <p>L’agent Kortex est inclus dans l’offre <b>Premium (5 000 FCFA / 30 jours)</b>.</p>
          <ul className="list-disc space-y-1 pl-5 text-sm text-kx-muted">
            <li>Il analyse vos scans et vous explique chaque faille avec le correctif adapté à votre stack.</li>
            <li>Il retient votre contexte et apprend des décisions passées pour mieux vous conseiller.</li>
            <li>Chaque matin, il fait une revue autonome et propose les scans utiles, toujours validés par un expert Kortex avant exécution.</li>
          </ul>
          <Link href="/credits" className="btn inline-block">Passer en Premium</Link>
        </section>
      </>
    );
  }

  return (
    <>
      <PageHeader title="Agent Kortex" sub="Analyse, priorise et propose. Toute action est validée par un expert Kortex avant d’être exécutée." />
      <div className="grid gap-6 xl:grid-cols-3">
        <section className="card flex min-h-[60vh] flex-col xl:col-span-2">
          <div className="flex-1 space-y-3 overflow-y-auto pr-1" style={{ maxHeight: '60vh' }}>
            {msgs.loading && <Loading />}
            {msgs.data && msgs.data.length === 0 && !pending && (
              <p className="text-sm text-kx-muted">Posez une question : « Quelles sont mes failles les plus urgentes ? », « Comment corriger la CSP sur mon Laravel ? », « Que me conseilles-tu de scanner cette semaine ? »</p>
            )}
            {msgs.data?.map(m => <Bubble key={m.id} m={m} />)}
            {pending && (
              <>
                <Bubble m={{ id: -1, role: 'user', content: pending, origin: 'chat', created_time: new Date().toISOString() }} />
                <p className="flex items-center gap-2 text-sm text-kx-muted"><Spinner /> L’agent analyse vos données…</p>
              </>
            )}
            <div ref={end} />
          </div>
          {err && <p className="alert-err mt-3" role="alert">{err}</p>}
          <form onSubmit={send} className="mt-3 flex gap-2">
            <label htmlFor="agentmsg" className="sr-only">Message</label>
            <input id="agentmsg" className="input flex-1" placeholder="Écrivez à l’agent…" maxLength={4000} value={text} onChange={e => setText(e.target.value)} disabled={busy} />
            <button className="btn shrink-0" disabled={busy || !text.trim()}>{busy ? '…' : 'Envoyer'}</button>
          </form>
          <p className="mt-1 text-xs text-kx-muted">{s.messages_left} message(s) restant(s) aujourd’hui.</p>
        </section>

        <div className="space-y-6">
          {s.autopilot_available && (
            <section className="card space-y-2">
              <h2 className="card-title mb-0">Mode autonome</h2>
              <p className="text-sm text-kx-muted">Chaque matin, l’agent passe en revue vos applications et propose les actions utiles.</p>
              <button className={s.autopilot ? 'btn' : 'btn-ghost'} onClick={toggleAutopilot}>{s.autopilot ? 'Activé — désactiver' : 'Désactivé — activer'}</button>
            </section>
          )}

          <section className="card">
            <h2 className="card-title">Propositions</h2>
            {actions.data && actions.data.length === 0 && <p className="text-sm text-kx-muted">Aucune proposition pour l’instant.</p>}
            <ul className="space-y-3">
              {actions.data?.map(a => (
                <li key={a.id} className="text-sm">
                  <div className="flex items-center justify-between gap-2">
                    <b>#{a.id} {a.kind === 'advanced_audit' ? 'Audit avancé' : `Scan ${a.profile}`}</b>
                    <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${ACTION_STATUS[a.status]?.cls || ''}`}>{ACTION_STATUS[a.status]?.label || a.status}</span>
                  </div>
                  <p className="truncate text-kx-muted">{a.target_url}</p>
                  {a.review_note && <p className="text-xs text-kx-muted">Note : {a.review_note}</p>}
                  {a.scan_id && <Link className="text-xs underline" href={`/scans/${a.scan_id}`}>Voir le scan #{a.scan_id}</Link>}
                </li>
              ))}
            </ul>
          </section>

          <section className="card">
            <h2 className="card-title">Ce que l’agent a retenu</h2>
            {mem.data && mem.data.length === 0 && <p className="text-sm text-kx-muted">Rien pour l’instant : il apprend au fil de vos échanges.</p>}
            <ul className="space-y-2">
              {mem.data?.slice(0, 20).map(m => (
                <li key={m.id} className="flex items-start justify-between gap-2 text-sm">
                  <span><span className="text-xs font-semibold uppercase text-kx-muted">{MEMORY_LABEL[m.kind] || m.kind}</span> · {m.content}</span>
                  <button className="shrink-0 text-xs text-kx-muted hover:text-red-700" onClick={() => forget(m.id)} aria-label="Oublier">Oublier</button>
                </li>
              ))}
            </ul>
          </section>
        </div>
      </div>
    </>
  );
}
