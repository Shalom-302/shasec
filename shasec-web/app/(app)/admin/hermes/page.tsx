'use client';

import { useEffect, useRef, useState } from 'react';
import AdminOnly from '@/components/AdminOnly';
import { PageHeader } from '@/components/ui';
import { api } from '@/lib/api';

type Msg = { role: 'user' | 'hermes'; text: string; at: number };

const SUGGESTIONS = [
  'Audite kaanari.com et résume les failles critiques',
  'Lance un scan rapide de cci.kaanari.com',
  'Montre-moi les findings du dernier scan',
];

function HermesChat() {
  const [messages, setMessages] = useState<Msg[]>([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const sessionId = useRef<string>(`admin-${Date.now().toString(36)}`);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages, busy]);

  const send = async (text: string) => {
    const msg = text.trim();
    if (!msg || busy) return;
    setErr('');
    setInput('');
    setMessages(m => [...m, { role: 'user', text: msg, at: Date.now() }]);
    setBusy(true);
    try {
      const res = await api<{ reply: string; session_id: string }>('/hermes/chat', {
        method: 'POST', body: { message: msg, session_id: sessionId.current },
      });
      sessionId.current = res.session_id || sessionId.current;
      setMessages(m => [...m, { role: 'hermes', text: res.reply, at: Date.now() }]);
    } catch (e: any) {
      setErr(e.message || 'Erreur');
    } finally {
      setBusy(false);
    }
  };

  const onSubmit = (e: React.FormEvent) => { e.preventDefault(); send(input); };
  const onKey = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(input); }
  };

  return (
    <div className="flex h-[calc(100vh-13rem)] min-h-[420px] flex-col">
      <div className="flex-1 space-y-4 overflow-y-auto rounded-2xl border border-kx-border bg-white p-4 sm:p-6">
        {messages.length === 0 && (
          <div className="flex h-full flex-col items-center justify-center text-center">
            <p className="font-display text-lg font-semibold">Parlez à Hermes</p>
            <p className="mt-1 max-w-md text-sm text-kx-muted">
              Demandez-lui en langage naturel de lancer un audit, de choisir un périmètre ou de résumer les failles.
              Il pilote shasec pour vous.
            </p>
            <div className="mt-5 flex flex-wrap justify-center gap-2">
              {SUGGESTIONS.map(s => (
                <button key={s} onClick={() => send(s)} className="rounded-full border border-kx-border bg-kx-panel2 px-3 py-1.5 text-xs text-kx-text transition hover:border-black/30">
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}
        {messages.map((m, i) => (
          <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            <div className={`max-w-[85%] whitespace-pre-wrap break-words rounded-2xl px-4 py-2.5 text-sm ${
              m.role === 'user' ? 'bg-black text-white' : 'border border-kx-border bg-kx-panel2 text-kx-text'}`}>
              {m.role === 'hermes' && <span className="mb-1 block text-[11px] font-semibold uppercase tracking-wide text-kx-muted">Hermes</span>}
              {m.text}
            </div>
          </div>
        ))}
        {busy && (
          <div className="flex justify-start">
            <div className="rounded-2xl border border-kx-border bg-kx-panel2 px-4 py-2.5 text-sm text-kx-muted">
              <span className="inline-flex gap-1">
                <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-kx-muted [animation-delay:-0.2s]" />
                <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-kx-muted [animation-delay:-0.1s]" />
                <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-kx-muted" />
              </span>
            </div>
          </div>
        )}
        <div ref={endRef} />
      </div>

      {err && <p className="alert-err mt-3" role="alert">{err}</p>}

      <form onSubmit={onSubmit} className="mt-3 flex items-end gap-2">
        <textarea
          className="input max-h-40 min-h-[48px] flex-1 resize-none py-3"
          placeholder="Écrivez à Hermes…  (Entrée pour envoyer, Maj+Entrée pour un retour à la ligne)"
          value={input} onChange={e => setInput(e.target.value)} onKeyDown={onKey} disabled={busy} rows={1}
        />
        <button className="btn h-12 px-5" disabled={busy || !input.trim()}>Envoyer</button>
      </form>
    </div>
  );
}

export default function HermesPage() {
  return (
    <AdminOnly>
      <PageHeader title="Hermes" sub="Assistant d’audit — il pilote shasec en langage naturel." />
      <HermesChat />
    </AdminOnly>
  );
}
