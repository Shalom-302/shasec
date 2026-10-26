'use client';

import { useState } from 'react';
import { api } from '@/lib/api';

export function GrantForm() {
  const [email, setEmail] = useState('');
  const [credits, setCredits] = useState(20);
  const [days, setDays] = useState('');
  const [note, setNote] = useState('');
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const grant = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setMsg(null);
    try {
      await api('/credits/grant', { method: 'POST', body: { email, credits, expires_in_days: days ? Number(days) : null, note: note || null } });
      setMsg({ ok: true, text: `${credits} crédit(s) attribué(s) à ${email}.` });
      setEmail(''); setNote('');
    } catch (e: any) { setMsg({ ok: false, text: e.message }); } finally { setBusy(false); }
  };

  return (
    <form onSubmit={grant} className="card space-y-4">
      <h2 className="card-title mb-0">Attribuer des crédits à un compte</h2>
      <div className="grid gap-4 sm:grid-cols-4">
        <div className="sm:col-span-2">
          <label className="label" htmlFor="g-email">Email du compte</label>
          <input id="g-email" type="email" required className="input" value={email} onChange={e => setEmail(e.target.value)} />
        </div>
        <Num id="g-credits" label="Crédits" value={credits} set={setCredits} min={1} />
        <div>
          <label className="label" htmlFor="g-days">Expire après N jours</label>
          <input id="g-days" type="number" min={1} className="input" value={days} onChange={e => setDays(e.target.value)} placeholder="Jamais" />
        </div>
      </div>
      <div>
        <label className="label" htmlFor="g-note">Motif</label>
        <input id="g-note" className="input" value={note} onChange={e => setNote(e.target.value)} maxLength={255} />
      </div>
      {msg && <p className={msg.ok ? 'alert-ok' : 'alert-err'} role="status">{msg.text}</p>}
      <button className="btn" disabled={busy || !email}>{busy ? 'Attribution…' : 'Attribuer'}</button>
    </form>
  );
}

export function Num({ id, label, value, set, min, max }: { id: string; label: string; value: number; set: (n: number) => void; min?: number; max?: number }) {
  return (
    <div>
      <label className="label" htmlFor={id}>{label}</label>
      <input id={id} type="number" className="input" min={min} max={max} value={value} onChange={e => set(Math.max(min ?? 0, Number(e.target.value) || 0))} />
    </div>
  );
}
