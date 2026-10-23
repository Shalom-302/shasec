'use client';

import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { useState } from 'react';
import { Logo } from '@/components/icons';
import { authCall } from '@/lib/api';

export function AuthForm({ mode }: { mode: 'login' | 'register' }) {
  const params = useSearchParams();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const isRegister = mode === 'register';

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr('');
    if (isRegister && password.length < 8) return setErr('Le mot de passe doit contenir au moins 8 caractères.');
    if (isRegister && password !== confirm) return setErr('Les mots de passe ne correspondent pas.');
    setBusy(true);
    try {
      await authCall(mode, { email, password });
      const next = params.get('next');
      // Only same-site relative paths: never an open redirect.
      window.location.href = next && next.startsWith('/') && !next.startsWith('//') ? next : '/dashboard';
    } catch (e: any) {
      setErr(e.status === 429 ? 'Trop de tentatives. Patientez une minute puis réessayez.' : e.message);
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} className="space-y-5 rounded-3xl bg-white p-6 text-kx-text shadow-2xl sm:p-8" noValidate>
      <Link href="/" className="mb-2 flex justify-center"><Logo size="lg" /></Link>
      <div>
        <h2 className="font-display text-2xl font-semibold">{isRegister ? 'Créer votre compte' : 'Bon retour parmi nous'}</h2>
        <p className="mt-1 text-sm text-kx-muted">
          {isRegister ? '3 scans de découverte offerts à l’inscription.' : 'Connectez-vous pour suivre vos audits.'}
        </p>
      </div>
      {params.get('expired') && !isRegister && (
        <p className="alert-info">Votre session a expiré, reconnectez-vous.</p>
      )}
      <div>
        <label className="label" htmlFor="email">Email</label>
        <input id="email" className="input" type="email" autoComplete="email" required value={email} onChange={e => setEmail(e.target.value)} />
      </div>
      <div>
        <label className="label" htmlFor="password">Mot de passe</label>
        <input id="password" className="input" type="password" required minLength={isRegister ? 8 : undefined}
          autoComplete={isRegister ? 'new-password' : 'current-password'} value={password} onChange={e => setPassword(e.target.value)} />
      </div>
      {isRegister && (
        <div>
          <label className="label" htmlFor="confirm">Confirmer le mot de passe</label>
          <input id="confirm" className="input" type="password" required autoComplete="new-password" value={confirm} onChange={e => setConfirm(e.target.value)} />
        </div>
      )}
      {err && <p className="alert-err" role="alert">{err}</p>}
      <button className="btn w-full py-3 text-base" disabled={busy || !email || !password}>
        {busy ? 'Patientez…' : isRegister ? 'Créer mon compte' : 'Se connecter'}
      </button>
      <p className="text-center text-sm text-kx-muted">
        {isRegister ? <>Déjà inscrit ? <Link className="font-semibold underline decoration-black/25 underline-offset-4 hover:decoration-black" href="/login">Se connecter</Link></>
          : <>Pas encore de compte ? <Link className="font-semibold underline decoration-black/25 underline-offset-4 hover:decoration-black" href="/register">Créer un compte</Link></>}
      </p>
    </form>
  );
}
