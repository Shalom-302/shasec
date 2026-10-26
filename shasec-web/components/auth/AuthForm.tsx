'use client';

import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { useState } from 'react';
import { Logo } from '@/components/icons';
import { api, authCall } from '@/lib/api';
import type { CreditBalance } from '@/lib/types';

export function AuthForm({ mode, admin = false }: { mode: 'login' | 'register'; admin?: boolean }) {
  const params = useSearchParams();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [terms, setTerms] = useState(false);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const isRegister = mode === 'register';

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr('');
    if (isRegister && password.length < 8) return setErr('Le mot de passe doit contenir au moins 8 caractères.');
    if (isRegister && password !== confirm) return setErr('Les mots de passe ne correspondent pas.');
    if (isRegister && !terms) return setErr('Acceptez les conditions d’utilisation pour créer votre compte.');
    setBusy(true);
    try {
      await authCall(mode, { email, password });
      if (admin && !(await api<CreditBalance>('/credits/me'))?.is_admin) {
        // Same accounts as the client app, but this entry point is for operators only.
        await authCall('logout').catch(() => null);
        setErr('Ce compte n’a pas les droits administrateur.');
        setBusy(false);
        return;
      }
      const next = params.get('next');
      // Only same-site relative paths: never an open redirect.
      window.location.href = next && next.startsWith('/') && !next.startsWith('//') ? next : admin ? '/admin' : '/dashboard';
    } catch (e: any) {
      setErr(e.status === 429 ? 'Trop de tentatives. Patientez une minute puis réessayez.' : e.message);
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} className="space-y-5 rounded-3xl bg-white p-6 text-kx-text shadow-2xl sm:p-8" noValidate>
      <Link href="/" className="mb-2 flex justify-center"><Logo size="lg" /></Link>
      <div>
        <h2 className="font-display text-2xl font-semibold">
          {isRegister ? 'Créer votre compte' : admin ? 'Console administrateur' : 'Bon retour parmi nous'}
        </h2>
        <p className="mt-1 text-sm text-kx-muted">
          {isRegister ? '3 scans de découverte offerts à l’inscription.'
            : admin ? 'Accès réservé aux opérateurs Kortex.' : 'Connectez-vous pour suivre vos audits.'}
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
      {isRegister && (
        <label className="flex cursor-pointer items-start gap-2.5 text-sm text-kx-muted">
          <input type="checkbox" className="mt-0.5 h-4 w-4 accent-black" checked={terms} onChange={e => setTerms(e.target.checked)} />
          <span>J’accepte les <Link href="/terms" target="_blank" className="font-semibold text-black underline underline-offset-4">conditions d’utilisation</Link>.</span>
        </label>
      )}
      {err && <p className="alert-err" role="alert">{err}</p>}
      <button className="btn w-full py-3 text-base" disabled={busy || !email || !password}>
        {busy ? 'Patientez…' : isRegister ? 'Créer mon compte' : 'Se connecter'}
      </button>
      {!admin && <p className="text-center text-sm text-kx-muted">
        {isRegister ? <>Déjà inscrit ? <Link className="font-semibold underline decoration-black/25 underline-offset-4 hover:decoration-black" href="/login">Se connecter</Link></>
          : <>Pas encore de compte ? <Link className="font-semibold underline decoration-black/25 underline-offset-4 hover:decoration-black" href="/register">Créer un compte</Link></>}
      </p>}
    </form>
  );
}
