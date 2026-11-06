'use client';

import Link from 'next/link';
import { useState } from 'react';
import { Logo } from '@/components/icons';
import { forgotPassword, resetPassword } from '@/lib/api';

export function ResetPasswordForm() {
  const [step, setStep] = useState<'email' | 'code' | 'done'>('email');
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [err, setErr] = useState('');
  const [info, setInfo] = useState('');
  const [busy, setBusy] = useState(false);

  const sendCode = async (e?: React.FormEvent) => {
    e?.preventDefault();
    setErr(''); setInfo(''); setBusy(true);
    try {
      await forgotPassword(email.trim());
      setStep('code');
      setInfo('Si un compte existe avec cet email, un code a été envoyé sur le numéro WhatsApp associé.');
    } catch (e: any) {
      setErr(e.status === 429 ? 'Trop de demandes. Réessayez dans 10 minutes.' : e.message);
    } finally { setBusy(false); }
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr('');
    if (password.length < 8 || !/^\p{Lu}/u.test(password))
      return setErr('Le mot de passe doit faire au moins 8 caractères et commencer par une majuscule.');
    if (password !== confirm) return setErr('Les mots de passe ne correspondent pas.');
    setBusy(true);
    try {
      await resetPassword(email.trim(), code.trim(), password);
      setStep('done');
    } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };

  return (
    <div className="space-y-5 rounded-3xl bg-white p-6 text-kx-text shadow-2xl sm:p-8">
      <Link href="/" className="mb-2 flex justify-center"><Logo size="lg" /></Link>
      <div>
        <h2 className="font-display text-2xl font-semibold">Mot de passe oublié</h2>
        <p className="mt-1 text-sm text-kx-muted">
          {step === 'email' && 'Entrez l’email de votre compte : nous envoyons un code sur votre WhatsApp.'}
          {step === 'code' && <>Saisissez le code reçu et choisissez un nouveau mot de passe pour <b>{email}</b>.</>}
          {step === 'done' && 'Votre mot de passe a été modifié. Toutes vos sessions ont été déconnectées.'}
        </p>
      </div>

      {step === 'email' && (
        <form onSubmit={sendCode} className="space-y-5" noValidate>
          <div>
            <label className="label" htmlFor="email">Email</label>
            <input id="email" className="input" type="email" autoComplete="email" required value={email} onChange={e => setEmail(e.target.value)} />
          </div>
          {err && <p className="alert-err" role="alert">{err}</p>}
          <button className="btn w-full py-3 text-base" disabled={busy || !email.includes('@')}>{busy ? 'Envoi…' : 'Recevoir un code'}</button>
        </form>
      )}

      {step === 'code' && (
        <form onSubmit={submit} className="space-y-5" noValidate>
          {info && <p className="alert-info" role="status">{info}</p>}
          <div>
            <label className="label" htmlFor="otp">Code reçu par WhatsApp</label>
            <input id="otp" className="input text-center text-2xl tracking-[0.4em]" inputMode="numeric" autoComplete="one-time-code"
              maxLength={6} required value={code} onChange={e => setCode(e.target.value.replace(/\D/g, ''))} placeholder="______" autoFocus />
          </div>
          <div>
            <label className="label" htmlFor="password">Nouveau mot de passe</label>
            <input id="password" className="input" type="password" autoComplete="new-password" required value={password} onChange={e => setPassword(e.target.value)} />
            <p className="hint">Au moins 8 caractères, commençant par une majuscule.</p>
          </div>
          <div>
            <label className="label" htmlFor="confirm">Confirmer le mot de passe</label>
            <input id="confirm" className="input" type="password" autoComplete="new-password" required value={confirm} onChange={e => setConfirm(e.target.value)} />
          </div>
          {err && <p className="alert-err" role="alert">{err}</p>}
          <button className="btn w-full py-3 text-base" disabled={busy || code.length < 4 || !password}>{busy ? 'Patientez…' : 'Changer le mot de passe'}</button>
          <div className="flex items-center justify-between text-sm">
            <button type="button" onClick={() => { setStep('email'); setErr(''); setInfo(''); }} className="text-kx-muted hover:text-black hover:underline">← Changer d’email</button>
            <button type="button" onClick={() => sendCode()} disabled={busy} className="font-semibold text-black underline underline-offset-4">Renvoyer le code</button>
          </div>
        </form>
      )}

      {step === 'done' && (
        <Link href="/login" className="btn block w-full py-3 text-center text-base">Se connecter</Link>
      )}

      {step !== 'done' && (
        <p className="text-center text-sm text-kx-muted">
          <Link className="font-semibold underline decoration-black/25 underline-offset-4 hover:decoration-black" href="/login">Retour à la connexion</Link>
        </p>
      )}
    </div>
  );
}
