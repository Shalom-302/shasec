'use client';

import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { useState } from 'react';
import { Logo } from '@/components/icons';
import { api, authCall, resendOtp, verifyOtp } from '@/lib/api';
import type { CreditBalance } from '@/lib/types';

export function AuthForm({ mode, admin = false }: { mode: 'login' | 'register'; admin?: boolean }) {
  const params = useSearchParams();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [phone, setPhone] = useState('');
  const [terms, setTerms] = useState(false);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  // When set, we switch to the WhatsApp-code screen for this email.
  const [otpEmail, setOtpEmail] = useState('');
  const isRegister = mode === 'register';

  const finishLogin = () => {
    const next = params.get('next');
    window.location.href = next && next.startsWith('/') && !next.startsWith('//') ? next : admin ? '/admin' : '/dashboard';
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr('');
    if (isRegister && (password.length < 8 || !/^\p{Lu}/u.test(password)))
      return setErr('Le mot de passe doit faire au moins 8 caractères et commencer par une majuscule.');
    if (isRegister && password !== confirm) return setErr('Les mots de passe ne correspondent pas.');
    if (isRegister && !/^\+?\d[\d\s]{7,}$/.test(phone.trim())) return setErr('Entrez un numéro WhatsApp valide (indicatif + numéro).');
    if (isRegister && !terms) return setErr('Acceptez les conditions d’utilisation pour créer votre compte.');
    setBusy(true);
    try {
      const res = await authCall(mode, { email, password, phone: phone.trim() });
      if (res?.otp_required) { setOtpEmail(res.email || email); setBusy(false); return; }
      if (admin && !(await api<CreditBalance>('/credits/me'))?.is_admin) {
        await authCall('logout').catch(() => null);
        setErr('Ce compte n’a pas les droits administrateur.');
        setBusy(false);
        return;
      }
      finishLogin();
    } catch (e: any) {
      // Login of an unverified account -> route to the code screen.
      if (e?.data?.otp_required) { setOtpEmail(e.data.email || email); setBusy(false); return; }
      setErr(e.status === 429
        ? (isRegister
          ? 'Trop d’inscriptions depuis cette connexion. Réessayez dans 10 minutes.'
          : 'Trop de tentatives. Patientez une minute puis réessayez.')
        : e.message);
      setBusy(false);
    }
  };

  if (otpEmail) {
    return <OtpScreen email={otpEmail} onVerified={finishLogin} onBack={() => { setOtpEmail(''); setErr(''); }} />;
  }

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
      {isRegister && (
        <div>
          <label className="label" htmlFor="phone">Numéro WhatsApp</label>
          <input id="phone" className="input" type="tel" autoComplete="tel" required value={phone}
            onChange={e => setPhone(e.target.value)} placeholder="225 01 52 31 11 24" />
          <p className="hint">Ex. 07 88 01 62 04 (Côte d’Ivoire) ou +33 6… pour l’étranger. Vous recevrez un code par WhatsApp.</p>
        </div>
      )}
      <div>
        <label className="label" htmlFor="password">Mot de passe</label>
        <input id="password" className="input" type="password" required minLength={isRegister ? 8 : undefined}
          autoComplete={isRegister ? 'new-password' : 'current-password'} value={password} onChange={e => setPassword(e.target.value)} />
        {isRegister && <p className="hint">Au moins 8 caractères, commençant par une majuscule.</p>}
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

function OtpScreen({ email, onVerified, onBack }: { email: string; onVerified: () => void; onBack: () => void }) {
  const [code, setCode] = useState('');
  const [err, setErr] = useState('');
  const [info, setInfo] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(''); setInfo(''); setBusy(true);
    try { await verifyOtp(email, code.trim()); onVerified(); }
    catch (e: any) { setErr(e.message); setBusy(false); }
  };

  const resend = async () => {
    setErr(''); setInfo('');
    try { await resendOtp(email); setInfo('Un nouveau code a été envoyé sur WhatsApp.'); }
    catch (e: any) { setErr(e.message); }
  };

  return (
    <form onSubmit={submit} className="space-y-5 rounded-3xl bg-white p-6 text-kx-text shadow-2xl sm:p-8" noValidate>
      <Link href="/" className="mb-2 flex justify-center"><Logo size="lg" /></Link>
      <div>
        <h2 className="font-display text-2xl font-semibold">Vérifiez votre compte</h2>
        <p className="mt-1 text-sm text-kx-muted">
          Un code a été envoyé par WhatsApp. Saisissez-le pour activer <b>{email}</b>.
        </p>
      </div>
      <div>
        <label className="label" htmlFor="otp">Code de vérification</label>
        <input id="otp" className="input text-center text-2xl tracking-[0.4em]" inputMode="numeric" autoComplete="one-time-code"
          maxLength={6} required value={code} onChange={e => setCode(e.target.value.replace(/\D/g, ''))} placeholder="______" autoFocus />
      </div>
      {info && <p className="alert-ok" role="status">{info}</p>}
      {err && <p className="alert-err" role="alert">{err}</p>}
      <button className="btn w-full py-3 text-base" disabled={busy || code.length < 4}>{busy ? 'Vérification…' : 'Valider'}</button>
      <div className="flex items-center justify-between text-sm">
        <button type="button" onClick={onBack} className="text-kx-muted hover:text-black hover:underline">← Retour</button>
        <button type="button" onClick={resend} className="font-semibold text-black underline underline-offset-4">Renvoyer le code</button>
      </div>
    </form>
  );
}
