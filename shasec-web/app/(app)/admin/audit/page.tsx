'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';
import AdminOnly from '@/components/AdminOnly';
import { PageHeader, TextLink } from '@/components/ui';
import { api } from '@/lib/api';
import type { Scan, ScanProfile } from '@/lib/types';

const PROFILES: { v: ScanProfile; name: string; hint: string }[] = [
  { v: 'fast', name: 'Rapide', hint: 'Reconnaissance légère' },
  { v: 'standard', name: 'Standard', hint: 'Scanners principaux' },
  { v: 'deep', name: 'Approfondi', hint: 'Outillage complet' },
];

function AuditLauncher() {
  const router = useRouter();
  const [url, setUrl] = useState('');
  const [type, setType] = useState<'website' | 'api'>('website');
  const [profile, setProfile] = useState<ScanProfile>('deep');
  const [active, setActive] = useState(true);
  const [aggressive, setAggressive] = useState(false);
  const [token, setToken] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  const launch = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setErr('');
    try {
      const scan = await api<Scan>('/scans/audit', {
        method: 'POST',
        body: {
          url: url.trim(), type, profile,
          allow_active_exploitation: active,
          aggression: aggressive ? 'aggressive' : 'safe',
          auth_token: token.trim() || null,
        },
      });
      router.push(`/scans/${scan.id}`);
    } catch (e: any) { setErr(e.message); setBusy(false); }
  };

  return (
    <form onSubmit={launch} className="card max-w-2xl space-y-5">
      <div className="rounded-xl border border-kx-border bg-kx-panel2 p-4 text-sm text-kx-muted">
        La chasse en 5 étapes : <b className="text-kx-text">1</b> cartographie du domaine (sous-domaines, hôtes vivants,
        stack), puis vous choisissez le périmètre, puis <b className="text-kx-text">2</b> scan passif + actif,
        <b className="text-kx-text"> 3</b> accès anonyme, <b className="text-kx-text">4</b> validation contrôlée, et
        <b className="text-kx-text"> 5</b> le rapport — généré à la demande, pas à chaque scan.
      </div>

      <div>
        <label className="label" htmlFor="a-url">Domaine ou URL</label>
        <input id="a-url" className="input" required placeholder="https://exemple.com" value={url} onChange={e => setUrl(e.target.value)} />
        <p className="hint">La cartographie énumère les sous-domaines de ce domaine (recon passive).</p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <label className="label" htmlFor="a-type">Type attendu</label>
          <select id="a-type" className="input" value={type} onChange={e => setType(e.target.value as any)}>
            <option value="website">Site web</option>
            <option value="api">API</option>
          </select>
        </div>
        <div>
          <label className="label" htmlFor="a-profile">Profil (par hôte sélectionné)</label>
          <select id="a-profile" className="input" value={profile} onChange={e => setProfile(e.target.value as ScanProfile)}>
            {PROFILES.map(p => <option key={p.v} value={p.v}>{p.name} — {p.hint}</option>)}
          </select>
        </div>
      </div>

      <div className="space-y-3 rounded-xl border border-kx-border p-4">
        <label className="flex cursor-pointer items-start gap-3 text-sm">
          <input type="checkbox" className="mt-0.5 h-4 w-4 accent-black" checked={active} onChange={e => setActive(e.target.checked)} />
          <span><b>Exploitation active</b> — envoie les sondes XSS/injection/contrôle d’accès (BOLA/BFLA) et collecte les preuves. Bornée, non destructive.</span>
        </label>
        <label className="flex cursor-pointer items-start gap-3 text-sm">
          <input type="checkbox" className="mt-0.5 h-4 w-4 accent-black" checked={aggressive} onChange={e => setAggressive(e.target.checked)} disabled={!active} />
          <span><b>Mode agressif</b> — élargit la couverture (plages d’ID, chemins) sans augmenter le volume de requêtes.</span>
        </label>
        <div>
          <label className="label" htmlFor="a-token">Jeton d’authentification (optionnel)</label>
          <input id="a-token" className="input font-mono text-xs" value={token} onChange={e => setToken(e.target.value)}
            placeholder="eyJ… (sans « Bearer »)" autoComplete="off" />
          <p className="hint">Nécessaire pour tester BOLA/BFLA (accès inter-objets d’un compte authentifié). Jamais stocké.</p>
        </div>
      </div>

      {err && <p className="alert-err" role="alert">{err}</p>}
      <button className="btn" disabled={busy || !url.trim()}>{busy ? 'Cartographie en cours…' : 'Lancer la cartographie'}</button>
      <p className="text-xs text-kx-muted">
        Compte opérateur : non facturé. En lançant cet audit, vous confirmez être autorisé à tester ce domaine.
        <TextLink href="/scans"> Voir mes scans</TextLink>
      </p>
    </form>
  );
}

export default function AuditPage() {
  return (
    <AdminOnly>
      <PageHeader title="Audit de domaine" sub="Cartographie puis chasse en 5 étapes sur les hôtes sélectionnés." />
      <AuditLauncher />
    </AdminOnly>
  );
}
