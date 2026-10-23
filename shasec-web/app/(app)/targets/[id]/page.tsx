'use client';

import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import { useState } from 'react';
import { ErrorBox, Loading, PageHeader, StatusBadge, TextLink, VerifiedBadge } from '@/components/ui';
import { api } from '@/lib/api';
import { fmtDate, PROFILE_LABEL, TYPE_LABEL } from '@/lib/format';
import type { Page, Scan, Target } from '@/lib/types';
import { useAsync } from '@/lib/useAsync';

function CopyField({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div>
      <span className="label">{label}</span>
      <div className="flex gap-2">
        <code className="min-w-0 flex-1 break-all rounded-lg border border-kx-border bg-kx-bg px-3 py-2 font-mono text-xs">{value}</code>
        <button
          type="button"
          className="btn-ghost shrink-0 px-3"
          onClick={async () => {
            try { await navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch {}
          }}
        >
          {copied ? 'Copié' : 'Copier'}
        </button>
      </div>
    </div>
  );
}

export default function TargetDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const target = useAsync(() => api<Target>(`/targets/${id}`), [id]);
  const scans = useAsync(() => api<Page<Scan>>('/scans', { query: { target_id: id, page: 1, size: 10 } }), [id]);
  const [busy, setBusy] = useState('');
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const verify = async () => {
    setBusy('verify'); setMsg(null);
    try {
      const t = await api<Target>(`/targets/${id}/verify`, { method: 'POST' });
      target.setData(t);
      setMsg({ ok: true, text: 'Propriété vérifiée. Vous pouvez maintenant scanner cette application.' });
    } catch (e: any) {
      setMsg({ ok: false, text: e.message });
    } finally { setBusy(''); }
  };

  const revoke = async () => {
    if (!confirm('Retirer l’autorisation de scan ? Il faudra re-vérifier la propriété pour scanner à nouveau.')) return;
    setBusy('revoke'); setMsg(null);
    try {
      await api(`/targets/${id}/authorize`, { method: 'POST', body: { is_authorized: false } });
      await target.reload();
    } catch (e: any) { setMsg({ ok: false, text: e.message }); } finally { setBusy(''); }
  };

  const remove = async () => {
    if (!confirm('Supprimer cette application et tout son historique de scans ?')) return;
    setBusy('delete');
    try {
      await api('/targets', { method: 'DELETE', query: { pk: id } });
      router.push('/targets');
    } catch (e: any) { setMsg({ ok: false, text: e.message }); setBusy(''); }
  };

  if (target.loading && !target.data) return <Loading />;
  if (target.error) return <ErrorBox message={target.error} onRetry={target.reload} />;
  const t = target.data!;

  return (
    <>
      <p className="mb-2 text-sm"><TextLink href="/targets">← Mes applications</TextLink></p>
      <PageHeader
        title={t.name}
        sub={<span className="font-mono">{t.url}</span>}
        actions={t.is_authorized && <Link href={`/scans/new?target=${t.id}`} className="btn">Lancer un scan</Link>}
      />

      <div className="grid gap-6 lg:grid-cols-3">
        <section className="card space-y-3 lg:col-span-1">
          <h2 className="card-title">Informations</h2>
          <Row k="Type" v={TYPE_LABEL[t.type] || t.type} />
          <Row k="Statut" v={<VerifiedBadge ok={t.is_authorized} />} />
          {t.verified_at && <Row k="Vérifiée le" v={fmtDate(t.verified_at)} />}
          <Row k="Ajoutée le" v={fmtDate(t.created_time)} />
          <div className="flex flex-wrap gap-2 pt-2">
            {t.is_authorized && <button className="btn-ghost px-3 py-1.5" disabled={!!busy} onClick={revoke}>Retirer l’autorisation</button>}
            <button className="btn-danger" disabled={!!busy} onClick={remove}>Supprimer</button>
          </div>
        </section>

        <section className="card space-y-4 lg:col-span-2">
          <h2 className="card-title">Preuve de propriété</h2>
          {t.is_authorized ? (
            <p className="alert-ok">Cette application est vérifiée : vous pouvez la scanner.</p>
          ) : (
            <>
              <p className="text-sm text-kx-muted">
                Pour protéger les sites des tiers, un scan n’est possible qu’après avoir prouvé que vous contrôlez
                l’application. Publiez le fichier ci-dessous sur le serveur, puis cliquez sur « Vérifier ».
              </p>
              <ol className="list-decimal space-y-3 pl-5 text-sm">
                <li>
                  Créez un fichier texte accessible publiquement à cette adresse :
                  {t.verify_url && <div className="mt-2"><CopyField label="Adresse du fichier" value={t.verify_url} /></div>}
                </li>
                <li>
                  Placez-y exactement ce contenu :
                  {t.verify_token && <div className="mt-2"><CopyField label="Contenu du fichier" value={t.verify_token} /></div>}
                </li>
                <li>Le fichier doit répondre en HTTP 200, sans redirection.</li>
              </ol>
              <button className="btn" onClick={verify} disabled={!!busy}>{busy === 'verify' ? 'Vérification…' : 'Vérifier maintenant'}</button>
            </>
          )}
          {msg && <p className={msg.ok ? 'alert-ok' : 'alert-err'} role="status">{msg.text}</p>}
        </section>
      </div>

      <section className="card mt-6">
        <h2 className="card-title">Scans de cette application</h2>
        {scans.loading && <Loading />}
        {scans.error && <ErrorBox message={scans.error} onRetry={scans.reload} />}
        {scans.data && scans.data.items.length === 0 && <p className="text-sm text-kx-muted">Aucun scan pour l’instant.</p>}
        {scans.data && scans.data.items.length > 0 && (
          <div className="overflow-x-auto">
            <table className="table">
              <thead><tr><th>#</th><th>Profil</th><th>Statut</th><th>Date</th><th /></tr></thead>
              <tbody>
                {scans.data.items.map(s => (
                  <tr key={s.id}>
                    <td className="text-kx-muted">{s.id}</td>
                    <td>{PROFILE_LABEL[s.profile]?.name || s.profile}</td>
                    <td><StatusBadge status={s.status} /></td>
                    <td className="whitespace-nowrap text-kx-muted">{fmtDate(s.created_time)}</td>
                    <td className="text-right"><TextLink href={`/scans/${s.id}`}>Détail</TextLink></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3 text-sm">
      <span className="text-kx-muted">{k}</span>
      <span className="text-right">{v}</span>
    </div>
  );
}
