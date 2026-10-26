'use client';

import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import { useState } from 'react';
import { ScopeAttestation } from '@/components/ScopeAttestation';
import { ErrorBox, Loading, PageHeader, StatusBadge, TextLink, VerifiedBadge } from '@/components/ui';
import { api } from '@/lib/api';
import { fmtDate, PROFILE_LABEL, TYPE_LABEL } from '@/lib/format';
import { TERMS_VERSION } from '@/lib/terms';
import type { Page, Scan, Target, TargetType } from '@/lib/types';
import { useAsync } from '@/lib/useAsync';

export default function TargetDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const target = useAsync(() => api<Target>(`/targets/${id}`), [id]);
  const scans = useAsync(() => api<Page<Scan>>('/scans', { query: { target_id: id, page: 1, size: 10 } }), [id]);
  const [busy, setBusy] = useState('');
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [attest, setAttest] = useState(false);

  const authorize = async () => {
    setBusy('authorize'); setMsg(null);
    try {
      const t = await api<Target>(`/targets/${id}/authorize`, {
        method: 'POST', body: { is_authorized: true, accept_terms: true, terms_version: TERMS_VERSION },
      });
      target.setData(t);
      setAttest(false);
      setMsg({ ok: true, text: 'Scan autorisé. Vous pouvez maintenant lancer un scan sur cette application.' });
    } catch (e: any) {
      setMsg({ ok: false, text: e.message });
    } finally { setBusy(''); }
  };

  const revoke = async () => {
    if (!confirm('Retirer l’autorisation de scan ? Il faudra attester à nouveau pour scanner cette application.')) return;
    setBusy('revoke'); setMsg(null);
    try {
      target.setData(await api<Target>(`/targets/${id}/authorize`, { method: 'POST', body: { is_authorized: false } }));
    } catch (e: any) { setMsg({ ok: false, text: e.message }); } finally { setBusy(''); }
  };

  const [edit, setEdit] = useState<{ name: string; url: string; type: TargetType } | null>(null);
  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!edit || !target.data) return;
    const urlChanged = edit.url.trim() !== target.data.url;
    if (urlChanged && target.data.is_authorized
      && !confirm('Changer l’URL retire l’autorisation de scan : il faudra attester à nouveau. Continuer ?')) return;
    setBusy('edit'); setMsg(null);
    try {
      await api(`/targets/${id}`, { method: 'PUT', body: { name: edit.name.trim() || edit.url.trim(), url: edit.url.trim(), type: edit.type } });
      setEdit(null);
      target.setData(await api<Target>(`/targets/${id}`));
      setMsg({ ok: true, text: 'Application modifiée.' });
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
          {edit ? (
            <form onSubmit={save} className="space-y-3">
              <div>
                <label className="label" htmlFor="e-name">Nom</label>
                <input id="e-name" className="input" value={edit.name} onChange={e => setEdit({ ...edit, name: e.target.value })} />
              </div>
              <div>
                <label className="label" htmlFor="e-url">URL</label>
                <input id="e-url" className="input" required value={edit.url} onChange={e => setEdit({ ...edit, url: e.target.value })} />
              </div>
              <div>
                <label className="label" htmlFor="e-type">Type</label>
                <select id="e-type" className="input" value={edit.type} onChange={e => setEdit({ ...edit, type: e.target.value as TargetType })}>
                  {(Object.keys(TYPE_LABEL) as TargetType[]).map(k => <option key={k} value={k}>{TYPE_LABEL[k]}</option>)}
                </select>
              </div>
              <div className="flex gap-2">
                <button className="btn btn-sm" disabled={!!busy || !edit.url.trim()}>{busy === 'edit' ? 'Enregistrement…' : 'Enregistrer'}</button>
                <button type="button" className="btn-ghost btn-sm" onClick={() => setEdit(null)}>Annuler</button>
              </div>
            </form>
          ) : (
            <>
              <Row k="Type" v={TYPE_LABEL[t.type] || t.type} />
              <Row k="Statut" v={<VerifiedBadge ok={t.is_authorized} />} />
              {t.authorized_at && <Row k="Autorisée le" v={fmtDate(t.authorized_at)} />}
              <Row k="Ajoutée le" v={fmtDate(t.created_time)} />
              <div className="flex flex-wrap gap-2 pt-2">
                <button className="btn-ghost btn-sm" disabled={!!busy} onClick={() => setEdit({ name: t.name, url: t.url, type: t.type })}>Modifier</button>
                {t.is_authorized && <button className="btn-ghost btn-sm" disabled={!!busy} onClick={revoke}>Retirer l’autorisation</button>}
                <button className="btn-danger" disabled={!!busy} onClick={remove}>Supprimer</button>
              </div>
            </>
          )}
        </section>

        <section className="card space-y-4 lg:col-span-2">
          <h2 className="card-title">Autorisation de scan</h2>
          {t.is_authorized ? (
            <p className="alert-ok">
              Scan autorisé{t.authorized_at ? ` le ${fmtDate(t.authorized_at)}` : ''}
              {t.terms_version ? ` · conditions d’utilisation du ${t.terms_version}` : ''}.
            </p>
          ) : (
            <>
              <p className="text-kx-muted">
                Avant le premier scan, confirmez que vous êtes autorisé à tester cette application.
              </p>
              <ScopeAttestation checked={attest} onChange={setAttest} />
              <button className="btn" onClick={authorize} disabled={!attest || !!busy}>
                {busy === 'authorize' ? 'Enregistrement…' : 'Autoriser le scan'}
              </button>
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
