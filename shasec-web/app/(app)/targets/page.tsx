'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { ScopeAttestation } from '@/components/ScopeAttestation';
import { Empty, ErrorBox, Loading, Pager, PageHeader, TextLink, VerifiedBadge } from '@/components/ui';
import { api } from '@/lib/api';
import { fmtDate, TYPE_LABEL } from '@/lib/format';
import { TERMS_VERSION } from '@/lib/terms';
import type { Page, Target, TargetType } from '@/lib/types';
import { useAsync } from '@/lib/useAsync';

export default function TargetsPage() {
  const router = useRouter();
  const [page, setPage] = useState(1);
  const { data, error, loading, reload } = useAsync(
    () => api<Page<Target>>('/targets', { query: { page, size: 20 } }), [page],
  );

  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [type, setType] = useState<TargetType>('website');
  const [busy, setBusy] = useState(false);
  const [formErr, setFormErr] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [attest, setAttest] = useState(false);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormErr('');
    setBusy(true);
    try {
      const t = await api<Target>('/targets', { method: 'POST', body: { name: name.trim() || url.trim(), url: url.trim(), type } });
      await api(`/targets/${t.id}/authorize`, {
        method: 'POST', body: { is_authorized: true, accept_terms: true, terms_version: TERMS_VERSION },
      });
      router.push(`/scans/new?target=${t.id}`);
    } catch (e: any) {
      setFormErr(e.message);
      setBusy(false);
    }
  };

  const form = (
    <form onSubmit={create} className="card mb-6 space-y-4">
      <h2 className="card-title mb-0">Ajouter une application</h2>
      <div className="grid gap-4 md:grid-cols-[1fr_2fr_auto]">
        <div>
          <label className="label" htmlFor="t-name">Nom</label>
          <input id="t-name" className="input" placeholder="Mon site" value={name} onChange={e => setName(e.target.value)} />
        </div>
        <div>
          <label className="label" htmlFor="t-url">URL</label>
          <input id="t-url" className="input" placeholder="https://exemple.com" required value={url} onChange={e => setUrl(e.target.value)} />
        </div>
        <div>
          <label className="label" htmlFor="t-type">Type</label>
          <select id="t-type" className="input" value={type} onChange={e => setType(e.target.value as TargetType)}>
            {(Object.keys(TYPE_LABEL) as TargetType[]).map(k => <option key={k} value={k}>{TYPE_LABEL[k]}</option>)}
          </select>
        </div>
      </div>
      <ScopeAttestation checked={attest} onChange={setAttest} id="attest-new" />
      {formErr && <p className="alert-err" role="alert">{formErr}</p>}
      <div className="flex gap-2">
        <button className="btn" disabled={busy || !url.trim() || !attest}>{busy ? 'Ajout…' : 'Ajouter et continuer'}</button>
        <button type="button" className="btn-ghost" onClick={() => setShowForm(false)}>Annuler</button>
      </div>
    </form>
  );

  return (
    <>
      <PageHeader
        title="Mes applications"
        sub="Les sites, API et hôtes que vous auditez."
        actions={!showForm && <button className="btn" onClick={() => setShowForm(true)}>Ajouter une application</button>}
      />
      {showForm && form}
      {loading && <Loading />}
      {error && <ErrorBox message={error} onRetry={reload} />}
      {data && data.items.length === 0 && !showForm && (
        <Empty title="Aucune application" action={<button className="btn" onClick={() => setShowForm(true)}>Ajouter une application</button>}>
          Ajoutez l’URL de l’application à auditer pour commencer.
        </Empty>
      )}
      {data && data.items.length > 0 && (
        <div className="card overflow-x-auto p-0 sm:p-0">
          <table className="table">
            <thead><tr><th>Nom</th><th>URL</th><th>Type</th><th>Statut</th><th>Ajoutée le</th><th /></tr></thead>
            <tbody>
              {data.items.map(t => (
                <tr key={t.id}>
                  <td className="font-medium"><Link href={`/targets/${t.id}`} className="hover:underline">{t.name}</Link></td>
                  <td className="max-w-[16rem] truncate font-mono text-xs text-kx-muted" title={t.url}>{t.url}</td>
                  <td className="text-kx-muted">{TYPE_LABEL[t.type] || t.type}</td>
                  <td><VerifiedBadge ok={t.is_authorized} /></td>
                  <td className="whitespace-nowrap text-kx-muted">{fmtDate(t.created_time, false)}</td>
                  <td className="whitespace-nowrap text-right">
                    {t.is_authorized
                      ? <TextLink href={`/scans/new?target=${t.id}`}>Scanner</TextLink>
                      : <TextLink href={`/targets/${t.id}`}>Autoriser</TextLink>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {data && <Pager page={page} totalPages={data.total_pages} onPage={setPage} />}
    </>
  );
}
