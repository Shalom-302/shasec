'use client';

import { useCallback, useEffect, useRef, useState } from 'react';

// ---- API helper: all calls go through the same-origin /backend proxy ---------
async function api(path: string, opts: { method?: string; body?: any; token?: string } = {}) {
  const res = await fetch(`/backend${path}`, {
    method: opts.method || 'GET',
    headers: {
      'Content-Type': 'application/json',
      ...(opts.token ? { Authorization: `Bearer ${opts.token}` } : {}),
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  let json: any = null;
  try { json = await res.json(); } catch { /* empty */ }
  if (!res.ok || (json && json.code && json.code >= 400)) {
    const msg = json?.msg || json?.data?.errors?.[0]?.ctx?.error || `HTTP ${res.status}`;
    throw new Error(msg);
  }
  return json?.data ?? json;
}

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

// ---- Subdomain map: parse the subfinder triage finding into rows -------------
type SubRow = { kind: string; host: string; doc: string; title: string };

function parseSubdomainMap(findings: any[]): SubRow[] | null {
  const triage = findings.find(
    f => f.plugin === 'subfinder' && (f.title || '').startsWith('Cartographie des sous-domaines')
  );
  if (!triage?.evidence) return null;
  const rows: SubRow[] = triage.evidence
    .split('\n')
    .map((line: string) => {
      const [kind, host, doc, title] = line.split('|').map((s: string) => (s || '').trim());
      return { kind: kind || 'inconnu', host: host || '', doc: doc || '', title: title || '' };
    })
    .filter((r: SubRow) => r.host);
  // Enrich with the dedicated "Documentation d'API exposée" findings (host · kind · doc).
  findings
    .filter(f => f.plugin === 'subfinder' && (f.title || '').startsWith("Documentation d'API"))
    .forEach(f => {
      const parts = (f.evidence || '').split('·').map((s: string) => s.trim());
      const row = rows.find(r => r.host === parts[0]);
      if (row && !row.doc && parts[2]) row.doc = parts[2];
    });
  const rank = (k: string) => (k === 'api' ? 0 : k === 'frontend' ? 1 : 2);
  return rows.sort((a, b) => rank(a.kind) - rank(b.kind) || a.host.localeCompare(b.host));
}

function KindBadge({ kind }: { kind: string }) {
  const map: Record<string, [string, string]> = {
    api: ['API · Backend', 'var(--accent)'],
    frontend: ['Frontend', 'var(--accent2)'],
    inconnu: ['Inconnu', 'var(--info)'],
  };
  const [label, color] = map[kind] || map.inconnu;
  return (
    <span style={{ background: color, color: '#fff', fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 5, whiteSpace: 'nowrap' }}>
      {label}
    </span>
  );
}

function SubdomainMap({ rows }: { rows: SubRow[] }) {
  const apis = rows.filter(r => r.kind === 'api').length;
  const fronts = rows.filter(r => r.kind === 'frontend').length;
  const docs = rows.filter(r => r.doc).length;
  return (
    <div className="panel">
      <h2>Cartographie des sous-domaines · {rows.length} sondés</h2>
      <p className="sub" style={{ margin: '0 0 12px', fontSize: 12.5 }}>
        {apis} API/backend · {fronts} frontend · {docs} doc(s) d'API trouvée(s). Type déduit du contenu servi ;
        à confirmer manuellement, uniquement dans le scope.
      </p>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ textAlign: 'left', color: 'var(--muted)', fontSize: 11, textTransform: 'uppercase' }}>
              <th style={{ padding: '6px 8px' }}>Type</th>
              <th style={{ padding: '6px 8px' }}>Sous-domaine</th>
              <th style={{ padding: '6px 8px' }}>Doc API</th>
              <th style={{ padding: '6px 8px' }}>Titre</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i} style={{ borderTop: '1px solid var(--border)' }}>
                <td style={{ padding: '7px 8px' }}><KindBadge kind={r.kind} /></td>
                <td style={{ padding: '7px 8px' }}>
                  <a href={`https://${r.host}`} target="_blank" rel="noreferrer" className="mono">{r.host}</a>
                </td>
                <td style={{ padding: '7px 8px' }}>
                  {r.doc
                    ? <a href={r.doc} target="_blank" rel="noreferrer" className="mono" style={{ color: 'var(--accent2)' }}>{r.doc}</a>
                    : <span className="muted">—</span>}
                </td>
                <td style={{ padding: '7px 8px' }} className="muted">{r.title || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default function Page() {
  const [token, setToken] = useState<string | null>(null);
  const [email, setEmail] = useState('pentest-lab@kaanari.com');
  const [password, setPassword] = useState('Pentest#2026!');
  const [authErr, setAuthErr] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    try { const t = localStorage.getItem('shasec_token'); if (t) setToken(t); } catch {}
  }, []);

  const auth = async (mode: 'login' | 'register') => {
    setBusy(true); setAuthErr('');
    try {
      const data = await api(`/auth/${mode}`, { method: 'POST', body: { email, password } });
      const t = data.access_token;
      setToken(t);
      try { localStorage.setItem('shasec_token', t); } catch {}
    } catch (e: any) { setAuthErr(e.message); } finally { setBusy(false); }
  };

  const logout = () => { setToken(null); try { localStorage.removeItem('shasec_token'); } catch {} };

  if (!token) {
    return (
      <div className="wrap">
        <h1 className="h1">Shasec — Console pentest</h1>
        <p className="sub">Connecte-toi à l'API shaapi pour lancer des scans et lire les findings.</p>
        <div className="panel" style={{ maxWidth: 420 }}>
          <h2>Connexion</h2>
          <div style={{ marginBottom: 10 }}>
            <label>Email</label>
            <input className="grow" style={{ width: '100%' }} value={email} onChange={e => setEmail(e.target.value)} />
          </div>
          <div style={{ marginBottom: 14 }}>
            <label>Mot de passe</label>
            <input className="grow" style={{ width: '100%' }} type="password" value={password} onChange={e => setPassword(e.target.value)} />
          </div>
          <div className="row">
            <button disabled={busy} onClick={() => auth('login')}>Se connecter</button>
            <button className="ghost" disabled={busy} onClick={() => auth('register')}>Créer le compte</button>
          </div>
          {authErr && <div className="err">{authErr}</div>}
        </div>
      </div>
    );
  }

  return <Dashboard token={token} onLogout={logout} />;
}

// ---- Dashboard ---------------------------------------------------------------
function Dashboard({ token, onLogout }: { token: string; onLogout: () => void }) {
  const [url, setUrl] = useState('http://juiceshop.lab:3000');
  const [type, setType] = useState('website');
  const [scanId, setScanId] = useState<number | null>(null);
  const [progress, setProgress] = useState<any>(null);
  const [findings, setFindings] = useState<any[] | null>(null);
  const [raw, setRaw] = useState(false);
  const [err, setErr] = useState('');
  const [starting, setStarting] = useState(false);
  const poll = useRef<any>(null);

  const startScan = async () => {
    setErr(''); setFindings(null); setProgress(null); setStarting(true);
    try {
      const scan = await api('/scans/quick', { method: 'POST', token, body: { url, type } });
      setScanId(scan.id);
    } catch (e: any) { setErr(e.message); } finally { setStarting(false); }
  };

  // Poll progress until terminal, then load findings.
  useEffect(() => {
    if (!scanId) return;
    let stop = false;
    const tick = async () => {
      try {
        const p = await api(`/scans/${scanId}/progress`, { token });
        if (stop) return;
        setProgress(p);
        if (p.status === 'completed' || p.status === 'failed') {
          clearInterval(poll.current);
          const f = await api(`/scans/${scanId}/findings`, { token });
          const items = Array.isArray(f) ? f : (f.items ?? []);
          setFindings(items);
        }
      } catch (e: any) { setErr(e.message); }
    };
    tick();
    poll.current = setInterval(tick, 1500);
    return () => { stop = true; clearInterval(poll.current); };
  }, [scanId, token]);

  const subMap = findings ? parseSubdomainMap(findings) : null;
  const isMapFinding = (f: any) =>
    f.plugin === 'subfinder' &&
    ((f.title || '').startsWith('Cartographie des sous-domaines') || (f.title || '').startsWith("Documentation d'API"));
  const listFindings = (findings || []).filter(f => !(subMap && subMap.length && isMapFinding(f)));
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  listFindings.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
  const sorted = listFindings.slice().sort(
    (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
  );

  return (
    <div className="wrap">
      <div className="toolbar">
        <div>
          <h1 className="h1">Shasec — Console pentest</h1>
          <p className="sub" style={{ margin: 0 }}>Scan → progression → findings, sans quitter le navigateur.</p>
        </div>
        <button className="ghost" onClick={onLogout}>Déconnexion</button>
      </div>

      {/* Scan launcher */}
      <div className="panel">
        <h2>Nouveau quick scan</h2>
        <div className="row">
          <div className="grow">
            <label>Cible (URL http(s) ou hôte)</label>
            <input className="grow" style={{ width: '100%' }} value={url} onChange={e => setUrl(e.target.value)} placeholder="https://exemple.com" />
          </div>
          <div>
            <label>Type</label>
            <select value={type} onChange={e => setType(e.target.value)}>
              <option value="website">website</option>
              <option value="api">api</option>
              <option value="graphql">graphql</option>
              <option value="host">host</option>
            </select>
          </div>
          <div style={{ alignSelf: 'flex-end' }}>
            <button disabled={starting} onClick={startScan}>{starting ? 'Lancement…' : 'Lancer le scan'}</button>
          </div>
        </div>
        <p className="sub" style={{ margin: '10px 0 0', fontSize: 12 }}>
          Rappel manuel : uniquement des cibles autorisées (scope), débit faible, rien de destructif.
        </p>
        {err && <div className="err">{err}</div>}
      </div>

      {/* Live progress */}
      {progress && (
        <div className="panel">
          <h2>Progression {scanId ? `· scan #${scanId}` : ''}</h2>
          <div className="phase">
            <span><b>{progress.current_phase}</b> <span className="muted">· étape {progress.phase_index}/{progress.phase_total}</span></span>
            <span className="mono">{progress.percent}%</span>
          </div>
          <div className="bar"><span style={{ width: `${progress.percent}%` }} /></div>
          {progress.message && <p className="sub" style={{ margin: '8px 0 0', fontSize: 12.5 }}>{progress.message}</p>}

          {progress.scanners?.total > 0 && (
            <>
              <div style={{ marginTop: 10, fontSize: 12.5 }} className="muted">
                Scanners : {progress.scanners.done}/{progress.scanners.total} terminés
              </div>
              <div className="chips">
                {(progress.scanners.running || []).map((n: string) => (
                  <span key={n} className="chip run">▶ {n}</span>
                ))}
              </div>
            </>
          )}

          <div className="steps">
            {(progress.steps || []).slice().reverse().map((s: any, i: number) => (
              <div className="step" key={i}>
                <span className="mono muted">{(s.ts || '').slice(11, 19)}</span>
                <span><b>{s.phase || s.event}</b>{s.message ? ` — ${s.message}` : ''}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Subdomain map (frontend / API-backend / doc) */}
      {subMap && subMap.length > 0 && <SubdomainMap rows={subMap} />}

      {/* Findings */}
      {findings && (
        <div className="panel">
          <div className="toolbar" style={{ marginBottom: 12 }}>
            <h2 style={{ margin: 0 }}>Findings · {listFindings.length}</h2>
            <button className="ghost" onClick={() => setRaw(r => !r)}>{raw ? 'Vue lisible' : 'JSON brut'}</button>
          </div>

          {raw ? (
            <pre className="mono" style={{ maxHeight: 520, overflow: 'auto', background: '#0a0f1e', border: '1px solid var(--border)', borderRadius: 8, padding: 12, fontSize: 12 }}>
              {JSON.stringify(findings, null, 2)}
            </pre>
          ) : (
            <>
              <div className="statgrid">
                {SEV_ORDER.map(s => (
                  <div className="stat" key={s}>
                    <div className="n" style={{ color: `var(--${s === 'critical' ? 'crit' : s === 'high' ? 'high' : s === 'medium' ? 'med' : s === 'low' ? 'low' : 'info'})` }}>{counts[s]}</div>
                    <div className="l">{s}</div>
                  </div>
                ))}
              </div>
              {sorted.map((f, i) => (
                <details className="finding" key={i}>
                  <summary>
                    <span className={`sev ${f.severity}`}>{f.severity}</span>
                    <span className="ftitle">{f.title}</span>
                    <span className="fplugin">{f.plugin}</span>
                  </summary>
                  <div className="fbody">
                    {f.description && <p className="kv">{f.description}</p>}
                    {f.recommendation && <p className="kv"><b>Reco :</b> {f.recommendation}</p>}
                    {f.evidence && <pre>{f.evidence}</pre>}
                  </div>
                </details>
              ))}
              {sorted.length === 0 && <p className="muted">Aucun finding.</p>}
            </>
          )}
        </div>
      )}
    </div>
  );
}
