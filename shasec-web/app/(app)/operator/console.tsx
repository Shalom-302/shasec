'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { SEV_FR, SEV_ORDER, STATUS_FR, groupFindings } from '@/lib/findings';

// ---- API helper: same-origin /api/k proxy (session in httpOnly cookies) ------
// The operator console is admin-only; the server attaches the Bearer token.
async function api(path: string, opts: { method?: string; body?: any; token?: string } = {}) {
  const res = await fetch(`/api/k${path}`, {
    method: opts.method || 'GET',
    headers: opts.body ? { 'Content-Type': 'application/json' } : undefined,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  let json: any = null;
  try { json = await res.json(); } catch {}
  if (res.status === 401) {
    window.location.href = '/login?next=/operator';
    throw new Error('Session expirée');
  }
  if (!res.ok || (json && json.code && json.code >= 400)) {
    throw new Error(json?.msg || `HTTP ${res.status}`);
  }
  return json?.data ?? json;
}


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

function SubdomainMap({ rows, onScan, scanning }: { rows: SubRow[]; onScan: (host: string, kind: string) => void; scanning: boolean }) {
  const apis = rows.filter(r => r.kind === 'api').length;
  const fronts = rows.filter(r => r.kind === 'frontend').length;
  const docs = rows.filter(r => r.doc).length;
  const [sel, setSel] = useState('');
  const selRow = rows.find(r => r.host === sel);
  return (
    <div className="panel">
      <h2>Cartographie des sous-domaines · {rows.length} sondés</h2>
      <p className="sub" style={{ margin: '0 0 12px', fontSize: 12.5 }}>
        {apis} API/backend · {fronts} frontend · {docs} doc(s) d'API trouvée(s). Type déduit du contenu servi ;
        à confirmer manuellement, uniquement dans le scope.
      </p>

      {/* Per-subdomain scan: pick one host and run the full pipeline on it, just
          like the global scan. (A dedicated button per row does the same below.) */}
      <div className="row" style={{ margin: '0 0 14px', alignItems: 'flex-end' }}>
        <div className="grow">
          <label>Scanner un sous-domaine en détail</label>
          <select className="grow" style={{ width: '100%' }} value={sel} onChange={e => setSel(e.target.value)}>
            <option value="">— choisir un sous-domaine —</option>
            {rows.map(r => (
              <option key={r.host} value={r.host}>{r.host} ({r.kind})</option>
            ))}
          </select>
        </div>
        <div style={{ alignSelf: 'flex-end' }}>
          <button disabled={!sel || scanning} onClick={() => selRow && onScan(selRow.host, selRow.kind)}>
            {scanning ? 'Lancement…' : 'Lancer le scan'}
          </button>
        </div>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ textAlign: 'left', color: 'var(--muted)', fontSize: 11, textTransform: 'uppercase' }}>
              <th style={{ padding: '6px 8px' }}>Type</th>
              <th style={{ padding: '6px 8px' }}>Sous-domaine</th>
              <th style={{ padding: '6px 8px' }}>Doc API</th>
              <th style={{ padding: '6px 8px' }}>Titre</th>
              <th style={{ padding: '6px 8px' }}>Action</th>
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
                <td style={{ padding: '7px 8px' }}>
                  <button className="ghost" style={{ fontSize: 12, padding: '4px 10px' }}
                    disabled={scanning} onClick={() => onScan(r.host, r.kind)}>
                    {scanning ? '…' : 'Scanner'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// Short, stable label for a scan tab: the target host (falls back to the raw URL).
function hostLabel(u: string): string {
  try { return new URL(u.includes('://') ? u : `https://${u}`).host; } catch { return u; }
}

export default function OperatorConsole() {
  // Session handled by the app shell; no credentials ever live in this bundle.
  return <Dashboard token="" onLogout={() => { window.location.href = '/dashboard'; }} />;
}

// ---- Dashboard ---------------------------------------------------------------
function Dashboard({ token, onLogout }: { token: string; onLogout: () => void }) {
  const [url, setUrl] = useState('');
  const [type, setType] = useState('website');
  // Scan history kept in-session: the global scan and every per-subdomain scan
  // coexist. `activeId` is the one on screen; `store` holds each scan's own
  // progress/findings/exploits so switching tabs never erases another's result.
  const [scans, setScans] = useState<{ id: number; label: string; url: string; type: string }[]>([]);
  const [activeId, setActiveId] = useState<number | null>(null);
  const [store, setStore] = useState<Record<number, { progress: any; findings: any[] | null; exploits: any[] | null }>>({});
  const [repReq, setRepReq] = useState<ReqState>({ method: 'GET', url: '', headers: '', body: '', allowWrite: false });
  const [raw, setRaw] = useState(false);
  const [err, setErr] = useState('');
  const [starting, setStarting] = useState(false);
  // Active-exploitation controls (lot 2). OFF by default — prod-safe.
  const [activeExploit, setActiveExploit] = useState(false);
  const [authToken, setAuthToken] = useState('');
  const [idRange, setIdRange] = useState('1-10');
  const [allowDestructive, setAllowDestructive] = useState(false);
  // Chasse aux sorcières — scan depth/speed profile and exploit aggression.
  const [profile, setProfile] = useState('standard'); // fast | standard | deep
  const [aggressive, setAggressive] = useState(false); // widens bounded coverage
  // Explicit, affirmative scope authorization — required to enable active
  // exploitation. Makes the "authorized target" gate visible instead of implicit.
  const [authorizedScope, setAuthorizedScope] = useState(false);
  const poll = useRef<any>(null);
  // Mirror of `store` for the poll effect's "already loaded?" guard, so the effect
  // needn't depend on `store` (which would respawn the interval on every tick).
  const storeRef = useRef(store);
  storeRef.current = store;

  // `over` lets a caller (e.g. the subdomain map) launch a scan on a specific
  // URL/type without waiting for the `url`/`type` state to flush.
  const startScan = async (over?: { url?: string; type?: string }) => {
    const u = over?.url ?? url;
    const t = over?.type ?? type;
    if (activeExploit && !authorizedScope) {
      setErr('Confirme d’abord que la cible est dans ton périmètre autorisé (case à cocher) pour lancer l’exploitation active.');
      return;
    }
    setErr(''); setStarting(true);
    try {
      const body: any = { url: u, type: t, allow_active_exploitation: activeExploit, profile };
      if (authToken.trim()) body.auth_token = authToken.trim();
      if (activeExploit) {
        if (idRange.trim()) body.id_range = idRange.trim();
        body.allow_destructive = allowDestructive;
        body.aggression = aggressive ? 'aggressive' : 'safe';
      }
      const scan = await api('/scans/quick', { method: 'POST', token, body });
      const label = hostLabel(u);
      // Register the new scan without touching the others, then focus it.
      setScans(prev => (prev.some(s => s.id === scan.id) ? prev : [...prev, { id: scan.id, label, url: u, type: t }]));
      setStore(prev => ({ ...prev, [scan.id]: { progress: null, findings: null, exploits: null } }));
      setActiveId(scan.id);
    } catch (e: any) { setErr(e.message); } finally { setStarting(false); }
  };

  // Launch a dedicated scan on one discovered subdomain — same pipeline as the
  // global scan. Reflects the choice in the launcher, scrolls up to the progress,
  // and reuses startScan so findings/progress/leads render identically.
  const scanHost = (host: string, kind: string) => {
    const t = kind === 'api' ? 'api' : 'website';
    const u = `https://${host}`;
    setUrl(u); setType(t);
    try { window.scrollTo({ top: 0, behavior: 'smooth' }); } catch {}
    startScan({ url: u, type: t });
  };

  // Poll the active scan until terminal, then load its findings — writing into
  // that scan's slot in `store`. If its findings are already loaded (a completed
  // scan we're revisiting), don't poll: its result stays as-is.
  useEffect(() => {
    if (activeId == null) return;
    const id = activeId;
    if (storeRef.current[id]?.findings != null) return; // already terminal & loaded
    let stop = false;
    const put = (patch: Partial<{ progress: any; findings: any[] | null; exploits: any[] | null }>) =>
      setStore(s => ({ ...s, [id]: { ...(s[id] ?? { progress: null, findings: null, exploits: null }), ...patch } }));
    const tick = async () => {
      try {
        const p = await api(`/scans/${id}/progress`, { token });
        if (stop) return;
        put({ progress: p });
        if (p.status === 'completed' || p.status === 'failed') {
          clearInterval(poll.current);
          const f = await api(`/scans/${id}/findings`, { token });
          const findings = Array.isArray(f) ? f : (f.items ?? []);
          let exploits: any[] = [];
          try {
            const ex = await api(`/scans/${id}/exploits`, { token });
            exploits = Array.isArray(ex) ? ex : (ex.items ?? []);
          } catch { exploits = []; }
          if (!stop) put({ findings, exploits });
        }
      } catch (e: any) { setErr(e.message); }
    };
    tick();
    poll.current = setInterval(tick, 1500);
    return () => { stop = true; clearInterval(poll.current); };
  }, [activeId, token]);

  const active = activeId != null ? store[activeId] : undefined;
  const activeScan = scans.find(s => s.id === activeId);
  const progress = active?.progress ?? null;
  const findings = active?.findings ?? null;
  const exploits = active?.exploits ?? null;

  const subMap = findings ? parseSubdomainMap(findings) : null;
  const isMapFinding = (f: any) =>
    f.plugin === 'subfinder' &&
    ((f.title || '').startsWith('Cartographie des sous-domaines') || (f.title || '').startsWith("Documentation d'API"));
  const listFindings = (findings || []).filter(f => !(subMap && subMap.length && isMapFinding(f)));
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  listFindings.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1; });
  const grouped = groupFindings(listFindings);

  return (
    <div className="wrap">
      <div className="toolbar">
        <div>
          <h1 className="h1">Console opérateur</h1>
          <p className="sub" style={{ margin: 0 }}>Scan → progression → findings, sans quitter le navigateur.</p>
        </div>
        <button className="ghost" onClick={onLogout}>← Retour au dashboard</button>
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
          <div>
            <label>Profil (vitesse)</label>
            <select value={profile} onChange={e => setProfile(e.target.value)}
              title="fast = recon rapide · standard = équilibré · deep = tous les outils lourds">
              <option value="fast">fast · recon rapide (~2 min)</option>
              <option value="standard">standard · équilibré</option>
              <option value="deep">deep · complet (lent)</option>
            </select>
          </div>
          <div style={{ alignSelf: 'flex-end' }}>
            <button disabled={starting} onClick={() => startScan()}>{starting ? 'Lancement…' : 'Lancer le scan'}</button>
          </div>
        </div>

        {/* Explicit scope authorization — the "authorized target" gate, made
            visible. Required before any active exploitation can be enabled. */}
        <label style={{ display: 'flex', alignItems: 'flex-start', gap: 8, marginTop: 14,
            padding: '10px 12px', border: `1px solid ${authorizedScope ? 'var(--accent)' : 'var(--border)'}`,
            borderRadius: 8, cursor: 'pointer' }}>
          <input type="checkbox" checked={authorizedScope}
            onChange={e => { setAuthorizedScope(e.target.checked); if (!e.target.checked) setActiveExploit(false); }} />
          <span style={{ fontSize: 12.5 }}>
            <b>Je confirme que cette cible est dans mon périmètre autorisé (scope).</b><br />
            Requis pour activer l'exploitation active. Cette confirmation est ta traçabilité — ne coche
            que des cibles pour lesquelles tu détiens une autorisation écrite.
          </span>
        </label>

        {/* Active-exploitation options (lot 2) — gated by the scope confirmation above */}
        <div className="row" style={{ marginTop: 12, alignItems: 'flex-end', opacity: authorizedScope ? 1 : 0.5 }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: authorizedScope ? 'pointer' : 'not-allowed' }}
            title={authorizedScope ? '' : 'Coche d’abord la confirmation de périmètre autorisé.'}>
            <input type="checkbox" disabled={!authorizedScope} checked={activeExploit} onChange={e => setActiveExploit(e.target.checked)} />
            Exploitation active (bypass /admin, mots de passe par défaut, Postgres, BOLA, XSS, SQLi, GraphQL…)
          </label>
          <div className="grow">
            <label>Token (Bearer, sans le préfixe) — pour BOLA/BFLA/JWT</label>
            <input className="grow" style={{ width: '100%' }} value={authToken} onChange={e => setAuthToken(e.target.value)} placeholder="eyJhbGci…" />
          </div>
        </div>
        {activeExploit && (
          <div className="row" style={{ marginTop: 8, alignItems: 'flex-end' }}>
            <div>
              <label>Plage d'IDs (BOLA)</label>
              <input style={{ width: 120 }} value={idRange} onChange={e => setIdRange(e.target.value)} placeholder="1-10" />
            </div>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', color: 'var(--crit)' }}>
              <input type="checkbox" checked={allowDestructive} onChange={e => setAllowDestructive(e.target.checked)} />
              ⚠️ Verbes destructifs (PUT/PATCH/DELETE réels) — JAMAIS en prod
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}
              title="Élargit la couverture (plus de chemins admin/login testés, plage d'IDs plus large). Jamais destructif, jamais de surcharge.">
              <input type="checkbox" checked={aggressive} onChange={e => setAggressive(e.target.checked)} />
              🔥 Mode agressif (couverture élargie, sans casse ni surcharge)
            </label>
          </div>
        )}
        <p className="sub" style={{ margin: '10px 0 0', fontSize: 12 }}>
          L'exploitation active exige la confirmation de périmètre ci-dessus, et se limite au scope + débit faible.
          Sans « verbes destructifs », la détection reste non destructive (OPTIONS-first, stop-at-proof).
        </p>
        {err && <div className="err">{err}</div>}
      </div>

      {/* Scan tabs: global scan + each per-subdomain scan coexist; click to switch.
          Nothing is erased — every scan keeps its own progress/findings/exploits. */}
      {scans.length > 0 && (
        <div className="panel" style={{ padding: '10px 12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span className="muted" style={{ fontSize: 12, textTransform: 'uppercase' }}>Scans</span>
            {scans.map(s => {
              const st = store[s.id];
              const done = st?.findings != null;
              const failed = st?.progress?.status === 'failed';
              const dot = failed ? 'var(--crit)' : done ? 'var(--low)' : 'var(--accent)';
              const isActive = s.id === activeId;
              return (
                <button
                  key={s.id}
                  className={isActive ? '' : 'ghost'}
                  style={{ fontSize: 12.5, padding: '5px 10px', display: 'inline-flex', alignItems: 'center', gap: 6 }}
                  onClick={() => setActiveId(s.id)}
                  title={s.url}
                >
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: dot, display: 'inline-block' }} />
                  {s.label}
                  <span className="muted">#{s.id}</span>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Live progress */}
      {progress && (
        <div className="panel">
          <h2>Progression {activeId ? `· scan #${activeId}${activeScan ? ` · ${activeScan.label}` : ''}` : ''}</h2>
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
      {subMap && subMap.length > 0 && <SubdomainMap rows={subMap} onScan={scanHost} scanning={starting} />}

      {/* Findings */}
      {findings && (
        <div className="panel">
          <div className="toolbar" style={{ marginBottom: 12 }}>
            <h2 style={{ margin: 0 }}>Résultats · {grouped.length} type(s) · {listFindings.length} au total</h2>
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
                    <div className="l">{SEV_FR[s] || s}</div>
                  </div>
                ))}
              </div>
              {grouped.map((g) => (
                <details className="finding" key={g.key}>
                  <summary>
                    <span className={`sev ${g.severity}`}>{SEV_FR[g.severity] || g.severity}</span>
                    <span className="ftitle">{g.fr}{g.count > 1 ? ` · ${g.count}×` : ''}</span>
                    <span className="fplugin">{g.plugin}</span>
                  </summary>
                  <div className="fbody">
                    {g.why && <p className="kv"><b>Pourquoi c'est un risque :</b> {g.why}</p>}
                    {g.fix && <p className="kv"><b>Correctif :</b> {g.fix}</p>}
                    {g.fr !== g.title && <p className="kv muted" style={{ fontSize: 12 }}>Intitulé source (outil) : {g.title}</p>}
                    {g.samples.length > 0 && (
                      <pre>{g.samples.join('\n')}{g.count > g.samples.length ? `\n… (+${g.count - g.samples.length} autre(s))` : ''}</pre>
                    )}
                  </div>
                </details>
              ))}
              {grouped.length === 0 && <p className="muted">Aucun résultat.</p>}
            </>
          )}
        </div>
      )}

      {/* Exploit proofs (lot 2 — active verifiers) */}
      {exploits && exploits.length > 0 && (
        <div className="panel">
          <h2 style={{ marginTop: 0 }}>Preuves d'exploitation · {exploits.length}</h2>
          <p className="sub" style={{ margin: '0 0 12px', fontSize: 12.5 }}>
            Détection non destructive : chaque preuve porte la requête/réponse exacte. « confirmé » = signal
            reproduit ; sinon candidat à vérifier.
          </p>
          {exploits.slice().sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)).map((e, i) => (
            <details className="finding" key={i}>
              <summary>
                <span className={`sev ${e.severity}`}>{e.severity}</span>
                <span className="ftitle">{e.title}</span>
                <span className="fplugin">{STATUS_FR[e.status] || (e.confirmed ? '✓ confirmé' : 'à vérifier')} · {e.category || e.module}</span>
              </summary>
              <div className="fbody">
                {e.impact && <p className="kv"><b>Impact :</b> {e.impact}</p>}
                {e.request && <pre><b>→ Requête</b>{'\n'}{e.request}</pre>}
                {e.response && <pre><b>← Réponse</b>{'\n'}{e.response}</pre>}
              </div>
            </details>
          ))}
        </div>
      )}

      {/* Test leads: concrete next actions derived from the scan → one-click into the Repeater */}
      {findings && <Leads findings={findings} scanUrl={activeScan?.url ?? url} onLoad={(a) => setRepReq({ method: 'GET', url: '', headers: '', body: '', allowWrite: false, ...a })} />}

      {/* Repeater (proxy) — replay/modify one request, scope-locked, read-only by default */}
      <Repeater token={token} req={repReq} setReq={setRepReq} />
    </div>
  );
}

// ---- Test leads: turn scan results into concrete "what to do next" actions ----
type ReqState = { method: string; url: string; headers: string; body: string; allowWrite: boolean };
type Lead = { key: string; prio: number; sev: string; label: string; why: string; hint: string; action: Partial<ReqState> };

function buildLeads(findings: any[], scanUrl: string): Lead[] {
  let origin = '';
  try { origin = new URL(scanUrl.includes('://') ? scanUrl : `https://${scanUrl}`).origin; } catch {}
  const leads: Lead[] = [];
  const seen = new Set<string>();
  const push = (l: Lead) => { if (!seen.has(l.key)) { seen.add(l.key); leads.push(l); } };

  // 1) From the parsed API inventory (api-spec) — the richest source.
  const inv = findings.find(f => f.plugin === 'api-spec' && /inventaire|op[ée]ration/i.test(f.title || ''));
  if (inv?.evidence) {
    for (const line of String(inv.evidence).split('\n')) {
      const m = line.trim().match(/^(GET|POST|PUT|PATCH|DELETE)\s+(\/\S*)/i);
      if (!m) continue;
      const method = m[1].toUpperCase();
      const path = m[2];
      const url = origin + path.replace(/\{[^}]+\}/g, '1');
      if (method === 'GET' && /\{[^}]*id[^}]*\}/i.test(path)) {
        push({ key: 'bola:' + path, prio: 1, sev: 'high', label: `Tester un IDOR/BOLA sur ${path}`,
          why: "La ressource est désignée par un identifiant : tu peux tenter d'accéder à l'objet d'un autre compte.",
          hint: "Clique Charger, envoie avec id=1, puis remplace le 1 par 2 dans l'URL et renvoie. Si tu obtiens des données DIFFÉRENTES (et pas une erreur), l'accès n'est pas cloisonné.",
          action: { method: 'GET', url, headers: '' } });
      } else if (method === 'GET') {
        push({ key: 'auth:' + path, prio: 3, sev: 'medium', label: `Vérifier l'accès à ${path}`,
          why: "Endpoint documenté : il devrait exiger une authentification.",
          hint: "Charge et envoie SANS header Authorization. Un 200 avec des données = endpoint non protégé.",
          action: { method: 'GET', url, headers: '' } });
      }
    }
  }

  // 2) URLs seen in any finding's evidence/title (open & inspect).
  for (const f of findings) {
    const urls = (`${f.evidence || ''} ${f.title || ''}`.match(/https?:\/\/[^\s"'<>]+/g) || []);
    const u = urls[0];
    if (!u) continue;
    if (origin && !u.startsWith(origin)) continue;
    push({ key: 'open:' + u, prio: 5, sev: f.severity || 'info', label: `Inspecter ${u.replace(origin, '') || '/'}`,
      why: `Vu dans « ${(f.title || '').slice(0, 60)} ».`,
      hint: "Charge et envoie pour lire la réponse brute.",
      action: { method: 'GET', url: u, headers: '' } });
  }

  // 3) Always offer the root as a starting point.
  if (origin) push({ key: 'base', prio: 9, sev: 'info', label: `Rejouer la racine ${origin}`,
    why: 'Point de départ pour explorer manuellement.', hint: '', action: { method: 'GET', url: origin + '/', headers: '' } });

  return leads.sort((a, b) => a.prio - b.prio).slice(0, 15);
}

function Leads({ findings, scanUrl, onLoad }: { findings: any[]; scanUrl: string; onLoad: (a: Partial<ReqState>) => void }) {
  const leads = buildLeads(findings, scanUrl);
  if (leads.length === 0) return null;
  return (
    <div className="panel">
      <h2 style={{ marginTop: 0 }}>Pistes à tester · {leads.length}</h2>
      <p className="sub" style={{ margin: '0 0 12px', fontSize: 12.5 }}>
        Des actions concrètes déduites du scan. Clique « Charger » : ça pré-remplit le Repeater ci-dessous, tu n'as plus qu'à envoyer.
      </p>
      {leads.map(l => (
        <div key={l.key} style={{ borderTop: '1px solid var(--border)', padding: '10px 0' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <span className={`sev ${l.sev}`}>{SEV_FR[l.sev] || l.sev}</span>
            <b style={{ flex: 1 }}>{l.label}</b>
            <button onClick={() => { onLoad(l.action); try { document.getElementById('repeater')?.scrollIntoView({ behavior: 'smooth' }); } catch {} }}>
              Charger dans le Repeater ↓
            </button>
          </div>
          <p className="kv" style={{ margin: '6px 0 0' }}>{l.why}</p>
          {l.hint && <p className="kv" style={{ margin: '4px 0 0', color: 'var(--accent2)' }}><b>Quoi faire :</b> {l.hint}</p>}
        </div>
      ))}
    </div>
  );
}

// Ready-to-pick presets so you don't type raw headers / bodies by hand.
const HEADER_PRESETS = [
  'Authorization: Bearer ',
  'Content-Type: application/json',
  'Accept: application/json',
  'Cookie: ',
  'X-Requested-With: XMLHttpRequest',
  'Origin: ',
  'Referer: ',
  'User-Agent: ',
];
const BODY_PRESETS: { label: string; body: string; ctype?: string }[] = [
  { label: '(vide)', body: '' },
  { label: 'JSON vide {}', body: '{}', ctype: 'application/json' },
  { label: 'JSON login', body: '{\n  "email": "",\n  "password": ""\n}', ctype: 'application/json' },
  { label: 'JSON générique', body: '{\n  "key": "value"\n}', ctype: 'application/json' },
  { label: 'Form urlencoded', body: 'key=value&key2=value2', ctype: 'application/x-www-form-urlencoded' },
];

// ---- Repeater: the safe heart of a Burp-like tool, driven by the API ----------
function Repeater({ token, req, setReq }: { token: string; req: ReqState; setReq: (r: ReqState) => void }) {
  const [resp, setResp] = useState<any>(null);
  const [rerr, setRerr] = useState('');
  const [sending, setSending] = useState(false);
  const patch = (p: Partial<ReqState>) => setReq({ ...req, ...p });

  const addHeader = (line: string) => {
    const cur = req.headers.trim();
    patch({ headers: (cur ? cur + '\n' : '') + line });
  };
  const applyBodyPreset = (p: { body: string; ctype?: string }) => {
    let lines = req.headers.split('\n').filter(l => l.trim() && !/^content-type\s*:/i.test(l.trim()));
    if (p.ctype) lines.push(`Content-Type: ${p.ctype}`);
    const method = p.body && (req.method === 'GET' || req.method === 'HEAD') ? 'POST' : req.method;
    setReq({ ...req, body: p.body, headers: lines.join('\n'), method });
  };

  const hostOf = (u: string) => { try { return new URL(u).hostname; } catch { return ''; } };

  const send = async () => {
    setRerr(''); setResp(null); setSending(true);
    try {
      const hdrs: Record<string, string> = {};
      req.headers.split('\n').forEach(line => {
        const idx = line.indexOf(':');
        if (idx > 0) hdrs[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
      });
      const scope = hostOf(req.url);
      const data = await api('/security/proxy/replay', {
        method: 'POST', token,
        body: { url: req.url, method: req.method, headers: hdrs, body: req.body, scope_hosts: scope ? [scope] : [], allow_write: req.allowWrite },
      });
      setResp(data);
    } catch (e: any) { setRerr(e.message); } finally { setSending(false); }
  };

  return (
    <div className="panel" id="repeater">
      <h2 style={{ marginTop: 0 }}>Repeater · rejouer une requête</h2>
      <p className="sub" style={{ margin: '0 0 12px', fontSize: 12.5 }}>
        Scope-locké sur l'hôte de l'URL, lecture seule par défaut. Le cœur utile de Burp, sans MITM sur la prod.
      </p>
      <div className="row" style={{ alignItems: 'flex-end' }}>
        <div>
          <label>Méthode</label>
          <select value={req.method} onChange={e => patch({ method: e.target.value })}>
            {['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'].map(m => <option key={m} value={m}>{m}</option>)}
          </select>
        </div>
        <div className="grow">
          <label>URL</label>
          <input className="grow" style={{ width: '100%' }} value={req.url} onChange={e => patch({ url: e.target.value })} placeholder="https://cible/chemin" />
        </div>
        <div style={{ alignSelf: 'flex-end' }}>
          <button disabled={sending} onClick={send}>{sending ? 'Envoi…' : 'Envoyer'}</button>
        </div>
      </div>
      <div className="row" style={{ marginTop: 8 }}>
        <div className="grow">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
            <label style={{ margin: 0 }}>En-têtes (une par ligne : Nom: valeur)</label>
            <select value="" onChange={e => { if (e.target.value) addHeader(e.target.value); e.currentTarget.selectedIndex = 0; }} style={{ fontSize: 12 }}>
              <option value="">＋ en-tête courant…</option>
              {HEADER_PRESETS.map(h => <option key={h} value={h}>{h.split(':')[0]}</option>)}
            </select>
          </div>
          <textarea className="grow" style={{ width: '100%', minHeight: 54, fontFamily: 'monospace', fontSize: 12 }} value={req.headers} onChange={e => patch({ headers: e.target.value })} placeholder={'Authorization: Bearer …\nAccept: application/json'} />
        </div>
        <div className="grow">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
            <label style={{ margin: 0 }}>Corps</label>
            <select value="" onChange={e => { const p = BODY_PRESETS[Number(e.target.value)]; if (p) applyBodyPreset(p); e.currentTarget.selectedIndex = 0; }} style={{ fontSize: 12 }}>
              <option value="">modèle de corps…</option>
              {BODY_PRESETS.map((p, i) => <option key={p.label} value={i}>{p.label}</option>)}
            </select>
          </div>
          <textarea className="grow" style={{ width: '100%', minHeight: 54, fontFamily: 'monospace', fontSize: 12 }} value={req.body} onChange={e => patch({ body: e.target.value })} placeholder={'{ }'} />
        </div>
      </div>
      <label style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 8, cursor: 'pointer', color: req.allowWrite ? 'var(--crit)' : undefined }}>
        <input type="checkbox" checked={req.allowWrite} onChange={e => patch({ allowWrite: e.target.checked })} />
        ⚠️ Autoriser un verbe d'écriture (POST/PUT/PATCH/DELETE) — modifie des données
      </label>
      {rerr && <div className="err">{rerr}</div>}
      {resp?.response && (
        <div style={{ marginTop: 12 }}>
          <div className="phase">
            <span><b>HTTP {resp.response.status}</b></span>
            <span className="mono muted">{resp.response.elapsed_ms} ms · {(resp.response.body || '').length} o</span>
          </div>
          <pre className="mono" style={{ maxHeight: 320, overflow: 'auto', background: '#0a0f1e', border: '1px solid var(--border)', borderRadius: 8, padding: 12, fontSize: 12 }}>
            {(resp.response.body || '').slice(0, 8000)}
          </pre>
        </div>
      )}
    </div>
  );
}
