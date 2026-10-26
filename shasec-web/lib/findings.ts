// Finding presentation shared by the scan pages and the operator console:
// French labels, plain-language enrichment of common scanner findings, grouping.

export type FindingLike = {
  title: string; severity: string; plugin: string;
  description?: string | null; evidence?: string | null; recommendation?: string | null;
  owasp?: string | null;
};

export const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
export const SEV_FR: Record<string, string> = {
  critical: 'critique', high: 'élevée', medium: 'moyenne', low: 'faible', info: 'info',
};
// Finding/exploit lifecycle (methodology §14): observed vs. confirmed, etc.
export const STATUS_FR: Record<string, string> = {
  suspected: 'à vérifier', confirmed: '✓ confirmé', false_positive: 'faux positif',
  stopped: 'arrêté', fixed: 'corrigé', retest_required: 'à retester',
};

// ---- French enrichment: external tools (zap/nikto/nuclei) report in English. --
// We map the common findings to a clear French title + why-it-matters + fix, so
// the console is understandable without depending on the (optional) AI summary.
// Matching is by substring on the lowercased title; first match wins.
export type Enrich = { fr: string; why: string; fix: string };
const ENRICH: [RegExp, Enrich][] = [
  [/strict-transport-security|hsts/i, {
    fr: 'En-tête HSTS manquant',
    why: "Sans HSTS, un visiteur peut être rétrogradé en HTTP et voir son trafic intercepté (attaque man-in-the-middle / SSL-strip).",
    fix: "Ajouter l'en-tête : Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.",
  }],
  [/content security policy|content-security-policy|\bcsp\b/i, {
    fr: 'Content-Security-Policy absente ou incomplète',
    why: "Sans CSP, une injection de script (XSS) s'exécute librement dans la page.",
    fix: "Définir une CSP stricte (script-src 'self' …) sur le serveur/app.",
  }],
  [/anti-csrf|csrf/i, {
    fr: 'Protection CSRF absente',
    why: "Un formulaire/endpoint changeant d'état sans jeton anti-CSRF peut être déclenché depuis un autre site au nom de la victime.",
    fix: "Ajouter un jeton anti-CSRF et/ou cookies SameSite=Lax/Strict sur les actions sensibles.",
  }],
  [/x-powered-by|server leaks information/i, {
    fr: 'Fuite de technologie (en-tête X-Powered-By)',
    why: "Révèle la stack (Next.js/Node…) et aide un attaquant à cibler des CVE connues.",
    fix: "Supprimer/masquer les en-têtes X-Powered-By et Server.",
  }],
  [/x-content-type-options/i, {
    fr: 'En-tête X-Content-Type-Options manquant',
    why: "Le navigateur peut « deviner » le type de contenu (MIME sniffing) et exécuter un fichier de façon inattendue.",
    fix: "Ajouter : X-Content-Type-Options: nosniff.",
  }],
  [/anti-clickjacking|x-frame-options|clickjack/i, {
    fr: 'Protection anti-clickjacking manquante',
    why: "La page peut être embarquée dans une iframe piège pour tromper l'utilisateur (clickjacking).",
    fix: "Ajouter X-Frame-Options: DENY ou la directive CSP frame-ancestors 'none'.",
  }],
  [/vulnerable js library/i, {
    fr: 'Bibliothèque JavaScript vulnérable',
    why: "Une lib front datée peut porter des failles connues (XSS, prototype pollution…).",
    fix: "Mettre à jour la bibliothèque vers une version corrigée.",
  }],
  [/permissions-policy/i, {
    fr: 'En-tête Permissions-Policy manquant',
    why: "Sans elle, aucune restriction déclarée sur caméra/micro/géoloc… pour les scripts et iframes.",
    fix: "Déclarer une Permissions-Policy minimale (désactiver ce qui n'est pas utilisé).",
  }],
  [/cache-control/i, {
    fr: 'Directives Cache-Control à revoir',
    why: "Des réponses sensibles pourraient être mises en cache par le navigateur/proxy.",
    fix: "Mettre Cache-Control: no-store sur les réponses sensibles.",
  }],
  [/content-type header missing/i, {
    fr: 'En-tête Content-Type manquant',
    why: "Le navigateur interprète le type de réponse, ce qui peut mener à des rendus inattendus.",
    fix: "Toujours renvoyer un Content-Type explicite.",
  }],
  [/modern web application|authentication request identified|re-examine cache/i, {
    fr: 'Information (pas une faille)',
    why: "Signal informatif du scanner (appli moderne / requête d'auth détectée). Aucune action requise.",
    fix: "Rien à corriger — contextuel.",
  }],
  [/wildcard dns/i, {
    fr: 'DNS wildcard détecté',
    why: "Un enregistrement *.domaine répond pour n'importe quel sous-domaine (peut masquer des services).",
    fix: "Vérifier que le wildcard est intentionnel et n'expose rien d'inattendu.",
  }],
  [/uncommon header 'refresh'|refresh' found/i, {
    fr: 'En-tête Refresh inhabituel',
    why: "Une redirection via en-tête Refresh peut être détournée (open redirect) selon le contexte.",
    fix: "Préférer une redirection HTTP 3xx contrôlée, valider la destination.",
  }],
  [/alt-svc|http\/3/i, {
    fr: 'HTTP/3 annoncé (Alt-Svc)',
    why: "Simple information : le service annonce HTTP/3 (non testé par certains scanners).",
    fix: "Rien à corriger — informatif.",
  }],
];

export function enrichOf(title: string): Enrich | null {
  const t = (title || '').toLowerCase();
  for (const [rx, e] of ENRICH) if (rx.test(t)) return e;
  return null;
}

// Group identical/similar findings so the list isn't 20× the same HSTS line.
export type Grouped = {
  key: string; title: string; fr: string; severity: string; plugin: string;
  count: number; why: string; fix: string; samples: string[]; owasp?: string | null;
};
export function groupFindings(items: FindingLike[]): Grouped[] {
  const by: Record<string, Grouped> = {};
  for (const f of items) {
    const e = enrichOf(f.title);
    const key = (e ? e.fr : f.title) + '|' + f.severity;
    if (!by[key]) {
      by[key] = {
        key, title: f.title, fr: e ? e.fr : f.title, severity: f.severity, plugin: f.plugin,
        count: 0, why: e ? e.why : (f.description || ''), fix: e ? e.fix : (f.recommendation || ''),
        samples: [], owasp: f.owasp,
      };
    }
    by[key].count += 1;
    const ev = f.evidence || (f.title !== by[key].fr ? f.title : '');
    if (ev && by[key].samples.length < 8 && !by[key].samples.includes(ev)) by[key].samples.push(ev);
  }
  return Object.values(by).sort(
    (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) || b.count - a.count
  );
}
