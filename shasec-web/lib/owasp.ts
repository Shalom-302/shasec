// OWASP Top 10 (2021) short labels for finding badges (mirror of backend/app/shasec/owasp.py).
export const OWASP_FR: Record<string, string> = {
  A01: 'Contrôle d’accès', A02: 'Cryptographie', A03: 'Injection', A04: 'Conception',
  A05: 'Mauvaise config', A06: 'Composants obsolètes', A07: 'Authentification',
  A08: 'Intégrité', A09: 'Journalisation', A10: 'SSRF',
};
export const owaspLabel = (id?: string | null) => (id && OWASP_FR[id] ? `${id} · ${OWASP_FR[id]}` : '');
