// Client-side input checks, mirroring the API rules (the API validates again:
// this only gives the user an immediate, precise message before sending).

const PRIVATE_HOST = /^(localhost|.*\.local|.*\.internal|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0|\[?::1\]?$)/i;

/** Returns an error message, or '' when the URL is acceptable for this target type. */
export function urlError(raw: string, type: string = 'website'): string {
  const v = raw.trim();
  if (!v) return 'Veuillez saisir l’URL de votre application.';
  if (/\s/.test(v)) return 'URL invalide : elle ne doit pas contenir d’espace.';
  const needsScheme = type !== 'host';
  if (needsScheme && !/^https?:\/\//i.test(v)) {
    return 'URL invalide. Veuillez saisir une URL commençant par https:// ou http://';
  }
  let host = v;
  if (/^https?:\/\//i.test(v)) {
    try { host = new URL(v).hostname; } catch { return 'URL invalide. Vérifiez son format (ex. https://monsite.com).'; }
  }
  if (!host || (!host.includes('.') && !host.includes(':') && host !== 'localhost')) {
    return 'URL invalide : le nom de domaine est incomplet (ex. https://monsite.com).';
  }
  if (PRIVATE_HOST.test(host)) {
    return 'Les adresses locales ou privées ne peuvent pas être analysées. Indiquez une adresse publique.';
  }
  return '';
}

/** "kaanari.com" -> "https://kaanari.com" when the only problem is the missing scheme. */
export function urlFix(raw: string, type: string = 'website'): string {
  const v = raw.trim();
  if (!v || type === 'host' || /^[a-z][a-z0-9+.-]*:\/\//i.test(v) || /\s/.test(v)) return '';
  const candidate = `https://${v.replace(/^\/+/, '')}`;
  return urlError(candidate, type) ? '' : candidate;
}
