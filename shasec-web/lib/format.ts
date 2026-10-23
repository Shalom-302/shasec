import type { ScanBilling, ScanProfile, ScanStatus, TargetType } from './types';

export function fmtDate(iso?: string | null, withTime = true) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString('fr-FR', withTime
    ? { dateStyle: 'medium', timeStyle: 'short' }
    : { dateStyle: 'medium' });
}

export function hostOf(url: string) {
  try { return new URL(url.includes('://') ? url : `https://${url}`).host; } catch { return url; }
}

export const STATUS_LABEL: Record<ScanStatus, string> = {
  pending: 'En attente',
  running: 'En cours',
  completed: 'Terminé',
  failed: 'Échec',
};

export const PROFILE_LABEL: Record<ScanProfile, { name: string; hint: string }> = {
  fast: { name: 'Rapide', hint: 'Reconnaissance et empreinte (~2 min)' },
  standard: { name: 'Standard', hint: 'Principaux scanners de vulnérabilités' },
  deep: { name: 'Approfondi', hint: 'Tous les outils, y compris les plus lourds (long)' },
};

export const BILLING_LABEL: Record<ScanBilling, string> = {
  free: 'Scan gratuit',
  credits: 'Crédits',
  admin: 'Opérateur',
};

export const TYPE_LABEL: Record<TargetType, string> = {
  website: 'Site web',
  api: 'API',
  graphql: 'GraphQL',
  host: 'Hôte',
};

export const isTerminal = (s?: string) => s === 'completed' || s === 'failed';
