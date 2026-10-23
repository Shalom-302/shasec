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
  awaiting_approval: 'En attente de validation',
  queued: 'En file d’attente',
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
export const isActive = (s?: string) => s === 'queued' || s === 'running' || s === 'awaiting_approval';

export function fmtDuration(fromIso?: string | null, to: number = Date.now()) {
  if (!fromIso) return '';
  const sec = Math.max(0, Math.round((to - new Date(fromIso).getTime()) / 1000));
  const m = Math.floor(sec / 60);
  return m ? `${m} min ${String(sec % 60).padStart(2, '0')} s` : `${sec} s`;
}

/** Human label for a raw pipeline progress event. */
export function stepLabel(event: string, plugin?: string | null) {
  const map: Record<string, string> = {
    queued: 'Mis en file d’attente',
    started: 'Scan démarré',
    'scanners.start': 'Lancement des analyseurs',
    'scanners.done': 'Analyseurs terminés',
    'exploit.start': 'Validation contrôlée',
    'exploit.done': 'Validation terminée',
    'ai.start': 'Analyse IA',
    'ai.done': 'Analyse IA terminée',
    completed: 'Scan terminé',
    failed: 'Échec',
  };
  if (event === 'plugin.start') return `${plugin || 'Analyseur'} · démarré`;
  if (event === 'plugin.done') return `${plugin || 'Analyseur'} · terminé`;
  return map[event] || event;
}
