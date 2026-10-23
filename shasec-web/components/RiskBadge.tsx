import type { RiskLevel } from '@/lib/types';

const CLS: Record<RiskLevel, string> = {
  none: 'bg-kx-panel2 text-kx-muted',
  low: 'bg-amber-50 text-amber-800',
  medium: 'bg-orange-100 text-orange-800',
  high: 'bg-red-100 text-red-700',
};
const LABEL: Record<RiskLevel, string> = {
  none: 'Aucun', low: 'Faible', medium: 'Moyen', high: 'Élevé',
};

export function RiskBadge({ level, count }: { level: RiskLevel; count?: number }) {
  if (level === 'none') return <span className="text-xs text-kx-muted">—</span>;
  return (
    <span className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2.5 py-1 text-xs font-semibold ${CLS[level]}`}>
      <span className="h-1.5 w-1.5 rounded-full bg-current opacity-70" />
      {LABEL[level]}{count ? ` · ${count}` : ''}
    </span>
  );
}
