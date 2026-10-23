import Link from 'next/link';
import { SEV_FR } from '@/lib/findings';
import { STATUS_LABEL } from '@/lib/format';
import type { ScanStatus } from '@/lib/types';

export function Spinner({ className = '' }: { className?: string }) {
  return (
    <span
      role="status"
      aria-label="Chargement"
      className={`inline-block h-4 w-4 animate-spin rounded-full border-2 border-kx-accent border-t-transparent ${className}`}
    />
  );
}

export function Loading({ label = 'Chargement…' }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 py-8 text-kx-muted">
      <Spinner /> {label}
    </div>
  );
}

export function ErrorBox({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="alert-err flex flex-wrap items-center justify-between gap-3" role="alert">
      <span>{message}</span>
      {onRetry && <button className="btn-ghost btn-sm" onClick={onRetry}>Réessayer</button>}
    </div>
  );
}

export function Empty({ title, children, action }: { title: string; children?: React.ReactNode; action?: React.ReactNode }) {
  return (
    <div className="rounded-2xl border border-dashed border-kx-border bg-white px-6 py-12 text-center">
      <p className="font-display text-lg font-semibold">{title}</p>
      {children && <div className="mx-auto mt-1 max-w-md text-sm text-kx-muted">{children}</div>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function PageHeader({ title, sub, actions }: { title: string; sub?: React.ReactNode; actions?: React.ReactNode }) {
  return (
    <div className="mb-8 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        <h1 className="font-display text-2xl font-semibold sm:text-3xl">{title}</h1>
        {sub && <p className="mt-1.5 text-kx-muted">{sub}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}

const SEV_CLS: Record<string, string> = {
  critical: 'bg-sev-critical', high: 'bg-sev-high', medium: 'bg-sev-medium', low: 'bg-sev-low', info: 'bg-sev-info',
};

/** Severity exactly as the API sent it; unknown values are shown raw, never guessed. */
export function SeverityBadge({ severity }: { severity?: string | null }) {
  if (!severity) return <span className="text-xs text-kx-muted">—</span>;
  return (
    <span className={`whitespace-nowrap rounded-md px-2 py-0.5 text-[11px] font-bold uppercase tracking-wide text-white ${SEV_CLS[severity] || 'bg-kx-panel2'}`}>
      {SEV_FR[severity] || severity}
    </span>
  );
}

const STATUS_CLS: Record<ScanStatus, string> = {
  pending: 'bg-kx-panel2 text-kx-muted',
  running: 'bg-black text-white',
  completed: 'bg-kx-tealSoft text-teal-900',
  failed: 'bg-red-50 text-red-700',
};

export function StatusBadge({ status }: { status: ScanStatus | string }) {
  const s = status as ScanStatus;
  return (
    <span className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2.5 py-1 text-xs font-semibold ${STATUS_CLS[s] || 'bg-kx-panel2'}`}>
      {s === 'running' && <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-white" />}
      {STATUS_LABEL[s] || status}
    </span>
  );
}

export function VerifiedBadge({ ok }: { ok: boolean }) {
  return ok
    ? <span className="whitespace-nowrap rounded-full bg-kx-tealSoft px-2.5 py-1 text-xs font-semibold text-teal-900">Propriété vérifiée</span>
    : <span className="whitespace-nowrap rounded-full bg-amber-50 px-2.5 py-1 text-xs font-semibold text-amber-800">À vérifier</span>;
}

export function Pager({ page, totalPages, onPage }: { page: number; totalPages: number; onPage: (p: number) => void }) {
  if (totalPages <= 1) return null;
  return (
    <nav className="mt-4 flex items-center justify-end gap-2 text-sm" aria-label="Pagination">
      <button className="btn-ghost btn-sm" disabled={page <= 1} onClick={() => onPage(page - 1)}>Précédent</button>
      <span className="text-kx-muted">Page {page} / {totalPages}</span>
      <button className="btn-ghost btn-sm" disabled={page >= totalPages} onClick={() => onPage(page + 1)}>Suivant</button>
    </nav>
  );
}

export function TextLink({ href, children }: { href: string; children: React.ReactNode }) {
  return <Link href={href} className="font-medium underline decoration-black/25 underline-offset-4 hover:decoration-black">{children}</Link>;
}
