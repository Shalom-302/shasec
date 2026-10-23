// Minimal stroke icons (24px grid, currentColor) — no icon dependency.
type P = { className?: string };
const base = (d: React.ReactNode, className = 'h-5 w-5') => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
    {d}
  </svg>
);

export const IconHome = ({ className }: P) => base(<><path d="M3 10.5 12 3l9 7.5" /><path d="M5 9.5V21h14V9.5" /></>, className);
export const IconGlobe = ({ className }: P) => base(<><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18" /></>, className);
export const IconRadar = ({ className }: P) => base(<><circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="5" /><path d="M12 12 18 6" /></>, className);
export const IconCoins = ({ className }: P) => base(<><ellipse cx="9" cy="7" rx="6" ry="3" /><path d="M3 7v5c0 1.7 2.7 3 6 3s6-1.3 6-3V7" /><path d="M9 15v2c0 1.7 2.7 3 6 3s6-1.3 6-3v-5c0-1.6-2.4-2.9-5.5-3" /></>, className);
export const IconUser = ({ className }: P) => base(<><circle cx="12" cy="8" r="4" /><path d="M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6" /></>, className);
export const IconShield = ({ className }: P) => base(<><path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z" /><path d="m9 12 2 2 4-4" /></>, className);
export const IconTerminal = ({ className }: P) => base(<><rect x="3" y="4" width="18" height="16" rx="2" /><path d="m7 9 3 3-3 3M13 15h4" /></>, className);
export const IconPlus = ({ className }: P) => base(<path d="M12 5v14M5 12h14" />, className);
export const IconCheck = ({ className }: P) => base(<path d="m5 12 5 5 9-10" />, className);
export const IconArrow = ({ className }: P) => base(<path d="M5 12h14m-6-6 6 6-6 6" />, className);
export const IconLogout = ({ className }: P) => base(<><path d="M15 4h4v16h-4" /><path d="M10 8l-4 4 4 4M6 12h10" /></>, className);
export const IconMenu = ({ className }: P) => base(<path d="M4 7h16M4 12h16M4 17h16" />, className);

/** Kortex circuit wordmark + "Security", all black (light surfaces only). */
export function Logo({ size = 'md' }: { size?: 'md' | 'lg' }) {
  const h = size === 'lg' ? 'h-9' : 'h-7';
  return (
    <span className="inline-flex items-center gap-2.5 text-black">
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img src="/kortex-logo.svg" alt="Kortex" className={`${h} w-auto`} />
      <span className={`font-display font-semibold uppercase tracking-[0.2em] ${size === 'lg' ? 'text-base' : 'text-sm'}`}>Security</span>
    </span>
  );
}
