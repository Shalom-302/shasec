import Link from 'next/link';
import { Logo } from '@/components/icons';
import { TERMS, TERMS_VERSION } from '@/lib/terms';

export const metadata = { title: 'Conditions d’utilisation · Kortex Security' };

export default function TermsPage() {
  return (
    <div className="min-h-screen bg-kx-bg">
      <header className="border-b border-kx-border bg-white">
        <div className="mx-auto flex max-w-3xl items-center justify-between px-4 py-4 sm:px-8">
          <Link href="/"><Logo /></Link>
        </div>
      </header>
      <main className="mx-auto max-w-3xl px-4 py-10 sm:px-8">
        <h1 className="font-display text-3xl font-semibold">Conditions d’utilisation</h1>
        <p className="mt-2 text-sm text-kx-muted">Version du {TERMS_VERSION}</p>
        <div className="card mt-8 space-y-8">
          {TERMS.map(s => (
            <section key={s.title}>
              <h2 className="mb-2 font-display text-lg font-semibold">{s.title}</h2>
              <div className="space-y-2 text-kx-muted">{s.body.map((p, i) => <p key={i}>{p}</p>)}</div>
            </section>
          ))}
        </div>
      </main>
    </div>
  );
}
