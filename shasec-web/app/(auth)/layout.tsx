import Link from 'next/link';
import { IconCheck } from '@/components/icons';

const POINTS = [
  'Analyse de vos sites et API en quelques minutes',
  'Vulnérabilités expliquées en français, avec le correctif',
  'Rapports détaillés et historique de vos audits',
];

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-kx-navy text-white">
      <div className="mx-auto grid min-h-screen max-w-6xl items-center gap-12 px-4 py-10 sm:px-8 lg:grid-cols-2">
        <section className="hidden lg:block">
          <h1 className="font-display text-5xl font-semibold leading-[1.1]">
            Trouvez vos failles <span className="text-white/55">avant les attaquants.</span>
          </h1>
          <p className="mt-5 max-w-md text-lg text-white/70">
            Kortex Security audite vos applications web et vos API, et vous dit quoi corriger en priorité.
          </p>
          <ul className="mt-10 space-y-4">
            {POINTS.map(p => (
              <li key={p} className="flex items-center gap-3 text-white/85">
                <span className="grid h-7 w-7 place-items-center rounded-full bg-white/10 text-white"><IconCheck className="h-4 w-4" /></span>
                {p}
              </li>
            ))}
          </ul>
          <p className="mt-12 inline-flex rounded-full border border-white/15 bg-white/5 px-4 py-2 text-sm text-white/75">
            3 scans de découverte offerts, sans carte bancaire.
          </p>
        </section>

        <section className="mx-auto w-full max-w-md">
          {children}
        </section>
      </div>
    </div>
  );
}
