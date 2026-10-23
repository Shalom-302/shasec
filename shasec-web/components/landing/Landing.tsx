'use client';

import Link from 'next/link';
import { useLayoutEffect, useRef } from 'react';
import { gsap } from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { IconArrow, IconCheck, Logo } from '@/components/icons';
import { PLANS } from '@/lib/plans';

gsap.registerPlugin(ScrollTrigger);

const HEADLINE = ['Trouvez', 'vos', 'failles', 'avant', 'les', 'attaquants.'];

const STEPS = [
  { n: '01', title: 'Ajoutez votre application', text: 'L’URL de votre site, de votre API ou de votre endpoint GraphQL. Vous attestez être autorisé à la tester.' },
  { n: '02', title: 'Lancez le scan', text: 'Reconnaissance, empreinte, vulnérabilités connues, TLS, en-têtes, secrets exposés : tout s’enchaîne automatiquement.' },
  { n: '03', title: 'Corrigez en priorité', text: 'Chaque faille est expliquée en français, classée par gravité, avec le correctif à appliquer.' },
];

const FEATURES = [
  { title: 'Cartographie', text: 'Sous-domaines, services exposés, technologies détectées : votre surface d’attaque vue de l’extérieur.' },
  { title: 'Vulnérabilités web', text: 'Failles connues, mauvaises configurations, fichiers sensibles accessibles publiquement.' },
  { title: 'Chiffrement & en-têtes', text: 'Certificats, protocoles TLS, HSTS, CSP, cookies : les protections de base, vérifiées.' },
  { title: 'Secrets exposés', text: 'Clés d’API et jetons oubliés dans le JavaScript servi aux visiteurs.' },
  { title: 'API & GraphQL', text: 'Découverte des spécifications et des endpoints, contrôles d’exposition.' },
  { title: 'Analyse IA en français', text: 'Un score, une synthèse et des recommandations lisibles par toute l’équipe.' },
];

const DEMO_FINDINGS = [
  { sev: 'Élevée', cls: 'bg-sev-high', title: 'Content-Security-Policy absente' },
  { sev: 'Moyenne', cls: 'bg-sev-medium', title: 'En-tête HSTS manquant' },
  { sev: 'Faible', cls: 'bg-sev-low', title: 'Fuite de technologie (X-Powered-By)' },
];
const DEMO_PHASES = ['Reconnaissance', 'Analyse', 'Corrélation', 'Rapport'];

export default function Landing({ authed }: { authed: boolean }) {
  const root = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    const ctx = gsap.context(() => {
      const mm = gsap.matchMedia();

      mm.add('(prefers-reduced-motion: no-preference)', () => {
        // Hero: circuit lines draw in, headline words rise, CTAs fade.
        gsap.set('.circuit path', { strokeDasharray: 1200, strokeDashoffset: 1200 });
        const intro = gsap.timeline({ defaults: { ease: 'power3.out' } });
        intro
          .to('.circuit path', { strokeDashoffset: 0, duration: 2.4, stagger: 0.12, ease: 'power2.inOut' }, 0)
          .from('.circuit circle', { scale: 0, transformOrigin: 'center', duration: 0.5, stagger: 0.05 }, 0.8)
          .from('.hero-word', { yPercent: 110, opacity: 0, duration: 0.9, stagger: 0.07 }, 0.1)
          .from('.hero-fade', { y: 24, opacity: 0, duration: 0.8, stagger: 0.12 }, 0.6)
          .from('.console', { y: 60, opacity: 0, rotateX: 12, duration: 1.1 }, 0.5);

        // Hero console: a looping, scripted scan.
        const demo = gsap.timeline({ repeat: -1, repeatDelay: 1.6, delay: 1.6 });
        demo
          .set('.demo-bar', { width: '0%' })
          .set('.demo-finding', { opacity: 0, x: 24 })
          .set('.demo-phase', { color: '#a1a1aa' })
          .set('.demo-dot', { backgroundColor: '#e4e4e7' })
          .set('.demo-status', { textContent: 'En cours' });
        DEMO_PHASES.forEach((_, i) => {
          demo
            .to(`.demo-phase-${i}`, { color: '#0a0a0a', duration: 0.2 })
            .to(`.demo-dot-${i}`, { backgroundColor: '#0a0a0a', duration: 0.2 }, '<')
            .to('.demo-bar', { width: `${(i + 1) * 25}%`, duration: 0.9, ease: 'power1.inOut' }, '<');
          if (i === 1) demo.to('.demo-finding', { opacity: 1, x: 0, duration: 0.45, stagger: 0.35, ease: 'back.out(1.6)' });
        });
        demo.set('.demo-status', { textContent: 'Terminé' }).to('.demo-finding', { opacity: 1, duration: 2.4 });

        // Floating glow behind the hero.
        gsap.to('.glow', { xPercent: 18, yPercent: -12, scale: 1.15, duration: 6, repeat: -1, yoyo: true, ease: 'sine.inOut' });

        // Stats count up when visible.
        gsap.utils.toArray<HTMLElement>('.count').forEach(el => {
          const end = Number(el.dataset.to || 0);
          const obj = { v: 0 };
          gsap.to(obj, {
            v: end, duration: 1.6, ease: 'power2.out',
            scrollTrigger: { trigger: el, start: 'top 85%', once: true },
            onUpdate: () => { el.textContent = String(Math.round(obj.v)); },
          });
        });

        // Generic reveal on scroll.
        gsap.utils.toArray<HTMLElement>('.reveal').forEach(el => {
          gsap.from(el, { y: 40, opacity: 0, duration: 0.9, ease: 'power3.out', scrollTrigger: { trigger: el, start: 'top 85%' } });
        });

        // How it works: line draws as you scroll, steps pop in sequence.
        gsap.from('.steps-line', {
          scaleX: 0, transformOrigin: 'left center', ease: 'none',
          scrollTrigger: { trigger: '.steps', start: 'top 75%', end: 'bottom 60%', scrub: true },
        });
        gsap.from('.step', {
          y: 50, opacity: 0, duration: 0.8, stagger: 0.2, ease: 'power3.out',
          scrollTrigger: { trigger: '.steps', start: 'top 75%' },
        });

        gsap.from('.feature', {
          y: 40, opacity: 0, duration: 0.7, stagger: { each: 0.08, grid: 'auto', from: 'start' }, ease: 'power3.out',
          scrollTrigger: { trigger: '.features', start: 'top 80%' },
        });

        // Report preview: severity bars grow.
        gsap.from('.sev-bar', {
          scaleX: 0, transformOrigin: 'left center', duration: 1.1, stagger: 0.12, ease: 'power3.out',
          scrollTrigger: { trigger: '.report', start: 'top 75%' },
        });
        gsap.from('.score-ring', {
          strokeDashoffset: 302, duration: 1.6, ease: 'power3.out',
          scrollTrigger: { trigger: '.report', start: 'top 75%' },
        });

        gsap.from('.plan', {
          y: 60, opacity: 0, duration: 0.8, stagger: 0.12, ease: 'power3.out',
          scrollTrigger: { trigger: '.plans', start: 'top 80%' },
        });

        // Final CTA: parallax circuit.
        gsap.to('.cta-circuit', {
          yPercent: -20, ease: 'none',
          scrollTrigger: { trigger: '.cta', start: 'top bottom', end: 'bottom top', scrub: true },
        });
      });

      // Sticky nav gets a border once the page scrolls.
      ScrollTrigger.create({
        start: 40,
        onUpdate: self => root.current?.querySelector('.nav')?.classList.toggle('nav-scrolled', self.scroll() > 40),
      });
    }, root);
    return () => ctx.revert();
  }, []);

  return (
    <div ref={root} className="overflow-x-hidden bg-white text-kx-text">
      <style>{`.nav-scrolled{border-color:#e4e4e7;background:rgba(255,255,255,.85);backdrop-filter:blur(8px)}`}</style>

      {/* NAV */}
      <header className="nav fixed inset-x-0 top-0 z-50 border-b border-transparent transition-colors duration-300">
        <div className="mx-auto flex max-w-6xl items-center gap-3 px-4 py-4 sm:gap-6 sm:px-8">
          <Link href="/" aria-label="Kortex Security" className="shrink-0"><Logo /></Link>
          <nav className="ml-6 hidden gap-6 text-sm text-kx-muted md:flex" aria-label="Sections">
            <a href="#fonctionnement" className="hover:text-black">Fonctionnement</a>
            <a href="#fonctionnalites" className="hover:text-black">Fonctionnalités</a>
            <a href="#tarifs" className="hover:text-black">Tarifs</a>
          </nav>
          <div className="ml-auto flex items-center gap-2">
            {authed ? (
              <Link href="/dashboard" className="btn">Mon tableau de bord <IconArrow className="h-4 w-4" /></Link>
            ) : (
              <>
                <Link href="/login" className="hidden rounded-full px-4 py-2 text-sm font-medium hover:bg-kx-panel2 sm:inline-flex">Connexion</Link>
                <Link href="/register" className="btn whitespace-nowrap px-4 sm:px-5">Essai gratuit</Link>
              </>
            )}
          </div>
        </div>
      </header>

      {/* HERO */}
      <section className="relative isolate pb-24 pt-32 sm:pt-40">
        <div className="glow pointer-events-none absolute -top-40 left-1/2 -z-10 h-[520px] w-[720px] -translate-x-1/2 rounded-full bg-gradient-to-br from-zinc-200 via-zinc-100 to-transparent opacity-80 blur-3xl" />
        <Circuit className="circuit pointer-events-none absolute inset-x-0 top-10 -z-10 mx-auto h-[560px] w-full max-w-6xl text-zinc-300" />

        <div className="mx-auto grid max-w-6xl items-center gap-14 px-4 sm:px-8 lg:grid-cols-[1.1fr_1fr]">
          <div className="min-w-0">
            <p className="hero-fade mb-5 inline-flex items-center gap-2 rounded-full border border-kx-border bg-white px-3.5 py-1.5 text-xs font-medium">
              <span className="h-1.5 w-1.5 rounded-full bg-black" /> Audit de sécurité web & API, en self-service
            </p>
            <h1 className="font-display text-[2.6rem] font-semibold leading-[1.04] tracking-tight sm:text-6xl lg:text-7xl">
              {HEADLINE.map((w, i) => (
                <span key={i} className="inline-block overflow-hidden pb-1 align-bottom">
                  <span className={`hero-word inline-block ${i >= 3 ? 'text-zinc-400' : ''}`}>{w}&nbsp;</span>
                </span>
              ))}
            </h1>
            <p className="hero-fade mt-6 max-w-xl text-lg text-kx-muted">
              Kortex Security analyse vos sites et vos API, détecte les vulnérabilités et vous explique,
              en français, quoi corriger en priorité.
            </p>
            <div className="hero-fade mt-8 flex flex-wrap items-center gap-3">
              <Link href={authed ? '/scans/new' : '/register'} className="btn px-6 py-3 text-base">
                {authed ? 'Lancer un scan' : 'Commencer gratuitement'} <IconArrow className="h-4 w-4" />
              </Link>
              <a href="#fonctionnement" className="btn-ghost px-6 py-3 text-base">Comment ça marche</a>
            </div>
            <p className="hero-fade mt-5 flex items-center gap-2 text-sm text-kx-muted">
              <IconCheck className="h-4 w-4 text-black" /> 3 scans de découverte offerts · sans carte bancaire
            </p>
          </div>

          {/* Animated scan console */}
          <div className="console min-w-0 [perspective:1200px]">
            <div className="rounded-3xl border border-kx-border bg-white p-5 shadow-[0_30px_80px_-20px_rgba(0,0,0,.25)]">
              <div className="mb-4 flex items-center justify-between">
                <div className="flex gap-1.5"><span className="h-3 w-3 rounded-full bg-zinc-200" /><span className="h-3 w-3 rounded-full bg-zinc-200" /><span className="h-3 w-3 rounded-full bg-zinc-200" /></div>
                <span className="truncate pl-3 font-mono text-xs text-kx-muted">scan · votre-site.com</span>
              </div>
              <div className="mb-2 flex items-center justify-between text-sm">
                <span className="font-semibold">Analyse en cours</span>
                <span className="demo-status rounded-full bg-black px-2.5 py-0.5 text-xs font-semibold text-white">En cours</span>
              </div>
              <div className="h-2 overflow-hidden rounded-full bg-kx-panel2"><div className="demo-bar h-full w-0 rounded-full bg-black" /></div>
              <ol className="mt-4 grid grid-cols-4 gap-2 text-center text-[11px]">
                {DEMO_PHASES.map((p, i) => (
                  <li key={p} className={`demo-phase demo-phase-${i} text-zinc-400`}>
                    <span className={`demo-dot demo-dot-${i} mx-auto mb-1 block h-2 w-2 rounded-full bg-zinc-200`} />{p}
                  </li>
                ))}
              </ol>
              <div className="mt-5 space-y-2">
                {DEMO_FINDINGS.map(f => (
                  <div key={f.title} className="demo-finding flex items-center gap-3 rounded-xl border border-kx-border px-3 py-2.5 text-sm">
                    <span className={`rounded-md px-2 py-0.5 text-[10px] font-bold uppercase text-white ${f.cls}`}>{f.sev}</span>
                    <span className="truncate font-medium">{f.title}</span>
                  </div>
                ))}
              </div>
              <p className="mt-4 text-center text-[11px] text-kx-muted">Démonstration animée · résultats illustratifs</p>
            </div>
          </div>
        </div>
      </section>

      {/* STATS */}
      <section className="border-y border-kx-border bg-kx-bg">
        <div className="mx-auto grid max-w-6xl grid-cols-1 divide-y divide-kx-border px-4 sm:grid-cols-3 sm:divide-x sm:divide-y-0 sm:px-8">
          {[
            { to: 15, suffix: '', label: 'analyseurs de sécurité orchestrés' },
            { to: 6, suffix: '', label: 'phases d’analyse, de la reconnaissance au rapport' },
            { to: 3, suffix: '', label: 'scans offerts à l’inscription' },
          ].map(s => (
            <div key={s.label} className="py-10 text-center sm:px-6">
              <p className="font-display text-5xl font-semibold"><span className="count" data-to={s.to}>{s.to}</span>{s.suffix}</p>
              <p className="mt-2 text-sm text-kx-muted">{s.label}</p>
            </div>
          ))}
        </div>
      </section>

      {/* HOW IT WORKS */}
      <section id="fonctionnement" className="mx-auto max-w-6xl scroll-mt-24 px-4 py-24 sm:px-8">
        <div className="reveal max-w-2xl">
          <p className="text-sm font-semibold uppercase tracking-widest text-kx-muted">Fonctionnement</p>
          <h2 className="mt-3 font-display text-4xl font-semibold sm:text-5xl">Votre premier audit en trois étapes.</h2>
        </div>
        <div className="steps relative mt-14">
          <div className="steps-line absolute left-0 right-0 top-7 hidden h-px bg-black md:block" />
          <ol className="grid gap-6 md:grid-cols-3">
            {STEPS.map(s => (
              <li key={s.n} className="step relative">
                <span className="relative z-10 grid h-14 w-14 place-items-center rounded-full bg-black font-display text-lg font-semibold text-white ring-8 ring-white">{s.n}</span>
                <h3 className="mt-6 font-display text-xl font-semibold">{s.title}</h3>
                <p className="mt-2 text-kx-muted">{s.text}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      {/* FEATURES */}
      <section id="fonctionnalites" className="scroll-mt-24 bg-kx-navy py-24 text-white">
        <div className="mx-auto max-w-6xl px-4 sm:px-8">
          <div className="reveal max-w-2xl">
            <p className="text-sm font-semibold uppercase tracking-widest text-white/50">Fonctionnalités</p>
            <h2 className="mt-3 font-display text-4xl font-semibold sm:text-5xl">Tout ce qu’un attaquant regarderait. Avant lui.</h2>
          </div>
          <div className="features mt-14 grid gap-px overflow-hidden rounded-3xl bg-white/10 sm:grid-cols-2 lg:grid-cols-3">
            {FEATURES.map(f => (
              <div key={f.title} className="feature group bg-kx-navy p-7 transition-colors duration-300 hover:bg-white/[.04]">
                <span className="mb-5 block h-px w-10 bg-white/40 transition-all duration-500 group-hover:w-20 group-hover:bg-white" />
                <h3 className="font-display text-xl font-semibold">{f.title}</h3>
                <p className="mt-2 text-white/60">{f.text}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* REPORT PREVIEW */}
      <section className="report mx-auto grid max-w-6xl items-center gap-14 px-4 py-24 sm:px-8 lg:grid-cols-2">
        <div className="reveal min-w-0">
          <p className="text-sm font-semibold uppercase tracking-widest text-kx-muted">Rapports</p>
          <h2 className="mt-3 font-display text-4xl font-semibold sm:text-5xl">Des résultats que toute l’équipe comprend.</h2>
          <p className="mt-5 text-lg text-kx-muted">
            Les vulnérabilités sont regroupées, classées par gravité et accompagnées d’un correctif concret.
            Téléchargez le rapport détaillé en PDF pour vos équipes ou vos clients.
          </p>
          <ul className="mt-6 space-y-3">
            {['Explications en français, sans jargon inutile', 'Priorisation par gravité', 'Rapport PDF, HTML ou JSON', 'Historique de tous vos audits'].map(t => (
              <li key={t} className="flex items-center gap-3"><IconCheck className="h-5 w-5" />{t}</li>
            ))}
          </ul>
        </div>
        <div className="reveal min-w-0 rounded-3xl border border-kx-border bg-white p-5 shadow-card sm:p-7">
          <div className="flex items-center gap-6">
            <svg viewBox="0 0 110 110" className="h-28 w-28 -rotate-90">
              <circle cx="55" cy="55" r="48" fill="none" stroke="#f4f4f5" strokeWidth="10" />
              <circle className="score-ring" cx="55" cy="55" r="48" fill="none" stroke="#0a0a0a" strokeWidth="10" strokeLinecap="round"
                strokeDasharray="302" strokeDashoffset="85" />
            </svg>
            <div>
              <p className="text-sm text-kx-muted">Score de sécurité</p>
              <p className="font-display text-4xl font-semibold">72<span className="text-xl text-kx-muted">/100</span></p>
              <p className="text-xs text-kx-muted">Exemple illustratif</p>
            </div>
          </div>
          <div className="mt-7 space-y-3">
            {[
              { l: 'Critique', w: '8%', c: 'bg-sev-critical', n: 0 },
              { l: 'Élevée', w: '30%', c: 'bg-sev-high', n: 2 },
              { l: 'Moyenne', w: '55%', c: 'bg-sev-medium', n: 4 },
              { l: 'Faible', w: '80%', c: 'bg-sev-low', n: 7 },
            ].map(r => (
              <div key={r.l} className="grid grid-cols-[80px_1fr_24px] items-center gap-3 text-sm">
                <span className="text-kx-muted">{r.l}</span>
                <span className="h-2.5 rounded-full bg-kx-panel2"><span className={`sev-bar block h-full rounded-full ${r.c}`} style={{ width: r.w }} /></span>
                <span className="text-right font-semibold">{r.n}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* PRICING */}
      <section id="tarifs" className="scroll-mt-24 border-t border-kx-border bg-kx-bg py-24">
        <div className="mx-auto max-w-6xl px-4 sm:px-8">
          <div className="reveal mx-auto max-w-2xl text-center">
            <p className="text-sm font-semibold uppercase tracking-widest text-kx-muted">Tarifs</p>
            <h2 className="mt-3 font-display text-4xl font-semibold sm:text-5xl">Payez ce que vous scannez.</h2>
            <p className="mt-4 text-kx-muted">Commencez gratuitement, puis achetez des crédits ou abonnez-vous pour une surveillance continue.</p>
          </div>
          <div className="plans mt-14 grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
            {PLANS.map(p => (
              <div key={p.name} className={`plan flex flex-col rounded-3xl border p-6 ${p.highlight ? 'border-black bg-black text-white shadow-2xl lg:-translate-y-3' : 'border-kx-border bg-white'}`}>
                <p className={`text-xs font-semibold uppercase tracking-wider ${p.highlight ? 'text-white/60' : 'text-kx-muted'}`}>{p.tag}</p>
                <h3 className="mt-1 font-display text-2xl font-semibold">{p.name}</h3>
                <p className="mt-4 font-display text-3xl font-semibold">{p.price}</p>
                <ul className={`mt-6 space-y-2.5 text-sm ${p.highlight ? 'text-white/80' : 'text-kx-muted'}`}>
                  {p.items.map(i => <li key={i} className="flex gap-2"><IconCheck className="mt-0.5 h-4 w-4 shrink-0" />{i}</li>)}
                </ul>
                <p className={`mt-6 text-xs ${p.highlight ? 'text-white/50' : 'text-kx-muted'}`}>{p.note}</p>
                <Link href={authed ? '/credits' : '/register'}
                  className={`mt-6 inline-flex justify-center rounded-full px-5 py-2.5 text-sm font-semibold transition ${p.highlight ? 'bg-white text-black hover:bg-zinc-200' : 'border border-kx-border hover:border-black'}`}>
                  {p.name === 'Premium Plus' ? 'Nous contacter' : p.name === 'Free' ? 'Commencer' : 'Choisir'}
                </Link>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* FINAL CTA */}
      <section className="cta relative isolate overflow-hidden bg-kx-navy py-28 text-white">
        <Circuit className="cta-circuit pointer-events-none absolute inset-0 -z-10 h-full w-full text-white/10" />
        <div className="reveal mx-auto max-w-3xl px-4 text-center sm:px-8">
          <h2 className="font-display text-4xl font-semibold sm:text-6xl">Votre surface d’attaque, enfin visible.</h2>
          <p className="mx-auto mt-5 max-w-xl text-lg text-white/60">Créez votre compte et lancez votre premier scan en quelques minutes.</p>
          <Link href={authed ? '/scans/new' : '/register'} className="mt-9 inline-flex items-center gap-2 rounded-full bg-white px-7 py-3.5 text-base font-semibold text-black transition hover:bg-zinc-200">
            {authed ? 'Lancer un scan' : 'Commencer gratuitement'} <IconArrow className="h-4 w-4" />
          </Link>
        </div>
      </section>

      <footer className="border-t border-kx-border bg-white">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4 px-4 py-8 text-sm text-kx-muted sm:px-8">
          <Logo />
          <nav className="flex gap-5" aria-label="Pied de page">
            <Link href="/terms" className="hover:text-black">Conditions d’utilisation</Link>
            <Link href="/login" className="hover:text-black">Connexion</Link>
          </nav>
          <p>© {new Date().getFullYear()} Kortex Security</p>
        </div>
      </footer>
    </div>
  );
}

/** Decorative circuit traces echoing the Kortex logo (lines ending in pads). */
function Circuit({ className = '' }: { className?: string }) {
  const traces = [
    'M0 120 H220 L270 70 H420', 'M0 200 H160 L220 260 H380 L420 220', 'M1200 90 H980 L930 140 H800',
    'M1200 260 H1040 L990 210 H860', 'M0 420 H120 L180 360 H300', 'M1200 440 H1080 L1020 500 H900',
    'M600 0 V60 L650 110 V180', 'M560 560 V500 L520 460 V400',
  ];
  const pads = [[420, 70], [420, 220], [800, 140], [860, 210], [300, 360], [900, 500], [650, 180], [520, 400]];
  return (
    <svg viewBox="0 0 1200 560" preserveAspectRatio="xMidYMid slice" className={className} aria-hidden="true">
      <g fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        {traces.map(d => <path key={d} d={d} />)}
      </g>
      <g fill="currentColor">{pads.map(([x, y]) => <circle key={`${x}-${y}`} cx={x} cy={y} r="6" />)}</g>
    </svg>
  );
}
