/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./app/**/*.{ts,tsx}', './components/**/*.{ts,tsx}', './lib/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Kortex Security palette: white is primary, black secondary.
        // Color is reserved for meaning (severity, verified state).
        kx: {
          bg: '#f7f7f7',        // app canvas
          panel: '#ffffff',     // cards
          panel2: '#f4f4f5',    // subtle fills (inputs, chips, table heads)
          border: '#e4e4e7',
          text: '#0a0a0a',
          muted: '#5f5f66',
          accent: '#0a0a0a',    // links, focus
          navy: '#0a0a0a',      // dark surfaces (auth canvas, highlight panels)
          navy2: '#1c1c1f',
          cta: '#0a0a0a',       // primary buttons
          ctaHover: '#27272a',
          teal: '#209893',
          tealSoft: '#d7f7f1',
        },
        sev: {
          critical: '#c81e4b',
          high: '#e96c14',
          medium: '#e0a608',
          low: '#3898ec',
          info: '#8f8f8f',
        },
      },
      fontFamily: {
        sans: ['var(--font-body)', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        display: ['var(--font-display)', 'var(--font-body)', 'ui-sans-serif', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      boxShadow: {
        card: '0 1px 2px rgba(6,13,37,.04), 0 4px 16px rgba(6,13,37,.05)',
      },
    },
  },
  plugins: [],
};
