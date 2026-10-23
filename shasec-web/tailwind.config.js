/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./app/**/*.{ts,tsx}', './components/**/*.{ts,tsx}', './lib/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Kortex Security palette — sober dark UI, status colors carry meaning.
        kx: {
          bg: '#0b1020',
          panel: '#121a2e',
          panel2: '#1a2340',
          border: '#263154',
          text: '#e6ecff',
          muted: '#94a0c0',
          accent: '#4f7cff',
          ok: '#22c55e',
        },
        sev: {
          critical: '#dc2626',
          high: '#ea580c',
          medium: '#d97706',
          low: '#ca8a04',
          info: '#64748b',
        },
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
    },
  },
  plugins: [],
};
