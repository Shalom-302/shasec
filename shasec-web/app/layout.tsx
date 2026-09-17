import './globals.css';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Shasec — Console pentest',
  description: 'Console web pour piloter les scans shaapi et lire les findings.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="fr">
      <body>{children}</body>
    </html>
  );
}
