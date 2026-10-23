import './globals.css';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Kortex Security',
  description: 'Audits de sécurité self-service pour vos sites et API.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="fr">
      <body>{children}</body>
    </html>
  );
}
