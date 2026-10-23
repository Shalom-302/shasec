import './globals.css';
import type { Metadata } from 'next';
import { Outfit, Roboto_Flex } from 'next/font/google';

const display = Outfit({ subsets: ['latin'], variable: '--font-display', display: 'swap' });
const body = Roboto_Flex({ subsets: ['latin'], variable: '--font-body', display: 'swap' });

export const metadata: Metadata = {
  title: 'Kortex Security',
  description: 'Audits de sécurité self-service pour vos sites et API.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="fr" className={`${display.variable} ${body.variable}`}>
      <body>{children}</body>
    </html>
  );
}
