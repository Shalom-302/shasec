import { cookies } from 'next/headers';
import Landing from '@/components/landing/Landing';

export const metadata = {
  title: 'Kortex Security · Audit de sécurité web & API',
  description: 'Analysez vos sites et vos API, détectez les vulnérabilités et corrigez en priorité. 3 scans offerts.',
};

export default function Home() {
  return <Landing authed={!!cookies().get('kx_at')?.value} />;
}
