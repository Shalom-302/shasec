'use client';

import { useSession } from './SessionProvider';
import { Empty, Loading } from './ui';

export default function AdminOnly({ children }: { children: React.ReactNode }) {
  const { loading, isAdmin } = useSession();
  if (loading) return <Loading />;
  if (!isAdmin) return <Empty title="Accès réservé aux administrateurs" />;
  return <>{children}</>;
}
