'use client';

import { useSession } from '@/components/SessionProvider';
import { ErrorBox, Loading, PageHeader } from '@/components/ui';
import { authCall } from '@/lib/api';
import { fmtDate } from '@/lib/format';

export default function SettingsPage() {
  const { user, loading, error, isAdmin } = useSession();

  const logout = async () => {
    await authCall('logout').catch(() => null);
    window.location.href = '/login';
  };

  return (
    <>
      <PageHeader title="Compte" />
      {loading && <Loading />}
      {error && <ErrorBox message={error} />}
      {user && (
        <section className="card max-w-xl space-y-3 text-sm">
          <h2 className="card-title">Profil</h2>
          <div className="flex justify-between gap-3"><span className="text-kx-muted">Email</span><span>{user.email}</span></div>
          <div className="flex justify-between gap-3"><span className="text-kx-muted">Type de compte</span><span>{isAdmin ? 'Opérateur' : 'Client'}</span></div>
          {user.join_time && <div className="flex justify-between gap-3"><span className="text-kx-muted">Inscrit le</span><span>{fmtDate(user.join_time, false)}</span></div>}
          <div className="pt-3"><button className="btn-ghost" onClick={logout}>Se déconnecter</button></div>
        </section>
      )}
    </>
  );
}
