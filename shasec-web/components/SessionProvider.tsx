'use client';

import { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { api } from '@/lib/api';
import type { CreditBalance, User } from '@/lib/types';

type Session = {
  user: User | null;
  balance: CreditBalance | null;
  isAdmin: boolean;
  loading: boolean;
  error: string;
  refreshBalance: () => Promise<void>;
};

const Ctx = createContext<Session | null>(null);

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [balance, setBalance] = useState<CreditBalance | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const refreshBalance = useCallback(async () => {
    try { setBalance(await api<CreditBalance>('/credits/me')); } catch { /* shown where used */ }
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const [u, b] = await Promise.all([api<User>('/auth/me'), api<CreditBalance>('/credits/me')]);
        setUser(u);
        setBalance(b);
      } catch (e: any) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const isAdmin = !!balance?.is_admin;
  return (
    <Ctx.Provider value={{ user, balance, isAdmin, loading, error, refreshBalance }}>
      {children}
    </Ctx.Provider>
  );
}

export function useSession() {
  const s = useContext(Ctx);
  if (!s) throw new Error('useSession outside SessionProvider');
  return s;
}
