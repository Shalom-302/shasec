'use client';

import { DependencyList, useCallback, useEffect, useState } from 'react';

/** Load data with explicit loading / error states and a reload(). */
export function useAsync<T>(fn: () => Promise<T>, deps: DependencyList) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const run = useCallback(fn, deps);

  const reload = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      setData(await run());
    } catch (e: any) {
      setError(e?.message || 'Erreur inattendue');
    } finally {
      setLoading(false);
    }
  }, [run]);

  useEffect(() => { reload(); }, [reload]);
  return { data, error, loading, reload, setData };
}
