'use client';

import { useEffect, useRef, useState } from 'react';

/** Checkbox selection over the rows of one table page. `selectable` lists the ids
 *  that may be picked; the selection resets whenever that list changes (new page,
 *  new filter, reload), so it never points at rows that are no longer shown. */
export function useSelection(selectable: number[]) {
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const key = selectable.join(',');
  useEffect(() => { setSelected(new Set()); }, [key]);

  const allOn = selectable.length > 0 && selectable.every(id => selected.has(id));
  return {
    ids: [...selected],
    count: selected.size,
    has: (id: number) => selected.has(id),
    toggle: (id: number) => setSelected(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    }),
    allOn,
    someOn: selected.size > 0 && !allOn,
    toggleAll: () => setSelected(allOn ? new Set() : new Set(selectable)),
    clear: () => setSelected(new Set()),
  };
}

export type Selection = ReturnType<typeof useSelection>;

/** Header checkbox: checks/unchecks every selectable row (indeterminate when partial). */
export function SelectAllBox({ sel, disabled }: { sel: Selection; disabled?: boolean }) {
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => { if (ref.current) ref.current.indeterminate = sel.someOn; }, [sel.someOn]);
  return (
    <input ref={ref} type="checkbox" className="h-4 w-4 accent-black" aria-label="Tout sélectionner"
      checked={sel.allOn} disabled={disabled} onChange={sel.toggleAll} />
  );
}

export function RowBox({ sel, id, label, disabled, title }: { sel: Selection; id: number; label: string; disabled?: boolean; title?: string }) {
  return (
    <input type="checkbox" className="h-4 w-4 accent-black disabled:opacity-30" aria-label={label} title={title}
      checked={sel.has(id)} disabled={disabled} onChange={() => sel.toggle(id)} />
  );
}

/** Action bar shown above a table while rows are selected. */
export function BulkBar({ sel, children }: { sel: Selection; children: React.ReactNode }) {
  if (sel.count === 0) return null;
  return (
    <div className="mb-3 flex flex-wrap items-center gap-3 rounded-xl border border-kx-border bg-kx-panel2 px-4 py-2.5 text-sm" role="region" aria-label="Actions groupées">
      <span className="font-medium">{sel.count} sélectionné{sel.count > 1 ? 's' : ''}</span>
      <button type="button" className="text-kx-muted hover:text-black hover:underline" onClick={sel.clear}>Désélectionner</button>
      <div className="ml-auto flex gap-2">{children}</div>
    </div>
  );
}
