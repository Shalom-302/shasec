'use client';

import Link from 'next/link';

/** The scope attestation a client gives (per target) before it can be scanned. */
export function ScopeAttestation({ checked, onChange, id = 'attest' }: { checked: boolean; onChange: (v: boolean) => void; id?: string }) {
  return (
    <label htmlFor={id} className={`flex cursor-pointer gap-3 rounded-xl border p-4 text-sm transition ${checked ? 'border-black bg-kx-panel2' : 'border-kx-border bg-white'}`}>
      <input id={id} type="checkbox" className="mt-0.5 h-4 w-4 shrink-0 accent-black" checked={checked} onChange={e => onChange(e.target.checked)} />
      <span>
        J’atteste être propriétaire de cette cible ou disposer d’une <b>autorisation écrite</b> de son propriétaire pour
        la tester, et j’accepte les{' '}
        <Link href="/terms" target="_blank" className="font-semibold underline underline-offset-4">conditions d’utilisation</Link>.
        <span className="mt-1 block text-xs text-kx-muted">Cette attestation est horodatée et enregistrée avec votre compte et votre adresse IP.</span>
      </span>
    </label>
  );
}
