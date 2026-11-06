'use client';

import { urlError, urlFix } from '@/lib/validate';

/** URL input with inline validation: the message appears under the field (after
 *  a first submit attempt or once the user leaves the field) and a one-tap fix
 *  is offered when only "https://" is missing. */
export function UrlField({ id, label = 'URL', value, onChange, type = 'website', showError, placeholder = 'https://exemple.com', onBlur }: {
  id: string; label?: string; value: string; onChange: (v: string) => void; type?: string;
  showError: boolean; placeholder?: string; onBlur?: () => void;
}) {
  const err = showError ? urlError(value, type) : '';
  const fix = err ? urlFix(value, type) : '';
  return (
    <div>
      <label className="label" htmlFor={id}>{label}</label>
      <input id={id} className={`input ${err ? 'border-red-400 focus:border-red-500' : ''}`} type="text" inputMode="url"
        autoCapitalize="off" autoCorrect="off" spellCheck={false} placeholder={placeholder}
        value={value} onChange={e => onChange(e.target.value)} onBlur={onBlur}
        aria-invalid={!!err} aria-describedby={err ? `${id}-err` : undefined} />
      {err && (
        <p id={`${id}-err`} className="mt-1 text-sm text-red-700" role="alert">
          {err}
          {fix && <> <button type="button" className="font-semibold underline underline-offset-2" onClick={() => onChange(fix)}>Utiliser {fix}</button></>}
        </p>
      )}
    </div>
  );
}
