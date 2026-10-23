'use client';

// Browser notifications for scan completion. Opt-in (the browser asks once);
// without permission we silently fall back to the in-app toast only.

export function notificationsSupported() {
  return typeof window !== 'undefined' && 'Notification' in window;
}

export function notificationsGranted() {
  return notificationsSupported() && Notification.permission === 'granted';
}

export async function askNotifications(): Promise<boolean> {
  if (!notificationsSupported()) return false;
  if (Notification.permission === 'granted') return true;
  if (Notification.permission === 'denied') return false;
  return (await Notification.requestPermission()) === 'granted';
}

export function notifyScanFinished(scanId: number, status: string, label?: string) {
  if (!notificationsGranted()) return;
  const ok = status === 'completed';
  try {
    const n = new Notification(ok ? `Scan #${scanId} terminé` : `Scan #${scanId} en échec`, {
      body: `${label ? `${label} · ` : ''}${ok ? 'Les résultats sont disponibles.' : 'Le scan n’a pas abouti.'}`,
      tag: `kx-scan-${scanId}`,
    });
    n.onclick = () => { window.focus(); window.location.href = `/scans/${scanId}`; };
  } catch { /* some browsers only allow notifications from a service worker */ }
}
