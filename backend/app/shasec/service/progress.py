"""Live scan-progress events: Redis pub/sub (push) + a persisted step log (pull).

The pipeline publishes events to ``shasec:scan:{scan_id}``; the WebSocket endpoint
subscribes and forwards them to the desktop client (push, real-time). Every event
is also appended to a capped Redis list ``shasec:scan:{scan_id}:steps`` so a client
that connects late — or prefers plain HTTP — can pull the full progress via
``GET /scans/{id}/progress`` (see ``snapshot`` + ``describe``).

Using Redis (not an in-process bus) means it works whether the scan runs in the
API process or in the arq worker.
"""
import json

from backend.common.log import log
from backend.database.db_redis import redis_client
from backend.utils.timezone import timezone

_STEPS_TTL = 86400          # keep a scan's step log for a day
_STEPS_MAX = 300            # cap the list so a chatty scan can't grow unbounded

# Ordered macro-phases of the pipeline, mapped from raw events. Percent is the
# value reached when the phase *starts*; the scanners phase fills 10→70 by
# per-plugin completion (computed in ``describe``).
PHASES = [
    'Initialisation',
    'Reconnaissance & scan',
    'Corrélation des résultats',
    'Validation contrôlée',
    'Analyse IA',
    'Terminé',
]
_EVENT_PHASE = {
    'started': ('Initialisation', 5),
    'scanners.start': ('Reconnaissance & scan', 10),
    'plugin.start': ('Reconnaissance & scan', None),   # percent from counts
    'plugin.done': ('Reconnaissance & scan', None),    # percent from counts
    'scanners.done': ('Corrélation des résultats', 70),
    'exploit.start': ('Validation contrôlée', 74),
    'exploit.done': ('Validation contrôlée', 82),
    'ai.start': ('Analyse IA', 86),
    'ai.done': ('Analyse IA', 95),
    'completed': ('Terminé', 100),
    'failed': ('Échec', None),
}


def channel(scan_id: int) -> str:
    return f'shasec:scan:{scan_id}'


def _steps_key(scan_id: int) -> str:
    return f'shasec:scan:{scan_id}:steps'


async def publish(scan_id: int, event: str, message: str | None = None, **data) -> None:
    """Best-effort publish + persist of a progress event. Never raises — progress
    is a nicety, it must not affect the scan."""
    payload: dict = {'scan_id': scan_id, 'event': event, 'ts': timezone.now().isoformat()}
    if message is not None:
        payload['message'] = message
    if data:
        payload.update(data)
    blob = json.dumps(payload, ensure_ascii=False)
    try:
        await redis_client.publish(channel(scan_id), blob)          # push (WebSocket)
    except Exception as exc:  # noqa: BLE001
        log.warning(f'progress publish failed for scan {scan_id}: {exc}')
    try:
        key = _steps_key(scan_id)
        await redis_client.rpush(key, blob)                         # pull (HTTP)
        await redis_client.ltrim(key, -_STEPS_MAX, -1)
        await redis_client.expire(key, _STEPS_TTL)
    except Exception as exc:  # noqa: BLE001
        log.warning(f'progress persist failed for scan {scan_id}: {exc}')


async def snapshot(scan_id: int) -> list[dict]:
    """Return every persisted progress event for a scan, in order (may be empty)."""
    try:
        raw = await redis_client.lrange(_steps_key(scan_id), 0, -1)
    except Exception as exc:  # noqa: BLE001
        log.warning(f'progress read failed for scan {scan_id}: {exc}')
        return []
    events: list[dict] = []
    for item in raw:
        try:
            events.append(json.loads(item))
        except (ValueError, TypeError):
            continue
    return events


def describe(events: list[dict], db_status: str | None = None) -> dict:
    """Fold the raw event stream into a UI-friendly progress view.

    Returns the current phase (label + index over ``PHASES``), a 0-100 percent,
    per-scanner counts (done/total + which are still running), and the ordered
    list of human steps — so a client can render "Étape 2/6 · nmap terminé (4/9)".
    """
    total = 0
    done = 0
    started: set[str] = set()
    finished: set[str] = set()
    status = 'pending'
    last_msg = None
    steps: list[dict] = []

    for ev in events:
        name = ev.get('event')
        phase = _EVENT_PHASE.get(name, (None, None))[0]
        if ev.get('message') is not None:
            last_msg = ev.get('message')
        if name == 'started':
            status = 'running'
        elif name == 'scanners.start':
            total = int(ev.get('total') or total)
        elif name == 'plugin.start':
            if ev.get('plugin'):
                started.add(ev['plugin'])
        elif name == 'plugin.done':
            if ev.get('plugin'):
                finished.add(ev['plugin'])
            done = len(finished) or (done + 1)
        elif name == 'completed':
            status = 'completed'
        elif name == 'failed':
            status = 'failed'
        steps.append({
            'event': name,
            'phase': phase,
            'message': ev.get('message'),
            'plugin': ev.get('plugin'),
            'ts': ev.get('ts'),
        })

    # Percent: honour the last event that carries an explicit value; the scanners
    # phase interpolates 10→70 by completion ratio.
    percent = 0
    current_phase = 'File d\'attente'
    for ev in events:
        name = ev.get('event')
        phase, pct = _EVENT_PHASE.get(name, (None, None))
        if phase:
            current_phase = phase
        if name in ('plugin.start', 'plugin.done') and total:
            percent = max(percent, 10 + int(60 * min(done, total) / total))
        elif pct is not None:
            percent = max(percent, pct)

    if status == 'completed':
        percent = 100
    elif status == 'failed':
        current_phase = 'Échec'

    # Reconcile with the DB when the step log is empty/expired.
    if not events and db_status:
        status = db_status
        percent = {'completed': 100, 'failed': 100, 'running': 10}.get(db_status, 0)
        current_phase = {'completed': 'Terminé', 'failed': 'Échec',
                         'running': 'Reconnaissance & scan'}.get(db_status, 'File d\'attente')

    try:
        phase_index = PHASES.index(current_phase) + 1
    except ValueError:
        phase_index = 0

    return {
        'status': status,
        'percent': percent,
        'current_phase': current_phase,
        'phase_index': phase_index,
        'phase_total': len(PHASES),
        'message': last_msg,
        'scanners': {
            'total': total,
            'done': min(done, total) if total else done,
            'running': sorted(started - finished),
        },
        'steps': steps,
    }
