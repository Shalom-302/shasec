"""Live scan-progress events over Redis pub/sub.

The pipeline publishes events to ``shasec:scan:{scan_id}``; the WebSocket
endpoint subscribes and forwards them to the desktop client. Using Redis (not an
in-process bus) means it works whether the scan runs in the API process or in the
arq worker.
"""
import json

from backend.common.log import log
from backend.database.db_redis import redis_client


def channel(scan_id: int) -> str:
    return f'shasec:scan:{scan_id}'


async def publish(scan_id: int, event: str, message: str | None = None, **data) -> None:
    """Best-effort publish of a progress event. Never raises — progress is a
    nicety, it must not affect the scan."""
    try:
        payload: dict = {'scan_id': scan_id, 'event': event}
        if message is not None:
            payload['message'] = message
        if data:
            payload.update(data)
        await redis_client.publish(channel(scan_id), json.dumps(payload, ensure_ascii=False))
    except Exception as exc:  # noqa: BLE001
        log.warning(f'progress publish failed for scan {scan_id}: {exc}')
