"""Hermes chat relay.

A thin, admin-only bridge between the web console and the Hermes agent. The
browser sends a natural-language message; this route forwards it to Hermes over
the internal docker network (never public) and returns Hermes' reply. Hermes is
the one that drives shasec (login, scan/audit, findings, summary) — this route
only carries the conversation, so the UI is "the same as WhatsApp, but on the web".

Contract with Hermes (POST settings.HERMES_URL):
    request  JSON {"message": str, "session_id": str, "user": str}
    response JSON {"reply": str}   (also tolerates {"response"|"text"|"content"} or raw text)
"""
from typing import Annotated

import httpx
from fastapi import APIRouter, Request
from pydantic import Field

from backend.app.shasec.service.access import actor_from, require_admin
from backend.common.exception import errors
from backend.common.log import log
from backend.common.response.response_schema import ResponseModel, response_base
from backend.common.schema import SchemaBase
from backend.common.security.jwt import DependsJwtAuth
from backend.core.conf import settings

router = APIRouter(prefix='/hermes', tags=['Hermes'])


class HermesChatParam(SchemaBase):
    message: Annotated[str, Field(min_length=1, max_length=4000)]
    # Client-generated conversation id so Hermes can keep context per chat.
    session_id: str | None = Field(default=None, max_length=64)


def _extract_reply(data) -> str:
    if isinstance(data, str):
        return data
    if isinstance(data, dict):
        for key in ('reply', 'response', 'text', 'content', 'message', 'answer'):
            val = data.get(key)
            if isinstance(val, str) and val.strip():
                return val
    return ''


@router.post('/chat', summary='[admin] Send a message to Hermes and get its reply',
             dependencies=[DependsJwtAuth])
async def hermes_chat(request: Request, obj: HermesChatParam) -> ResponseModel:
    actor = actor_from(request)
    require_admin(actor)  # phase 1: operator only. Premium client access comes later.

    if not settings.HERMES_URL:
        raise errors.ServerError(
            msg="L'assistant Hermes n'est pas encore connecté (HERMES_URL non configurée)."
        )

    headers = {'Content-Type': 'application/json'}
    if settings.HERMES_TOKEN:
        headers['Authorization'] = f'Bearer {settings.HERMES_TOKEN}'
    payload = {
        'message': obj.message,
        'session_id': obj.session_id or f'admin-{actor.id}',
        'user': getattr(actor, 'email', None) or f'user-{actor.id}',
    }

    try:
        async with httpx.AsyncClient(timeout=settings.HERMES_TIMEOUT) as client:
            resp = await client.post(settings.HERMES_URL, json=payload, headers=headers)
    except httpx.HTTPError as exc:
        log.error(f'hermes chat transport error: {exc}')
        raise errors.ServerError(msg="Impossible de joindre Hermes pour le moment.") from exc

    if resp.status_code >= 400:
        log.error(f'hermes chat upstream {resp.status_code}: {resp.text[:300]}')
        raise errors.ServerError(msg=f'Hermes a renvoyé une erreur ({resp.status_code}).')

    try:
        data = resp.json()
    except ValueError:
        data = resp.text
    reply = _extract_reply(data)
    if not reply:
        raise errors.ServerError(msg="Hermes n'a pas renvoyé de réponse exploitable.")

    return response_base.success(request=request, data={'reply': reply, 'session_id': payload['session_id']})
