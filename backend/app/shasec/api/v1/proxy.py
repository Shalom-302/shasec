"""Security proxy routes — Repeater/replay + captured-flow history.

The safe heart of a Burp-like tool, exposed through Shaapi's API. It never sits in
the production traffic path: it replays ONE operator-built request at a time via
httpx, guarded by scope-lock (authorized host only) and read-only-by-default
(write verbs require an explicit opt-in). Captured flows are stored as JSONL.
"""
import os
from typing import Annotated

from fastapi import APIRouter, Path, Query, Request

from backend.app.shasec.proxy.flows import FlowStore, HttpFlow, HttpRequest
from backend.app.shasec.proxy.repeater import ScopeError, WriteBlocked, replay
from backend.common.exception import errors
from backend.common.response.response_schema import ResponseModel, response_base
from backend.common.schema import SchemaBase
from backend.common.security.jwt import DependsJwtAuth

router = APIRouter(prefix='/security/proxy', tags=['Security Proxy'])

# JSONL flow store (env-overridable). Shared with the optional mitm addon.
_STORE = FlowStore(os.getenv('SHASEC_FLOW_STORE', 'reports/proxy_flows.jsonl'))


class ReplayParam(SchemaBase):
    url: str
    method: str = 'GET'
    headers: dict[str, str] = {}
    body: str = ''
    # Optional overrides applied before sending (method/url/headers/body).
    edits: dict | None = None
    # Authorized host(s) this replay may hit — the scope lock. Required.
    scope_hosts: list[str]
    # Explicit opt-in to send a write verb (PUT/PATCH/DELETE). PROD DANGER.
    allow_write: bool = False
    follow_redirects: bool = False


@router.post('/replay', summary='Replay/modify a single request (scope-locked, read-only by default)',
             dependencies=[DependsJwtAuth])
async def proxy_replay(request: Request, obj: ReplayParam) -> ResponseModel:
    if not obj.scope_hosts:
        raise errors.RequestError(msg='scope_hosts is required (declare the authorized target host)')
    flow = HttpFlow(request=HttpRequest(method=obj.method, url=obj.url, headers=obj.headers, body=obj.body))
    try:
        result = await replay(
            flow, scope_hosts=set(obj.scope_hosts), edits=obj.edits,
            allow_write=obj.allow_write, follow_redirects=obj.follow_redirects,
        )
    except ScopeError as exc:
        raise errors.ForbiddenError(msg=str(exc))
    except WriteBlocked as exc:
        raise errors.ForbiddenError(msg=str(exc))
    _STORE.append(result)
    return response_base.success(request=request, data=result.to_json())


@router.post('/flows/{flow_id}/replay', summary='Replay a stored flow (with optional edits)',
             dependencies=[DependsJwtAuth])
async def proxy_replay_stored(
    request: Request, flow_id: Annotated[str, Path(...)], obj: ReplayParam
) -> ResponseModel:
    base = _STORE.get(flow_id)
    if not base:
        raise errors.NotFoundError(msg='Flow not found')
    try:
        result = await replay(
            base, scope_hosts=set(obj.scope_hosts), edits=obj.edits,
            allow_write=obj.allow_write, follow_redirects=obj.follow_redirects,
        )
    except ScopeError as exc:
        raise errors.ForbiddenError(msg=str(exc))
    except WriteBlocked as exc:
        raise errors.ForbiddenError(msg=str(exc))
    _STORE.append(result)
    return response_base.success(request=request, data=result.to_json())


@router.get('/flows', summary='List captured HTTP flows (history)', dependencies=[DependsJwtAuth])
async def proxy_flows(request: Request, limit: Annotated[int, Query()] = 100) -> ResponseModel:
    flows = _STORE.load(limit=limit)
    return response_base.success(request=request, data=[f.to_json() for f in flows])


@router.get('/flows/{flow_id}', summary='Get one captured flow', dependencies=[DependsJwtAuth])
async def proxy_flow(request: Request, flow_id: Annotated[str, Path(...)]) -> ResponseModel:
    flow = _STORE.get(flow_id)
    if not flow:
        raise errors.NotFoundError(msg='Flow not found')
    return response_base.success(request=request, data=flow.to_json())
