"""Repeater — replay/modify a single HTTP request, production-safe.

This is the safe heart of "Burp" that fits Shaapi: take a captured (or hand-built)
``HttpFlow``, optionally edit it, send it once with ``httpx``, and capture the
response as a new flow. No live-traffic interception, so it cannot disrupt the
Kaanari production request path.

Two hard guardrails, on by default:
  * **scope lock** — the request host MUST be in ``scope_hosts`` (the authorized
    target). Anything else is refused, so a mistyped/edited URL can never hit an
    unrelated system.
  * **read-only** — write verbs (POST/PUT/PATCH/DELETE) are refused unless the
    operator explicitly passes ``allow_write=True``. Replaying a read is safe;
    replaying a write mutates data, so it is an explicit, deliberate act.
"""
from __future__ import annotations

import time
from dataclasses import replace

import httpx

from backend.app.shasec.proxy.flows import HttpFlow, HttpRequest, HttpResponse

_READ_METHODS = {'GET', 'HEAD', 'OPTIONS'}
_MAX_BODY = 200_000  # cap stored bodies


class ScopeError(RuntimeError):
    """Raised when a replay target is outside the authorized scope."""


class WriteBlocked(RuntimeError):
    """Raised when a write verb is replayed without explicit allow_write."""


def _apply_edits(req: HttpRequest, edits: dict | None) -> HttpRequest:
    if not edits:
        return req
    new = replace(req)
    if 'method' in edits:
        new.method = str(edits['method']).upper()
    if 'url' in edits:
        new.url = str(edits['url'])
    if 'body' in edits:
        new.body = str(edits['body'])
    if 'headers' in edits:  # merge (None value deletes a header)
        merged = dict(new.headers)
        for k, v in edits['headers'].items():
            if v is None:
                merged.pop(k, None)
            else:
                merged[k] = str(v)
        new.headers = merged
    return new


async def replay(
    flow: HttpFlow,
    *,
    scope_hosts: set[str],
    edits: dict | None = None,
    allow_write: bool = False,
    timeout: float = 15.0,
    follow_redirects: bool = False,
) -> HttpFlow:
    """Send ``flow.request`` (with optional ``edits``) once and return a new flow.

    Guardrails are enforced before any byte leaves the process.
    """
    req = _apply_edits(flow.request, edits)
    method = req.method.upper()

    if req.host not in {h.lower() for h in scope_hosts}:
        raise ScopeError(f'refus : {req.host!r} hors scope autorisé ({sorted(scope_hosts)})')
    if method not in _READ_METHODS and not allow_write:
        raise WriteBlocked(f'refus : verbe d\'écriture {method} sans allow_write=True (prod-safe par défaut)')

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=follow_redirects, verify=False) as client:
        t0 = time.monotonic()
        r = await client.request(method, req.url, headers=req.headers or None,
                                 content=req.body.encode() if req.body else None)
        elapsed_ms = int((time.monotonic() - t0) * 1000)

    resp = HttpResponse(
        status=r.status_code,
        headers=dict(r.headers),
        body=(r.text or '')[:_MAX_BODY],
        elapsed_ms=elapsed_ms,
    )
    return HttpFlow(request=req, response=resp, source='repeater',
                    note=f'replay of {flow.id}' if flow.id else '')


def diff(a: HttpFlow, b: HttpFlow) -> dict:
    """Compare two response flows — the core of a 'Comparer' view."""
    ra, rb = a.response, b.response
    if not ra or not rb:
        return {'comparable': False}
    return {
        'comparable': True,
        'status': (ra.status, rb.status),
        'len': (len(ra.body), len(rb.body)),
        'len_delta': len(rb.body) - len(ra.body),
        'elapsed_ms': (ra.elapsed_ms, rb.elapsed_ms),
        'same_status': ra.status == rb.status,
    }
