"""mitmproxy addon — OPTIONAL, OPERATOR-LOCAL interception (lab only).

⚠️  PRODUCTION SAFETY — READ FIRST
This addon is the ONLY interception piece, and it is deliberately kept OUT of the
Shaapi/FastAPI application process. It is meant to be run as a SEPARATE, operator-
local process against an AUTHORIZED target while you test manually, e.g.:

    mitmdump -s backend/app/shasec/proxy/mitm_addon.py \
             --set shasec_scope=api.kaanari.example \
             --set shasec_store=./reports/flows.jsonl

You then point *your own* browser/client at this mitmproxy. It NEVER sits in front
of the Kaanari production traffic path — inserting an experimental proxy there
would risk the whole server. It only records request/response flows (out of scope
hosts are skipped) into the same JSONL store the Repeater and pipeline read.

If mitmproxy is not installed, importing this file simply does nothing useful; the
Repeater (repeater.py) works without it and covers the safe 80% (replay/compare).
"""
from __future__ import annotations

from backend.app.shasec.proxy.flows import FlowStore, HttpFlow, HttpRequest, HttpResponse


class ShasecRecorder:
    """A mitmproxy addon that records in-scope flows to a FlowStore."""

    def __init__(self) -> None:
        self._store: FlowStore | None = None
        self._scope: set[str] = set()

    # -- mitmproxy lifecycle hooks -----------------------------------------
    def load(self, loader) -> None:  # noqa: ANN001 - mitmproxy type
        loader.add_option('shasec_store', str, './reports/flows.jsonl',
                          'JSONL file to append captured flows to')
        loader.add_option('shasec_scope', str, '',
                          'Comma-separated authorized hostnames; others are skipped')

    def configure(self, updated) -> None:  # noqa: ANN001
        from mitmproxy import ctx
        self._store = FlowStore(ctx.options.shasec_store)
        self._scope = {h.strip().lower() for h in ctx.options.shasec_scope.split(',') if h.strip()}

    def response(self, flow) -> None:  # noqa: ANN001 - mitmproxy HTTPFlow
        if self._store is None:
            return
        host = (flow.request.pretty_host or '').lower()
        if self._scope and host not in self._scope:
            return  # scope lock: never record out-of-scope traffic
        req = HttpRequest(
            method=flow.request.method,
            url=flow.request.pretty_url,
            headers=dict(flow.request.headers),
            body=flow.request.get_text(strict=False) or '',
        )
        resp = HttpResponse(
            status=flow.response.status_code,
            headers=dict(flow.response.headers),
            body=(flow.response.get_text(strict=False) or '')[:200_000],
        )
        self._store.append(HttpFlow(request=req, response=resp, source='mitm'))


# mitmproxy discovers a module-level ``addons`` list.
addons = [ShasecRecorder()]
