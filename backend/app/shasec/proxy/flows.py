"""HTTP flow model + store — the capture layer of Shaapi Security's proxy.

A ``HttpFlow`` is one request/response pair (Burp's "Logger" item). The store
appends flows to a JSONL file so they can be listed, inspected, replayed
(``repeater``) or fed into the detection pipeline. Deliberately storage-agnostic
and dependency-light: no DB coupling here, mirroring how the plugin/verifier
layers stay pure so the platform can wrap them later.
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


@dataclass
class HttpRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ''

    @property
    def host(self) -> str:
        return (urlsplit(self.url).hostname or '').lower()


@dataclass
class HttpResponse:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ''
    elapsed_ms: int = 0


@dataclass
class HttpFlow:
    request: HttpRequest
    response: HttpResponse | None = None
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    source: str = 'repeater'          # repeater | mitm | manual | pipeline
    ts: float = field(default_factory=time.time)
    note: str = ''

    def to_json(self) -> dict:
        return asdict(self)

    @classmethod
    def from_json(cls, d: dict) -> HttpFlow:
        req = HttpRequest(**d['request'])
        resp = HttpResponse(**d['response']) if d.get('response') else None
        return cls(request=req, response=resp, id=d.get('id', uuid.uuid4().hex[:12]),
                   source=d.get('source', 'repeater'), ts=d.get('ts', time.time()),
                   note=d.get('note', ''))


class FlowStore:
    """Append-only JSONL store of captured flows."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, flow: HttpFlow) -> HttpFlow:
        with self.path.open('a', encoding='utf-8') as fh:
            fh.write(json.dumps(flow.to_json(), ensure_ascii=False) + '\n')
        return flow

    def load(self, limit: int | None = None) -> list[HttpFlow]:
        if not self.path.exists():
            return []
        flows: list[HttpFlow] = []
        for line in self.path.read_text(encoding='utf-8').splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                flows.append(HttpFlow.from_json(json.loads(line)))
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
        return flows[-limit:] if limit else flows

    def get(self, flow_id: str) -> HttpFlow | None:
        return next((f for f in self.load() if f.id == flow_id), None)
