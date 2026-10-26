#!/usr/bin/env python3
"""Hermes HTTP adapter — a tiny bridge so shasec can chat with Hermes over HTTP.

Hermes has no built-in HTTP chat API; it runs a prompt one-shot with `hermes -z`.
This stdlib-only server (no pip deps — runs inside the hermes image as-is) turns

    POST /chat  {"message": "...", "session_id": "...", "user": "..."}
into
    hermes -z "<message>" --continue <session_id> --yolo [--skills <SKILLS>] [-p <profile>]

and returns {"reply": "<hermes stdout>"}. It is meant to listen ONLY on the
internal docker network — never expose a public port.

Env:
  HERMES_BIN            path to the hermes binary (default /opt/hermes/.venv/bin/hermes)
  HERMES_HOME           Hermes home (default /opt/data)
  HERMES_ADAPTER_TOKEN  if set, require `Authorization: Bearer <token>`
  HERMES_ADAPTER_PORT   listen port (default 8700)
  HERMES_SKILLS         optional skills to load (e.g. "shasec")
  HERMES_PROFILE_PREFIX if set, run each user in profile "<prefix><session_id>" (-p), isolating memory
  HERMES_RUN_TIMEOUT    per-message timeout in seconds (default 300)
"""
import json
import os
import re
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERMES_BIN = os.environ.get('HERMES_BIN', '/opt/hermes/.venv/bin/hermes')
HERMES_HOME = os.environ.get('HERMES_HOME', '/opt/data')
TOKEN = os.environ.get('HERMES_ADAPTER_TOKEN', '')
PORT = int(os.environ.get('HERMES_ADAPTER_PORT', '8700'))
SKILLS = os.environ.get('HERMES_SKILLS', '')
PROFILE_PREFIX = os.environ.get('HERMES_PROFILE_PREFIX', '')
RUN_TIMEOUT = int(os.environ.get('HERMES_RUN_TIMEOUT', '300'))

_SAFE_SESSION = re.compile(r'[^a-zA-Z0-9_.-]')
# Strip ANSI colour codes Hermes may emit so the web chat shows clean text.
_ANSI = re.compile(r'\x1b\[[0-9;]*m')
# Tool chatter Hermes prints before/around the real answer — dropped from the reply.
_NOISE = re.compile(r'^\s*(↪\s*restored workspace dir|restored workspace dir|loading |using profile)\b.*$',
                    re.I | re.M)


def _env():
    env = dict(os.environ)
    env['HERMES_HOME'] = HERMES_HOME
    # Make the venv + hermes bin reachable regardless of the launching shell.
    env['PATH'] = f'/opt/hermes/.venv/bin:/opt/hermes/bin:{env.get("PATH", "")}'
    return env


def _ensure_profile(session: str) -> None:
    """`hermes -p <profile>` errors if the profile doesn't exist, so create it
    first (best-effort; a second run on an existing profile just no-ops/errors
    harmlessly)."""
    if not PROFILE_PREFIX:
        return
    try:
        subprocess.run([HERMES_BIN, 'profile', 'create', f'{PROFILE_PREFIX}{session}'],
                       env=_env(), cwd=HERMES_HOME, capture_output=True, text=True, timeout=30)
    except Exception:  # noqa: BLE001 — already exists / race: ignore, the run will tell us
        pass


def _invoke(message: str, session: str, resume: bool):
    """One `hermes -z` run. Isolation per chat is done with a profile (-p); the
    session name is NOT passed to --continue (Hermes errors if it doesn't exist
    yet), we just --continue the profile's latest session when resuming."""
    cmd = [HERMES_BIN, '-p', f'{PROFILE_PREFIX}{session}'] if PROFILE_PREFIX else [HERMES_BIN]
    if resume:
        cmd += ['--continue']            # resume this profile's most recent session
    cmd += ['-z', message, '--yolo']
    if SKILLS:
        cmd += ['--skills', SKILLS]
    return subprocess.run(cmd, env=_env(), cwd=HERMES_HOME, capture_output=True, text=True, timeout=RUN_TIMEOUT)


def _run_hermes(message: str, session: str) -> tuple[bool, str]:
    session = _SAFE_SESSION.sub('-', session)[:64] or 'default'
    _ensure_profile(session)
    try:
        proc = _invoke(message, session, resume=True)
        combined = f'{proc.stdout or ""}\n{proc.stderr or ""}'.lower()
        # First message of a chat: no session to continue yet -> start a fresh one.
        if proc.returncode != 0 and ('no session' in combined or 'no previous' in combined
                                     or 'no matching session' in combined):
            proc = _invoke(message, session, resume=False)
    except subprocess.TimeoutExpired:
        return False, f"Hermes a dépassé le délai de {RUN_TIMEOUT}s."
    out = _NOISE.sub('', _ANSI.sub('', proc.stdout or '')).strip()
    if not out:
        err = _NOISE.sub('', _ANSI.sub('', proc.stderr or '')).strip()
        if proc.returncode != 0:
            return False, (err or f'hermes a quitté avec le code {proc.returncode}')[-2000:]
        out = err
    return True, out[-8000:] if out else 'Hermes a terminé sans produire de texte.'


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, obj: dict):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == '/health':
            return self._send(200, {'ok': True})
        return self._send(404, {'error': 'not found'})

    def do_POST(self):
        if self.path != '/chat':
            return self._send(404, {'error': 'not found'})
        if TOKEN:
            auth = self.headers.get('Authorization', '')
            if auth != f'Bearer {TOKEN}':
                return self._send(401, {'error': 'unauthorized'})
        try:
            n = int(self.headers.get('Content-Length', 0))
            data = json.loads(self.rfile.read(n) or b'{}')
        except (ValueError, TypeError):
            return self._send(400, {'error': 'invalid json'})
        message = (data.get('message') or '').strip()
        if not message:
            return self._send(400, {'error': 'message is required'})
        session = data.get('session_id') or data.get('user') or 'default'
        ok, reply = _run_hermes(message, str(session))
        return self._send(200 if ok else 502, {'reply': reply})

    def log_message(self, *a):  # keep container logs quiet; Hermes logs itself
        pass


if __name__ == '__main__':
    print(f'hermes-http adapter on :{PORT}  bin={HERMES_BIN} home={HERMES_HOME} '
          f'skills={SKILLS or "-"} profile_prefix={PROFILE_PREFIX or "-"}', flush=True)
    ThreadingHTTPServer(('0.0.0.0', PORT), Handler).serve_forever()
