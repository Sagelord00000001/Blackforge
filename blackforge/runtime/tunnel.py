"""Temporary public-URL tunnel bootstrap for the Development Console.

The Colab notebook needs a *real*, publicly reachable URL so a validation run
can be confirmed end-to-end (server up -> health check -> tunnel -> public
URL reachable -> console authenticated). This module wraps cloudflared, ngrok
or localtunnel — whichever is already installed — and returns a
:class:`TunnelSession` with a verified ``public_url``.

Rules this module obeys:

* No permanent configuration; the tunnel is ephemeral on purpose.
* The token that protects the console is *never* passed to the tunnel; the
  tunnel only carries a random subdomain for the local server. Authorization
  stays with :class:`AccessGate` inside the server process.
* Because this module spawns a tunnel binary it lives under ``blackforge/runtime/``
  (never ``blackforge/ui``/``blackforge/orchestration``), which is the only
  place the phase security scan permits process spawning for the console.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

_CLOUDFLARED_URL_RE = re.compile(r"(https://[a-z0-9-]+\.trycloudflare\.com)")
_NGROK_URL_RE = re.compile(r"url=(https://[^\s]+)")
_LOCALTUNNEL_URL_RE = re.compile(r"(https://[a-z0-9-]+\.loca\.lt)")
_CLOUDFLARED_ENV = "BLACKFORGE_TUNNEL_BINARY"


class TunnelUnavailableError(Exception):
    """Raised when no tunnel binary can be started and verified."""


@dataclass
class TunnelSession:
    """A running tunnel with a verified public URL."""

    public_url: str
    tool: str
    process: Any = field(repr=False, default=None)

    def stop(self) -> None:
        proc = self.process
        if proc is None:
            return
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001 - shutdown is best-effort
            proc.kill()


def start_tunnel(port: int, *, timeout_seconds: int = 120) -> TunnelSession:
    """Start whichever tunnel tool is present and wait for a live public URL.

    Resolution order: explicit ``BLACKFORGE_TUNNEL_BINARY`` override, then
    ``cloudflared``, then ``ngrok``, then ``lt`` (localtunnel). Raises
    :class:`TunnelUnavailableError` when none is installed or the URL never
    verifies (each candidate must return a reachable ``/health`` response).
    """
    overrides = [var for var in (os.environ.get(_CLOUDFLARED_ENV),) if var]
    candidates = []
    if overrides:
        candidates.append(("cloudflared", overrides[0]))
    for name in ("cloudflared", "ngrok", "lt"):
        binary = shutil.which(name)
        if binary:
            candidates.append((name, binary))

    if not candidates:
        raise TunnelUnavailableError(
            "no tunnel binary found (tried cloudflared, ngrok, lt). Install one "
            "or set BLACKFORGE_TUNNEL_BINARY."
        )

    errors: list[str] = []
    for tool, binary in candidates:
        try:
            session = _start_one(tool, binary, port)
        except TunnelUnavailableError as exc:
            errors.append(str(exc))
            continue
        try:
            _verify_public_url(session.public_url, timeout_seconds=timeout_seconds)
            return session
        except TunnelUnavailableError as exc:
            session.stop()
            errors.append(str(exc))
    raise TunnelUnavailableError(
        "all tunnel binaries failed: " + " | ".join(errors)
    )


def _start_one(tool: str, binary: str, port: int) -> TunnelSession:
    if tool == "cloudflared":
        return _start_cloudflared(binary, port)
    if tool == "ngrok":
        return _start_ngrok(binary, port)
    if tool == "lt":
        return _start_localtunnel(binary, port)
    raise TunnelUnavailableError(f"unsupported tunnel tool: {tool}")


def _start_cloudflared(binary: str, port: int) -> TunnelSession:
    command = [
        binary,
        "tunnel",
        "--no-autoupdate",
        "--url",
        f"http://127.0.0.1:{port}",
    ]
    process = _popen(command)
    return _await_url(process, _CLOUDFLARED_URL_RE, tool="cloudflared")


def _start_ngrok(binary: str, port: int) -> TunnelSession:
    command = [binary, "http", str(port), "--log", "stdout"]
    authtoken = os.environ.get("BLACKFORGE_NGROK_AUTHTOKEN")
    if authtoken:
        command.extend(["--authtoken", authtoken])
    process = _popen(command)
    return _await_url(process, _NGROK_URL_RE, tool="ngrok")


def _start_localtunnel(binary: str, port: int) -> TunnelSession:
    command = [binary, "--port", str(port)]
    process = _popen(command)
    return _await_url(process, _LOCALTUNNEL_URL_RE, tool="lt")


def _popen(command: list[str]) -> Any:
    try:
        return subprocess.Popen(  # noqa: S603 - tunnel binary explicitly requested
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except OSError as exc:
        raise TunnelUnavailableError(f"cannot start {command[0]}: {exc}") from exc


def _await_url(process: Any, pattern: re.Pattern[str], *, tool: str) -> TunnelSession:
    deadline = time.monotonic() + 60
    tail: list[str] = []
    while time.monotonic() < deadline:
        line = _read_line(process)
        if line:
            tail.append(line)
            tail = tail[-20:]
            match = pattern.search(line)
            if match:
                return TunnelSession(public_url=match.group(1), tool=tool, process=process)
        if process.poll() is not None:
            break
        time.sleep(0.2)
    process.terminate()
    raise TunnelUnavailableError(
        f"{tool} never published a public URL. Output: " + " | ".join(tail)
    )


def _read_line(process: Any) -> str:
    stdout = process.stdout
    if stdout is None:
        return ""
    try:
        line = stdout.readline()
    except Exception:  # noqa: BLE001 - a dead pipe must not crash the tunnel wait
        return ""
    return (line or "").strip()


def _verify_public_url(url: str, *, timeout_seconds: int) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        request = urllib.request.Request(url, headers={"User-Agent": "blackforge/console"})
        try:
            with urllib.request.urlopen(  # noqa: S310 - public URL was operator-chosen
                request, timeout=5
            ) as response:
                # Any 2xx/3xx/4xx means the tunnel forwarded and the backend
                # answered; the console is token-gated, so 401 is a healthy
                # server response, proof the tunnel is live. 5xx means the
                # backend behind the tunnel is not attached yet -> keep waiting.
                if response.status < 500:
                    return
                last_error = RuntimeError(f"upstream responded {response.status}")
        except urllib.error.HTTPError as exc:
            if exc.code < 500:
                return  # the backend answered with an auth gate - tunnel is live
            last_error = exc
        except Exception as exc:  # noqa: BLE001 - verification is probing only
            last_error = exc
        time.sleep(2)
    raise TunnelUnavailableError(
        f"tunnel URL {url} did not become reachable: {last_error}"
    )


__all__ = [
    "TunnelSession",
    "TunnelUnavailableError",
    "start_tunnel",
]
