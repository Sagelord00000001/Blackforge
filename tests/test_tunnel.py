from __future__ import annotations

import types
from typing import Any

from blackforge.runtime.tunnel import (
    _CLOUDFLARED_URL_RE,
    _LOCALTUNNEL_URL_RE,
    _NGROK_URL_RE,
    TunnelUnavailableError,
    _await_url,
)


class _FakeProcess:
    def __init__(self, line: str) -> None:
        self._line = line
        self.killed = False
        self.terminated = False

    @property
    def stdout(self) -> Any:
        return types.SimpleNamespace(readline=lambda: self._line)

    def poll(self) -> None:
        return None

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True

    def wait(self, timeout: int = 5) -> None:
        return None


def _extract(pattern: Any, tool: str, line: str) -> str:
    session = _await_url(_FakeProcess(line), pattern, tool=tool)
    try:
        return session.public_url
    finally:
        session.stop()


def test_cloudflared_url_has_a_capture_group() -> None:
    url = _extract(
        _CLOUDFLARED_URL_RE,
        "cloudflared",
        (
            "2026-09-08 INF +--+ INF |  https://sad-zebras-1337"
            ".trycloudflare.com                     | INF +--+\n"
        ),
    )
    assert url == "https://sad-zebras-1337.trycloudflare.com"


def test_ngrok_url_extraction() -> None:
    url = _extract(
        _NGROK_URL_RE,
        "ngrok",
        't=2026-09-08T10:00:00+0000 msg="started tunnel" url=https://abcd-1234.ngrok.io\n',
    )
    assert url == "https://abcd-1234.ngrok.io"


def test_localtunnel_url_extraction() -> None:
    url = _extract(
        _LOCALTUNNEL_URL_RE,
        "lt",
        "your url is: https://crazy-fox.loca.lt\n",
    )
    assert url == "https://crazy-fox.loca.lt"


def test_no_url_raises_unavailable() -> None:
    try:
        _extract(_CLOUDFLARED_URL_RE, "cloudflared", "INF foo bar baz\n")
    except TunnelUnavailableError as exc:
        assert "never published a public URL" in str(exc)
    else:
        raise AssertionError("expected TunnelUnavailableError")
