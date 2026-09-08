"""Temporary development-console access gate.

The Development Console is a *temporary* surface. Before it will accept a
mission for execution it requires an access token. The token is never
hardcoded: it comes from the ``BLACKFORGE_CONSOLE_TOKEN`` environment
variable, or — when that is unset — a per-process random value is generated
once and printed by the console so an operator can use it to unlock a
running instance.

The access gate is intentionally independent of the orchestrator. It exists
purely to prevent accidental or ambient exposure of the temporary UI; it is
**not** a substitute for the orchestrator's own authorization/scope gates,
which remain the authoritative control surface.

Nothing in this module writes, logs, or persists the raw token.
"""

from __future__ import annotations

import hmac
import os
import secrets
from dataclasses import dataclass

_ACCESS_ENV = "BLACKFORGE_CONSOLE_TOKEN"
_GENERATED_ATTR = "_blackforge_console_generated_token"


@dataclass
class AccessSession:
    """A successfully unlocked console session."""

    scope: str = "development_console"
    locked: bool = False


class AccessGate:
    """Require an access token to unlock a console session.

    The token may be supplied via the environment variable
    ``BLACKFORGE_CONSOLE_TOKEN``. If that is unset, a random token is
    generated for the process (exposed only through :meth:`generated_token`)
    so an operator can unlock the console while it runs; it is never written
    to disk or to logs.
    """

    def __init__(self, token: str | None = None) -> None:
        self._token = token or os.environ.get(_ACCESS_ENV)
        self._generated: str | None = None
        self._sessions: list[AccessSession] = []

    @property
    def has_environment_token(self) -> bool:
        return self._token is not None and self._token != ""

    def generated_token(self) -> str:
        """Lazily create and return the per-process generated token.

        Only meaningful when no environment token was configured. The value
        is held in memory and returned so the console can display it; it is
        never persisted.
        """
        if self._token is None or self._token == "":
            if self._generated is None:
                self._generated = secrets.token_urlsafe(24)
            return self._generated
        return self._token

    def unlock(self, candidate: str) -> bool:
        """Validate a candidate against the current access token.

        Comparison is constant-time to avoid trivial timing disclosure.
        """
        if candidate is None:
            return False
        current = self._token or getattr(self, _GENERATED_ATTR, None)
        if current is None:
            current = self.generated_token()
            setattr(self, _GENERATED_ATTR, current)
        if not current:
            return False
        if not hmac.compare_digest(str(candidate).encode("utf-8"), current.encode("utf-8")):
            return False
        self._sessions.append(AccessSession())
        return True

    def verify(self, candidate: str | None) -> bool:
        """Constant-time token check without creating an unlock session.

        Used by the HTTP server to authorize each request: the token must be
        supplied on every call and is validated without unlocking (so a single
        ``POST /api/unlock`` from the notebook opens no ambient session).
        """
        if candidate is None:
            return False
        current = self._token or getattr(self, _GENERATED_ATTR, None)
        if current is None:
            current = self.generated_token()
            setattr(self, _GENERATED_ATTR, current)
        if not current:
            return False
        return hmac.compare_digest(
            str(candidate).encode("utf-8"), current.encode("utf-8")
        )

    def is_unlocked(self) -> bool:
        return bool(self._sessions)

    def lock(self) -> None:
        self._sessions.clear()

    @property
    def session_count(self) -> int:
        return len(self._sessions)

    @property
    def environment_variable(self) -> str:
        return _ACCESS_ENV


__all__ = [
    "AccessGate",
    "AccessSession",
]
