"""Temporary Development Console HTTP server.

This module turns the Development Console into a real, reachable HTTP surface
so the Colab notebook can expose a working public URL through a tunnel
(cloudflare/ngrok/localtunnel). It is deliberately small, read-mostly and
stdlib-only:

* HTTP serving uses :mod:`http.server` and :mod:`json`; no web framework.
* No configuration, dialogue, or secret is persisted anywhere.
* Every API endpoint except ``GET /health`` requires the console access token
  (``Authorization: Bearer <token>``, validated by :class:`AccessGate`).
  ``/health`` stays open so a tunnel probe can confirm reachability without
  leaking any data — it returns only static metadata.
* There is no endpoint to write evidence, mutate the world model, or bypass
  authorization/scope. Creating and running a mission always funnels through
  the :class:`DevelopmentConsoleService` -> orchestrator gates.

Nothing here spawns a process, evaluates code, or runs a generic shell
command. ``os.system``, ``subprocess``, ``eval`` and ``exec`` are forbidden
in this module by the phase security scan.
"""

from __future__ import annotations

import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from blackforge.ui.access import AccessGate

if TYPE_CHECKING:  # pragma: no cover - annotations only
    from blackforge.ui.service import DevelopmentConsoleService


class ConsoleServerError(Exception):
    """Raised when the console server cannot be started or routed."""


class ConsoleRequestHandler(BaseHTTPRequestHandler):
    """Route console requests to JSON responses behind the access gate."""

    server: ConsoleHTTPServer

    # ------------------------------------------------------------------
    # Lifecycle logging (kept minimal and secret-free)
    # ------------------------------------------------------------------
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: ARG002
        pass

    # ------------------------------------------------------------------
    # Responses
    # ------------------------------------------------------------------
    def _send_json(
        self, status: int, payload: dict[str, Any], *, public: bool = False
    ) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if public:
            self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status: int, message: str) -> None:
        self._send_json(status, {"error": message, "ok": False})

    def _authorized(self) -> bool:
        """Extract and validate the bearer token for this request."""
        header = self.headers.get("Authorization", "")
        if header.lower().startswith("bearer "):
            return self.server.access.verify(header[len("bearer ") :].strip())
        query = urlparse(self.path).query
        for pair in query.split("&"):
            if not pair:
                continue
            key, _, value = pair.partition("=")
            if key == "token":
                from urllib.parse import unquote

                return self.server.access.verify(unquote(value))
        return False

    def _read_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        try:
            raw = self.rfile.read(length).decode("utf-8")
        except Exception as exc:  # noqa: BLE001 - malformed request bodies fail closed
            raise ConsoleServerError(f"cannot read request body: {exc}") from exc
        if not raw.strip():
            return {}
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ConsoleServerError(f"request body is not valid JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise ConsoleServerError("request body must be a JSON object")
        return payload

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------
    def do_OPTIONS(self) -> None:  # noqa: N802 - http.server API
        self._send_json(200, {"ok": True}, public=True)

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path == "/health":
            self._send_json(
                200,
                {
                    "ok": True,
                    "service": "blackforge-development-console",
                    "status": "ok",
                },
                public=True,
            )
            return
        if not self._authorized():
            self._error(401, "unauthorized; supply the console access token")
            return
        try:
            self._route_get(path)
        except ConsoleServerError as exc:
            self._error(400, str(exc))
        except Exception as exc:  # noqa: BLE001 - server never crashes on bad input
            self._error(500, f"internal error: {type(exc).__name__}")

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path == "/api/unlock":
            self._route_unlock()
            return
        if not self._authorized():
            self._error(401, "unauthorized; supply the console access token")
            return
        try:
            body = self._read_body()
            self._route_post(path, body)
        except ConsoleServerError as exc:
            self._error(400, str(exc))
        except Exception as exc:  # noqa: BLE001 - server never crashes on bad input
            self._error(500, f"internal error: {type(exc).__name__}")

    def _route_unlock(self) -> None:
        """Open unlock endpoint; validates the same token as the gate."""
        try:
            body = self._read_body()
        except ConsoleServerError as exc:
            self._error(400, str(exc))
            return
        candidate = body.get("token")
        if candidate is None or not self.server.access.verify(str(candidate)):
            self._error(401, "invalid access token")
            return
        self.server.access.unlock(str(candidate))
        self._send_json(200, {"ok": True, "unlocked": True})

    def _route_get(self, path: str) -> None:
        if path == "/api/status":
            self._send_json(200, {"ok": True, **self.server.status_payload()})
        elif path == "/api/missions":
            self._send_json(200, {"ok": True, "missions": self.server.service.list_mission_ids()})
        elif path.startswith("/api/missions/") and len(path.split("/")) == 4:
            mid = path.split("/")[3]
            self._send_json(200, {"ok": True, "mission": self._mission_payload(mid)})
        elif path.startswith("/api/missions/") and len(path.split("/")) == 5:
            mid, section = path.split("/")[3], path.split("/")[4]
            self._send_json(
                200, {"ok": True, section: self._section_payload(mid, section)}
            )
        else:
            self._error(404, f"no such route: {path}")

    def _route_post(self, path: str, body: dict[str, Any]) -> None:
        if path == "/api/missions":
            summary = self.server.service.create_mission(
                seed_target=str(body.get("seed_target", "")).strip(),
                name=str(body.get("name", "")).strip(),
                objective=str(body.get("objective", "")).strip(),
                profile=str(body.get("profile", "authorized_assessment")),
                max_steps=int(body.get("max_steps", 10) or 10),
                max_capability_calls=int(body.get("max_capability_calls", 25) or 25),
                max_runtime_seconds=float(body.get("max_runtime_seconds", 300) or 300),
                max_replans=int(body.get("max_replans", 3) or 3),
                allow_real_controlled=bool(body.get("allow_real_controlled", False)),
                execution_mode=str(body.get("execution_mode", "auto")),
                planner_mode=str(body.get("planner_mode", "auto")),
                validation_target=str(body.get("validation_target", "")).strip() or None,
            )
            self._send_json(200, {"ok": True, "mission": _summary_to_dict(summary)})
            return
        if path.endswith("/run"):
            mid = path.split("/")[3]
            planner = str(body.get("planner", "rule"))
            state = self.server.service.run_mission(mid, planner=planner)
            self._send_json(200, {"ok": True, "runtime": _runtime_to_dict(state)})
            return
        if path.endswith("/cancel"):
            mid = path.split("/")[3]
            state = self.server.service.cancel(mid)
            self._send_json(200, {"ok": True, "runtime": _runtime_to_dict(state)})
            return
        self._error(404, f"no such route: {path}")

    def _mission_payload(self, mission_id: str) -> dict[str, Any]:
        summary = self.server.service.mission_summary(mission_id)
        payload = _summary_to_dict(summary)
        state = self.server.service.runtime(mission_id)
        if state is not None:
            payload["runtime"] = _runtime_to_dict(state)
        payload["llm_status"] = (
            self.server.service.llm_status(mission_id)
            if hasattr(self.server.service, "llm_status")
            else None
        )
        return payload

    def _section_payload(self, mission_id: str, section: str) -> dict[str, Any]:
        if section == "capabilities":
            rows = [
                r.model_dump(mode="json")
                for r in self.server.service.capability_view(mission_id).rows
            ]
            return {"rows": rows}
        if section == "assets":
            assets = [
                a.model_dump(mode="json")
                for a in self.server.service.assets(mission_id)
            ]
            return {"assets": assets}
        if section == "evidence":
            evidence = [
                e.model_dump(mode="json")
                for e in self.server.service.evidence_rows(mission_id)
            ]
            return {"evidence": evidence}
        if section == "graph":
            graph = self.server.service.graph_summary(mission_id)
            return graph.model_dump(mode="json")
        if section == "findings":
            findings = [
                f.model_dump(mode="json")
                for f in self.server.service.findings(mission_id)
            ]
            return {"findings": findings}
        self._error(404, f"no such section: {section}")
        return {}


class ConsoleHTTPServer(ThreadingHTTPServer):
    """Threading console server bound to a service and access gate.

    ``port=0`` asks the OS to allocate a free ephemeral port, so the
    notebook can start the server, read :attr:`port`, and hand it to a
    tunnel without ever guessing.
    """

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        service: DevelopmentConsoleService,
        access: AccessGate | None = None,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        self.service = service
        self.access = access or AccessGate()
        self._started_at = time.time()
        super().__init__((host, port), ConsoleRequestHandler)
        self.host = host
        self.port = self.server_address[1]
        self.base_url = f"http://{host}:{self.port}"

    def status_payload(self) -> dict[str, Any]:
        status = self.service.status()
        return {
            "service": "blackforge-development-console",
            "uptime_seconds": round(time.time() - self._started_at, 2),
            "has_environment_token": self.access.has_environment_token,
            "unlocked": self.access.is_unlocked(),
            **status,
        }


def start_server(
    service: DevelopmentConsoleService,
    access: AccessGate | None = None,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
) -> ConsoleHTTPServer:
    """Start a console HTTP server and return it (call ``.shutdown()``)."""
    server = ConsoleHTTPServer(service, access, host=host, port=port)
    return server


def _summary_to_dict(summary: Any) -> dict[str, Any]:
    return {
        "mission_id": str(summary.mission_id),
        "name": summary.name,
        "objective": summary.objective,
        "seed_target": summary.seed_target,
        "status": summary.status,
        "profile": summary.profile.value,
        "execution_mode": summary.policy.execution_mode.value,
        "planner_mode": summary.policy.planner_mode.value,
        "validation_target": summary.policy.validation_target,
        "allow_real_controlled": summary.policy.allow_real_controlled,
    }


def _runtime_to_dict(state: Any) -> dict[str, Any]:
    return {
        "mission_id": str(state.mission_id),
        "phase": state.phase.value,
        "transport_mode": state.transport_mode,
        "mock_observations": state.mock_observations,
        "real_observations": state.real_observations,
        "steps_completed": state.steps_completed,
        "steps_remaining": state.steps_remaining,
        "capability_calls": state.capability_calls,
        "stop_reason": state.stop_reason.value if state.stop_reason else None,
        "llm_status": state.llm_status.model_dump(mode="json") if state.llm_status else None,
        "instructions": [
            {
                "capability": ins.capability,
                "target": ins.target,
                "source": ins.source.value,
                "status": ins.status.value,
                "evidence_ids": [str(e) for e in ins.evidence_ids],
            }
            for ins in state.instructions
        ],
    }


__all__ = [
    "ConsoleHTTPServer",
    "ConsoleRequestHandler",
    "ConsoleServerError",
    "start_server",
]
