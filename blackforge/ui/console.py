"""Temporary Blackforge Development Console (UI layer).

The console is a *temporary* development interface used to prove the full
orchestration experience end-to-end (target in -> evidence-backed results
out). It renders read-only status from the :class:`DevelopmentConsoleService`
and never touches the orchestrator's internals, evidence storage, world
model, or authorization machinery directly. It only ever calls the service
API.

Security model:
  * Before any mission is created or executed, the console requires an
    :class:`AccessGate` unlock (env token or a per-process generated token).
  * Evidence and asset rows are rendered from the service's redaction-safe
    view models; secrets never reach this layer.
  * There is no method here to write evidence, mutate the world model, or
    bypass authorization/scope.

The render functions are pure and deterministic, which keeps them testable
without a browser and suitable for a Jupyter/Colab notebook.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from blackforge.orchestration.models import AdapterMode
from blackforge.ui.access import AccessGate

if TYPE_CHECKING:  # pragma: no cover - annotations only
    from blackforge.ui.service import DevelopmentConsoleService

_MARK = {"pass": "[PASS] ", "fail": "[FAIL] ", "warn": "[WARN] ", "info": "[INFO] "}


class ConsoleAccessError(Exception):
    """Raised when an action requires an unlocked console session."""


class DevelopmentConsole:
    """Bounded UI facade over the DevelopmentConsoleService.

    Every mutating call first checks the access gate; a locked console
    raises :class:`ConsoleAccessError` before any work happens.
    """

    def __init__(
        self,
        service: DevelopmentConsoleService,
        access_gate: AccessGate | None = None,
    ) -> None:
        self.service = service
        self._gate = access_gate or AccessGate()

    # ------------------------------------------------------------------
    # Access
    # ------------------------------------------------------------------
    def environment_token_var(self) -> str:
        return self._gate.environment_variable

    def has_environment_token(self) -> bool:
        return self._gate.has_environment_token

    def display_token_hint(self) -> str:
        """Return the token an operator needs (only meaningful when unlocked)."""
        return self._gate.generated_token()

    def unlock(self, token: str) -> bool:
        return self._gate.unlock(token)

    def is_unlocked(self) -> bool:
        return self._gate.is_unlocked()

    # ------------------------------------------------------------------
    # Mutating console actions (access-gated)
    # ------------------------------------------------------------------
    def _require_unlocked(self) -> None:
        if not self._gate.is_unlocked():
            raise ConsoleAccessError(
                "console is locked; unlock with an access token before running a mission"
            )

    def create_mission(self, **kwargs: Any) -> dict:
        self._require_unlocked()
        summary = self.service.create_mission(**kwargs)
        return self._summary_dict(summary)

    def run_mission(self, mission_id: str, **kwargs: Any) -> dict:
        self._require_unlocked()
        state = self.service.run_mission(mission_id, **kwargs)
        return self._state_dict(state)

    def cancel(self, mission_id: str) -> dict:
        self._require_unlocked()
        state = self.service.cancel(mission_id)
        return self._state_dict(state)

    def mission_summary(self, mission_id: str) -> dict:
        return self._summary_dict(self.service.mission_summary(mission_id))

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------
    def render_report(self, mission_id: str) -> list[str]:
        """Render a full, read-only console report for a mission."""
        lines: list[str] = []
        _rule(lines, "BLACKFORGE DEVELOPMENT CONSOLE — MISSION REPORT")
        lines.append(f"Mission ID  : {mission_id}")
        summary = self.service.mission_summary(mission_id)
        _kv(lines, "Name", summary.name)
        _kv(lines, "Objective", summary.objective)
        _kv(lines, "Seed target", summary.seed_target)
        _kv(lines, "Profile", summary.profile.value)
        _kv(lines, "Status", summary.status)
        state = summary.runtime
        _kv(lines, "Phase", state.phase.value)
        _kv(lines, "Stop reason", state.stop_reason.value if state.stop_reason else "-")
        _kv(lines, "Steps", f"{state.steps_completed} complete / {state.steps_remaining} left")
        _kv(lines, "Capability calls", str(state.capability_calls))
        _kv(lines, "Replans", str(state.replans))
        _kv(lines, "Execution mode", state.execution_mode.value)
        transport = (
            f"{state.transport_mode} "
            f"(mock={state.mock_observations}, real={state.real_observations})"
        )
        _kv(lines, "Transport", transport)
        if state.llm_status is not None:
            _kv(lines, "Planner mode", state.llm_status.mode.value)
            _kv(lines, "LLM provider", state.llm_status.provider)
            _kv(lines, "LLM model", state.llm_status.model)
            _kv(lines, "LLM invocation", state.llm_status.invocation)
            _kv(lines, "LLM health", state.llm_status.health)

        lines.append("")
        _render_capabilities(lines, self.service.capability_view(mission_id))
        lines.append("")
        _render_assets(lines, self.service.assets(mission_id))
        lines.append("")
        _render_evidence(lines, self.service.evidence_rows(mission_id))
        lines.append("")
        _render_findings(lines, self.service.findings(mission_id))
        lines.append("")
        _render_graph(lines, self.service.graph_summary(mission_id))
        return lines

    # ------------------------------------------------------------------
    # Dict view helpers (for structured/rich UIs and tests)
    # ------------------------------------------------------------------
    def _summary_dict(self, summary: Any) -> dict:
        return {
            "mission_id": str(summary.mission_id),
            "name": summary.name,
            "objective": summary.objective,
            "seed_target": summary.seed_target,
            "status": summary.status,
            "profile": summary.profile.value,
            "phase": summary.runtime.phase.value,
            "steps_completed": summary.runtime.steps_completed,
            "steps_remaining": summary.runtime.steps_remaining,
            "capability_calls": summary.runtime.capability_calls,
            "execution_mode": summary.runtime.execution_mode.value,
            "transport_mode": summary.runtime.transport_mode,
            "real_observations": summary.runtime.real_observations,
            "mock_observations": summary.runtime.mock_observations,
            "stop_reason": (
                summary.runtime.stop_reason.value if summary.runtime.stop_reason else None
            ),
        }

    def _state_dict(self, state: Any) -> dict:
        return {
            "mission_id": str(state.mission_id),
            "phase": state.phase.value,
            "steps_completed": state.steps_completed,
            "steps_remaining": state.steps_remaining,
            "capability_calls": state.capability_calls,
            "execution_mode": state.execution_mode.value,
            "transport_mode": state.transport_mode,
            "real_observations": state.real_observations,
            "mock_observations": state.mock_observations,
            "stop_reason": state.stop_reason.value if state.stop_reason else None,
            "instruction_count": len(state.instructions),
            "llm_status": state.llm_status.model_dump(mode="json") if state.llm_status else None,
        }


def _rule(out: list[str], text: str) -> None:
    out.append("=" * 72)
    out.append(text)
    out.append("=" * 72)


def _kv(out: list[str], key: str, value: Any) -> None:
    out.append(f"{key:<18} : {value}")


def _render_capabilities(out: list[str], view: Any) -> None:
    _rule(out, "CAPABILITIES")
    _kv(out, "Registered", str(view.registered))
    _kv(out, "Applicable", str(view.applicable))
    _kv(out, "Authorized", str(view.authorized))
    _kv(out, "Real-controlled adapters", str(view.real_controlled))
    out.append("")
    out.append(
        f"{_pad('Capability', 40)}{_pad('Mode', 14)}{_pad('Adapter', 16)}"
        f"{_pad('App', 4)}{_pad('Auth', 5)}{_pad('Run', 4)}"
    )
    out.append("-" * 82)
    view.rows.sort(key=lambda r: r.capability)
    for row in view.rows:
        adapter = (
            AdapterMode.REAL_CONTROLLED.value
            if row.adapter is AdapterMode.REAL_CONTROLLED
            else AdapterMode.MOCK_ONLY.value
        )
        out.append(
            f"{_pad(row.capability, 40)}{_pad(row.mode or '-', 14)}"
            f"{_pad(adapter, 16)}{_pad('yes' if row.applicable else '-', 4)}"
            f"{_pad('yes' if row.authorized else '-', 5)}"
            f"{_pad(str(row.executed_count) if row.executed else '-', 4)}"
        )


def _render_assets(out: list[str], assets: Any) -> list[str]:
    _rule(out, "ASSETS")
    if not assets:
        out.append("  (no discovered assets yet)")
        return out
    out.append(
        f"{_pad('Entity type', 20)}{_pad('Name', 40)}"
        f"{_pad('Classification', 16)}{_pad('Authorized', 10)}"
    )
    out.append("-" * 86)
    for asset in assets:
        out.append(
            f"{_pad(asset.entity_type, 20)}{_pad(asset.name, 40)}"
            f"{_pad(asset.classification.value, 16)}"
            f"{_pad('yes' if asset.authorized else '-', 10)}"
        )
    return out


def _render_evidence(out: list[str], evidence: Any) -> list[str]:
    _rule(out, "EVIDENCE")
    if not evidence:
        out.append("  (no evidence yet)")
        return out
    for row in evidence:
        out.append(
            f"[{row.evidence_type}] {row.source_capability} @ {row.target} "
            f"({row.confidence}) source={row.source.value} redacted={row.redacted}"
        )
    return out


def _render_findings(out: list[str], findings: Any) -> list[str]:
    _rule(out, "FINDINGS (evidence-backed)")
    if not findings:
        out.append("  (no findings yet — findings are built strictly from evidence)")
        return out
    out.append(
        f"{_pad('Finding', 12)}{_pad('Title', 44)}"
        f"{_pad('Status', 12)}{_pad('Conf', 10)}{_pad('Source', 6)}"
    )
    out.append("-" * 100)
    for finding in findings:
        out.append(
            f"{_pad(finding.finding_id, 12)}{_pad(finding.title[:42], 44)}"
            f"{_pad(finding.status, 12)}{_pad(finding.confidence, 10)}"
            f"{_pad(finding.source.value, 6)}"
        )
    return out


def _render_graph(out: list[str], graph: Any) -> list[str]:
    _rule(out, "ATTACK GRAPH (descriptive, evidence-backed)")
    out.append(
        f"nodes={graph.node_count} edges={graph.edge_count} "
        f"open_paths={graph.open_path_count} uncertain={graph.uncertain_path_count}"
    )
    if graph.gaps:
        out.append("Open evidence gaps:")
        for gap in graph.gaps:
            out.append(f"  - {gap}")
    if graph.edges:
        out.append("Edges (state/confidence):")
        for edge in graph.edges:
            out.append(
                f"  - {edge.source} -> {edge.target} "
                f"[{edge.relationship.value},{edge.state},{edge.confidence}]"
            )
    return out


def _pad(value: Any, width: int) -> str:
    text = str(value)
    return text + " " * max(0, width - len(text))


__all__ = [
    "ConsoleAccessError",
    "DevelopmentConsole",
]
