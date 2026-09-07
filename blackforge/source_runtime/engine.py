from __future__ import annotations

import time
from typing import TYPE_CHECKING

from blackforge.authorization import AuthorizationBoundary
from blackforge.core.errors import (
    AuthorizationError,
    SourceRuntimeExecutionError,
)
from blackforge.core.logging import get_logger
from blackforge.core.types import Confidence
from blackforge.scope.models import detect_target_type
from blackforge.source_runtime.capabilities import (
    build_capabilities,
    build_source_runtime_meta,
)
from blackforge.source_runtime.correlation import CorrelationEvaluator
from blackforge.source_runtime.evidence import (
    correlation_outcome_evidence,
    link_correlation_evidence,
    runtime_evidence,
    source_evidence,
)
from blackforge.source_runtime.materializer import SourceRuntimeWorldMaterializer
from blackforge.source_runtime.models import (
    CorrelationOutcome,
    CorrelationResult,
    SourceRuntimeRequest,
    SourceRuntimeResult,
    SourceRuntimeStatus,
)
from blackforge.source_runtime.rules import default_rule_registry
from blackforge.source_runtime.transport import MockSourceRuntimeTransport

if TYPE_CHECKING:
    from blackforge.capabilities.registry import CapabilityRegistry
    from blackforge.evidence.bridge import EvidenceMemoryBridge
    from blackforge.evidence.store import EvidenceStore
    from blackforge.world_model.store import WorldModelStore

log = get_logger("source_runtime.engine")

_UNKNOWN = CorrelationResult.UNKNOWN


def _identity_for(target: str) -> str:
    if target.startswith("cloud"):
        return "cloud"
    if target.startswith("image"):
        return "image"
    return "cluster"


def _default_target(scope) -> str:
    """Resolve a target from the (authorized) scope when none is supplied.

    Uses the first allowed target's value if the scope carries one; otherwise
    falls back to the universal ``cloud`` umbrella target so correlation can run
    against the deterministic mock dataset without touching a live system.
    """
    allowed = getattr(scope, "allowed_targets", None)
    if allowed:
        value = getattr(allowed[0], "value", None)
        if isinstance(value, str) and value:
            return value
    return "cloud"


class SourceRuntimeEngine:
    """Authorized, deterministic source & runtime correlation.

    Every typed correlation capability runs the same pipeline: request
    validation -> scope/authorization check -> target-type check -> mock
    transport (declared source + observed runtime sides, independent fixtures)
    -> deterministic correlation rule evaluation -> evidence persistence
    (source evidence, runtime evidence, and a DERIVED correlation record
    referencing both) -> world model materialization -> best-effort memory
    link.

    Correlation is explicitly NOT vulnerability detection: a mismatch is
    recorded as a DISCREPANCY / CONTRADICTION, never as an automatic
    vulnerability or exploit path. A missing runtime side never causes the
    engine to invent one (UNKNOWN / INSUFFICIENT_EVIDENCE). The engine never
    becomes the original source of either the declared or the observed fact.
    """

    def __init__(
        self,
        capability_registry: CapabilityRegistry | None = None,
        evidence_store: EvidenceStore | None = None,
        world_model: WorldModelStore | None = None,
        memory_bridge: EvidenceMemoryBridge | None = None,
        authorization: AuthorizationBoundary | None = None,
    ) -> None:
        self.capability_registry = capability_registry
        self.evidence_store = evidence_store
        self.world_model = world_model
        self.memory_bridge = memory_bridge
        self.authorization = authorization or AuthorizationBoundary()
        self._transport = MockSourceRuntimeTransport()
        self._registry = default_rule_registry()
        self._evaluator = CorrelationEvaluator(self._registry)
        self._meta = {m.name: m for m in build_source_runtime_meta()}
        self._capability_ids = build_capabilities(self)
        self._capabilities = {
            cap.capability_id: cap for cap in self._capability_ids
        }
        self._materializer = (
            SourceRuntimeWorldMaterializer(world_model)
            if world_model is not None
            else None
        )
        if capability_registry is not None:
            for cap in self._capabilities.values():
                if not capability_registry.has(cap.capability_id):
                    capability_registry.register(cap)

    @property
    def capabilities(self) -> list:
        return list(self._capabilities.values())

    def has_capability(self, capability_id: str) -> bool:
        return capability_id in self._capabilities

    def run(
        self,
        capability_id: str,
        request: SourceRuntimeRequest,
        target: str | None = None,
    ) -> SourceRuntimeResult:
        start = time.time()
        target = target or _default_target(request.scope)

        if capability_id not in self._capabilities:
            return SourceRuntimeResult(
                mission_id=request.mission_id,
                session_id=request.session_id,
                target=target,
                capability_id=capability_id,
                mode=request.mode,
                status=SourceRuntimeStatus.UNKNOWN_CAPABILITY,
                error=f"unknown source/runtime capability: {capability_id}",
            )
        meta = self._meta[capability_id]

        self._enforce_authorization(request, capability_id, target, meta.risk_level)
        self._enforce_target_type(meta, target)

        raw = self._run_transport(capability_id, target, request.timeout_seconds)
        document = self._parse_document(raw, target)

        source_records = document.get("source") or []
        runtime_records = document.get("runtime") or []

        outcomes: list[CorrelationOutcome] = []
        evidence_ids: list = []
        warnings: list[str] = list(document.get("warnings") or [])

        paired = list(self._pair_records(source_records, runtime_records))
        materialize_pairs: list = []
        for source_record, runtime_record in paired[: request.max_comparisons]:
            outcome = self._evaluator.compare_records(
                source_record=source_record,
                runtime_record=runtime_record,
                source_conf=Confidence.MEDIUM,
                runtime_conf=Confidence.MEDIUM,
                capability_id=capability_id,
            )
            if outcome is None:
                continue
            outcomes.append(outcome)
            correlation_id = None
            if self.evidence_store is not None:
                ids = self._persist_correlation_evidence(
                    request,
                    target,
                    capability_id,
                    outcome,
                    source_record=source_record,
                    runtime_record=runtime_record,
                )
                correlation_id = ids[0]
                evidence_ids.extend(ids)
            materialize_pairs.append((outcome, correlation_id))

        if not outcomes:
            status = SourceRuntimeStatus.NO_EVIDENCE
        else:
            status = self._map_status(outcomes, warnings)

        if self.evidence_store is not None and evidence_ids:
            self._materialize_memory(evidence_ids)
        if self.world_model is not None and self._materializer is not None:
            self._materialize_world(
                request,
                messages=[(o, cid) for o, cid in materialize_pairs if cid is not None],
            )

        duration_ms = (time.time() - start) * 1000.0
        return SourceRuntimeResult(
            mission_id=request.mission_id,
            session_id=request.session_id,
            target=target,
            capability_id=capability_id,
            mode=request.mode,
            status=status,
            outcomes=outcomes,
            evidence_ids=evidence_ids,
            raw_output=raw,
            warnings=warnings,
            duration_ms=round(duration_ms, 3),
            authorized=True,
        )

    # ------------------------------------------------------------------
    # Pipeline helpers
    # ------------------------------------------------------------------
    def _enforce_authorization(
        self,
        request: SourceRuntimeRequest,
        capability_id: str,
        target: str,
        risk_level,
    ) -> None:
        decision = self.authorization.authorize(
            mission_id=request.mission_id,
            scope=request.scope,
            capability_name=capability_id,
            target_value=target,
            risk_level=risk_level,
        )
        if decision.value == "denied":
            raise AuthorizationError(
                f"source/runtime correlation denied: {capability_id} is not "
                f"authorized for target {target}"
            )
        if decision.value == "requires_approval":
            raise AuthorizationError(
                f"source/runtime correlation requires approval: {capability_id} "
                "exceeds the mission risk limit"
            )

    def _enforce_target_type(self, meta, target: str) -> None:
        detected = detect_target_type(target)
        if detected in meta.supported_target_types:
            return
        # Umbrella family targets (cloud / image / cluster) are accepted.
        if _identity_for(target) in {
            "cloud",
            "image",
            "cluster",
        }:
            return
        raise SourceRuntimeExecutionError(
            f"{meta.name} does not support target: {target}"
        )

    def _run_transport(self, capability_id: str, target: str, timeout: float) -> str:
        start = time.time()
        try:
            raw = self._transport.execute(capability_id, target)
        except Exception as exc:
            raise SourceRuntimeExecutionError(
                f"source/runtime transport failed for {capability_id}: {exc}"
            ) from exc
        if (time.time() - start) * 1000.0 > timeout * 1000.0:
            from blackforge.core.errors import SourceRuntimeTimeoutError

            raise SourceRuntimeTimeoutError(
                f"source/runtime transport timed out: {capability_id}"
            )
        return raw

    def _parse_document(self, raw: str, target: str) -> dict:
        import json

        try:
            document = json.loads(raw)
        except (json.JSONDecodeError, TypeError) as exc:
            raise SourceRuntimeExecutionError(
                f"source/runtime transport returned malformed output for {target}: {exc}"
            ) from exc
        if not isinstance(document, dict):
            raise SourceRuntimeExecutionError(
                f"source/runtime transport output for {target} is not a document"
            )
        error = document.get("error")
        if error is not None:
            kind = error.get("kind") if isinstance(error, dict) else str(error)
            message = (
                error.get("message")
                if isinstance(error, dict)
                else str(error)
            )
            raise SourceRuntimeExecutionError(
                f"source/runtime transport error ({kind}): {message}"
            )
        return document

    def _pair_records(
        self, source_records: list[dict], runtime_records: list[dict]
    ) -> list[tuple[dict, dict]]:
        """Pair source & runtime records that resolve to the same canonical identity.

        Records that do not share a canonical identity are returned as pairs
        too (they will evaluate to NOT_COMPARABLE), preserving the evidence
        that the same name in a different scope never silently matches.
        """
        from blackforge.source_runtime.identity import (
            build_correlation_identity,
        )

        def _key(record: dict) -> str:
            identity = record.get("identity") or {}
            return build_correlation_identity(
                identity.get("scope_kind", ""),
                identity.get("scope_parts"),
                identity.get("name", ""),
            ).identity

        source_by_key = {_key(r): r for r in source_records}
        runtime_by_key = {_key(r): r for r in runtime_records}
        pairs: list[tuple[dict, dict]] = []
        all_keys = sorted(set(source_by_key) | set(runtime_by_key))
        for key in all_keys:
            pairs.append((source_by_key.get(key), runtime_by_key.get(key)))
        return pairs

    def _persist_correlation_evidence(
        self,
        request: SourceRuntimeRequest,
        target: str,
        capability_id: str,
        outcome: CorrelationOutcome,
        source_record: dict | None,
        runtime_record: dict | None,
    ) -> list:
        """Persist source + runtime + derived correlation evidence for one outcome.

        Returns the correlaton evidence id (and buddies) after recording. The
        correlation record DERIVED_FROM both sides; neither side is mutated.
        """
        source_ev = source_evidence(
            request.mission_id,
            target,
            capability_id,
            source_record or {"identity": {}, "properties": {}},
            session_id=request.session_id,
            confidence=Confidence.MEDIUM,
        )
        runtime_ev = runtime_evidence(
            request.mission_id,
            target,
            capability_id,
            runtime_record or {"identity": {}, "properties": {}},
            session_id=request.session_id,
            confidence=Confidence.MEDIUM,
        )
        source_id = self._ensure_evidence(source_ev)
        runtime_id = self._ensure_evidence(runtime_ev)

        correlation_ev = correlation_outcome_evidence(
            request.mission_id,
            target,
            capability_id,
            outcome,
            session_id=request.session_id,
            mode=request.mode,
            source_evidence_id=source_id,
            runtime_evidence_id=runtime_id,
        )
        correlation_id = self._ensure_evidence(correlation_ev)
        link_correlation_evidence(
            self.evidence_store,
            correlation_id,
            source_id,
            runtime_id,
            result=outcome.result,
            identity=outcome.identity,
        )
        return [correlation_id, source_id, runtime_id]

    def _ensure_evidence(self, evidence) -> object:
        from blackforge.source_runtime.evidence import existing_evidence_id

        existing = existing_evidence_id(self.evidence_store, evidence)
        if existing is not None:
            return existing
        stored = self.evidence_store.add(evidence, via_validation=False)
        return stored.id

    def _materialize_memory(self, evidence_ids: list) -> None:
        if self.memory_bridge is None:
            return
        for evidence_id in evidence_ids:
            try:
                self.memory_bridge.materialize_memory(evidence_id)
            except Exception as exc:
                log.warning(
                    "source_runtime_memory_skipped",
                    evidence_id=str(evidence_id),
                    error=str(exc),
                )

    def _materialize_world(self, request, messages: list) -> None:
        """Materialize correlation outcomes into the world model when available.

        Each outcome is recorded as a ``SOURCE_COMPONENT`` entity plus
        descriptive ``DECLARED_AS`` / ``OBSERVED_AS`` / ``CORRESPONDS_TO`` /
        ``DIFFERS_FROM`` relationship edges. Failures are bounded and logged;
        the correlation result itself already persists as evidence.
        """
        if not messages or self._materializer is None:
            return
        try:
            self._materializer.materialize(
                request.mission_id,
                [
                    (outcome, evidence_id, outcome.confidence)
                    for outcome, evidence_id in messages
                    if evidence_id is not None
                ],
                session_id=request.session_id,
            )
        except Exception as exc:
            log.warning(
                "source_runtime_world_model_skipped",
                error=str(exc),
            )

    @staticmethod
    def _map_status(
        outcomes: list[CorrelationOutcome], warnings: list[str]
    ) -> SourceRuntimeStatus:
        if any(o.result == CorrelationResult.CONTRADICTION for o in outcomes):
            return SourceRuntimeStatus.PARTIAL
        if any(o.result == CorrelationResult.DISCREPANCY for o in outcomes):
            return SourceRuntimeStatus.PARTIAL
        if any(o.result == CorrelationResult.UNKNOWN for o in outcomes):
            return SourceRuntimeStatus.PARTIAL if warnings else SourceRuntimeStatus.SUCCESS
        if not outcomes:
            return SourceRuntimeStatus.NO_EVIDENCE
        return SourceRuntimeStatus.SUCCESS


__all__ = ["SourceRuntimeEngine"]
