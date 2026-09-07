from __future__ import annotations

import json
import os

import pytest

from blackforge.authorization import AuthorizationBoundary
from blackforge.capabilities.registry import CapabilityRegistry
from blackforge.core.errors import (
    AuthorizationError,
    SourceRuntimeExecutionError,
)
from blackforge.core.types import (
    Confidence,
    EvidenceType,
    ProvenanceType,
    RiskLevel,
    TargetType,
)
from blackforge.evidence.models import EvidenceRelation
from blackforge.evidence.repository import InMemoryEvidenceRepository
from blackforge.evidence.store import EvidenceStore
from blackforge.runtime.bootstrap import bootstrap
from blackforge.scope.models import Target, TargetScope
from blackforge.source_runtime import (
    DECLARED_ENTRIES,
    OBSERVED_ENTRIES,
    SOURCE_RUNTIME_CAPABILITY_IDS,
    CorrelationEvaluator,
    CorrelationOutcome,
    CorrelationResult,
    CorrelationRule,
    MockSourceRuntimeTransport,
    RuntimeFixtureProvider,
    Side,
    SourceFixtureProvider,
    SourceRuntimeEngine,
    SourceRuntimeMaterializeReport,
    SourceRuntimeMode,
    SourceRuntimeRequest,
    SourceRuntimeResult,
    SourceRuntimeStatus,
    SourceRuntimeWorldMaterializer,
    SourceValue,
    build_correlation_identity,
    build_source_runtime_meta,
    contradiction_rule,
    credential_value_redacted,
    default_property_resolver,
    default_rule_registry,
    exact_equality,
    immutable_digest_rule,
    link_correlation_evidence,
    presence_rule,
    redact_source_runtime_document,
    redact_source_runtime_raw,
    register_rule,
    same_correlation_identity,
    set_equality,
)
from blackforge.source_runtime.capabilities import (
    SourceRuntimeCapabilityMeta,
    SourceRuntimeCorrelationCapability,
    build_capabilities,
)
from blackforge.source_runtime.evidence import (
    correlation_confidence,
    correlation_outcome_evidence,
    evidence_dedup_key_for,
    existing_evidence_id,
    runtime_evidence,
    source_evidence,
)
from blackforge.world_model.models import EntityType, RelationshipType
from blackforge.world_model.query import RelationshipQuery, WorldQuery
from blackforge.world_model.repository import InMemoryWorldRepository
from blackforge.world_model.store import WorldModelStore

MID = "mission_p13"
SID = "session_p13"

_CLUSTER_TARGETS = [
    Target(value="cluster", target_type=TargetType.APPLICATION),
    Target(value="aelionix-prod/payments", target_type=TargetType.APPLICATION),
    Target(value="aelionix-prod/marketing", target_type=TargetType.APPLICATION),
    Target(value="aelionix-staging/payments", target_type=TargetType.APPLICATION),
]
_IMAGE_TARGETS = [
    Target(value="registry.aelionix.io", target_type=TargetType.ASSET),
]
_CLOUD_TARGETS = [Target(value="cloud", target_type=TargetType.CLOUD)]

_ALL_TARGETS = _CLUSTER_TARGETS + _IMAGE_TARGETS + _CLOUD_TARGETS


def _scope(
    *,
    targets: list[Target] | None = None,
    max_risk: RiskLevel = RiskLevel.HIGH,
) -> TargetScope:
    return TargetScope(
        mission_id=MID,
        allowed_targets=targets or _ALL_TARGETS,
        allowed_capabilities=[],
        max_risk_level=max_risk,
    )


def _request(
    *,
    targets: list[Target] | None = None,
    mission_id: str = MID,
    session_id: str | None = SID,
) -> SourceRuntimeRequest:
    return SourceRuntimeRequest(
        mission_id=mission_id,
        scope=_scope(targets=targets),
        session_id=session_id,
    )


def _engine(
    *,
    registry: CapabilityRegistry | None = None,
    use_stores: bool = True,
) -> tuple[SourceRuntimeEngine, EvidenceStore | None, WorldModelStore | None]:
    evidence = (
        EvidenceStore(repository=InMemoryEvidenceRepository())
        if use_stores
        else None
    )
    world = (
        WorldModelStore(repository=InMemoryWorldRepository())
        if use_stores
        else None
    )
    engine = SourceRuntimeEngine(
        capability_registry=registry,
        evidence_store=evidence,
        world_model=world,
        authorization=AuthorizationBoundary(mode="strict"),
    )
    return engine, evidence, world


# ──────────────────────────────────────────────────────────────────────
# 1. Models
# ──────────────────────────────────────────────────────────────────────


class TestSourceRuntimeModels:
    def test_source_runtime_mode_enum(self) -> None:
        assert SourceRuntimeMode.PASSIVE.value == "passive"
        assert SourceRuntimeMode.CONTROLLED.value == "controlled"

    def test_correlation_result_enum(self) -> None:
        values = {r.value for r in CorrelationResult}
        assert values == {
            "match",
            "discrepancy",
            "contradiction",
            "unknown",
            "insufficient_evidence",
            "not_comparable",
        }

    def test_source_runtime_status_enum(self) -> None:
        values = {s.value for s in SourceRuntimeStatus}
        assert "success" in values
        assert "partial" in values
        assert "no_evidence" in values
        assert "unsupported_target" in values
        assert "request_failed" in values

    def test_side_enum(self) -> None:
        assert Side.SOURCE.value == "source"
        assert Side.RUNTIME.value == "runtime"

    def test_source_value_defaults(self) -> None:
        sv = SourceValue(side=Side.SOURCE, property="x")
        assert sv.present is False
        assert sv.normalized_value is None

    def test_correlation_outcome_disclaimer(self) -> None:
        id_ = build_correlation_identity("cloud", ["a"], "b")
        o = CorrelationOutcome(
            capability_id="cap",
            identity=id_,
            result=CorrelationResult.MATCH,
            confidence=Confidence.MEDIUM,
        )
        assert "not automatically a vulnerability" in o.disclaimer

    def test_source_runtime_result_observation_count(self) -> None:
        r = SourceRuntimeResult(
            mission_id=MID,
            session_id=SID,
            target="t",
            capability_id="cap",
            mode=SourceRuntimeMode.CONTROLLED,
        )
        assert r.observation_count == 0
        r2 = SourceRuntimeResult(
            mission_id=MID,
            session_id=SID,
            target="t",
            capability_id="cap",
            mode=SourceRuntimeMode.CONTROLLED,
            outcomes=[
                CorrelationOutcome(
                    capability_id="cap",
                    identity=build_correlation_identity("x", [], "y"),
                    result=CorrelationResult.MATCH,
                    confidence=Confidence.MEDIUM,
                )
            ],
        )
        assert r2.observation_count == 1

    def test_source_runtime_result_model_dump(self) -> None:
        r = SourceRuntimeResult(
            mission_id=MID,
            session_id=SID,
            target="t",
            capability_id="cap",
            mode=SourceRuntimeMode.CONTROLLED,
        )
        d = r.model_dump(mode="json")
        assert d["mission_id"] == MID
        assert d["outcomes"] == []


# ──────────────────────────────────────────────────────────────────────
# 2. Identity
# ──────────────────────────────────────────────────────────────────────


class TestSourceRuntimeIdentity:
    def test_build_correlation_identity_deterministic(self) -> None:
        id1 = build_correlation_identity("cluster", ["prod", "ns"], "web")
        id2 = build_correlation_identity("cluster", ["prod", "ns"], "web")
        assert id1.identity == id2.identity
        assert id1.identity == "cluster:prod:ns:web"

    def test_different_scope_yields_different_identity(self) -> None:
        id1 = build_correlation_identity("cluster", ["prod", "payments"], "api")
        id2 = build_correlation_identity("cluster", ["prod", "marketing"], "api")
        assert id1.identity != id2.identity
        assert not same_correlation_identity(id1, id2)

    def test_same_name_different_scope_not_comparable(self) -> None:
        src = build_correlation_identity(
            "cluster", ["aelionix-prod", "payments"], "payment-gateway"
        )
        rnt = build_correlation_identity(
            "cluster", ["aelionix-prod", "payments-prod"], "payment-gateway"
        )
        assert src.identity != rnt.identity
        assert not same_correlation_identity(src, rnt)

    def test_slug_normalization(self) -> None:
        id_ = build_correlation_identity(
            "Cloud", ["AWS", "acct-112233445566"], "Payments-DB"
        )
        assert id_.scope_kind == "cloud"
        assert id_.keys["scope"] == "aws:acct-112233445566"
        assert id_.keys["name"] == "payments-db"
        assert id_.identity == "cloud:aws:acct-112233445566:payments-db"

    def test_empty_scope_parts(self) -> None:
        id_ = build_correlation_identity("image", [], "nginx")
        assert id_.identity == "image::nginx"
        assert "scope" not in id_.keys


# ──────────────────────────────────────────────────────────────────────
# 3. Rules
# ──────────────────────────────────────────────────────────────────────


class TestSourceRuntimeRules:
    def test_exact_equality_match(self) -> None:
        src = SourceValue(side=Side.SOURCE, property="x", normalized_value="a", present=True)
        rnt = SourceValue(side=Side.RUNTIME, property="x", normalized_value="a", present=True)
        assert exact_equality(source=src, runtime=rnt) == CorrelationResult.MATCH

    def test_exact_equality_discrepancy(self) -> None:
        src = SourceValue(side=Side.SOURCE, property="x", normalized_value="a", present=True)
        rnt = SourceValue(side=Side.RUNTIME, property="x", normalized_value="b", present=True)
        assert exact_equality(source=src, runtime=rnt) == CorrelationResult.DISCREPANCY

    def test_exact_equality_unknown_when_absent(self) -> None:
        src = SourceValue(side=Side.SOURCE, property="x", normalized_value="a", present=True)
        rnt = SourceValue(side=Side.RUNTIME, property="x", normalized_value=None, present=False)
        assert exact_equality(source=src, runtime=rnt) == CorrelationResult.UNKNOWN

    def test_set_equality_match(self) -> None:
        src = SourceValue(side=Side.SOURCE, property="env", normalized_value="a|b", present=True)
        rnt = SourceValue(side=Side.RUNTIME, property="env", normalized_value="a|b", present=True)
        assert set_equality(source=src, runtime=rnt) == CorrelationResult.MATCH

    def test_set_equality_unknown_both_absent(self) -> None:
        src = SourceValue(side=Side.SOURCE, property="env", normalized_value=None, present=False)
        rnt = SourceValue(side=Side.RUNTIME, property="env", normalized_value=None, present=False)
        assert set_equality(source=src, runtime=rnt) == CorrelationResult.UNKNOWN

    def test_immutable_digest_match(self) -> None:
        src = SourceValue(
            side=Side.SOURCE, property="digest", normalized_value="sha256:abc", present=True
        )
        rnt = SourceValue(
            side=Side.RUNTIME, property="digest", normalized_value="sha256:abc", present=True
        )
        assert immutable_digest_rule(source=src, runtime=rnt) == CorrelationResult.MATCH

    def test_immutable_digest_discrepancy(self) -> None:
        src = SourceValue(
            side=Side.SOURCE, property="digest", normalized_value="sha256:aaa", present=True
        )
        rnt = SourceValue(
            side=Side.RUNTIME, property="digest", normalized_value="sha256:bbb", present=True
        )
        assert immutable_digest_rule(source=src, runtime=rnt) == CorrelationResult.DISCREPANCY

    def test_immutable_digest_unknown_absent(self) -> None:
        src = SourceValue(
            side=Side.SOURCE, property="digest", normalized_value=None, present=False
        )
        rnt = SourceValue(
            side=Side.RUNTIME, property="digest", normalized_value="sha256:abc", present=True
        )
        assert immutable_digest_rule(source=src, runtime=rnt) == CorrelationResult.UNKNOWN

    def test_presence_rule_match(self) -> None:
        src = SourceValue(side=Side.SOURCE, property="x", normalized_value="yes", present=True)
        rnt = SourceValue(side=Side.RUNTIME, property="x", normalized_value="yes", present=True)
        assert presence_rule(source=src, runtime=rnt) == CorrelationResult.MATCH

    def test_presence_rule_unknown_source_absent(self) -> None:
        src = SourceValue(side=Side.SOURCE, property="x", normalized_value=None, present=False)
        rnt = SourceValue(side=Side.RUNTIME, property="x", normalized_value="yes", present=True)
        assert presence_rule(source=src, runtime=rnt) == CorrelationResult.UNKNOWN

    def test_presence_rule_unknown_runtime_absent(self) -> None:
        src = SourceValue(side=Side.SOURCE, property="x", normalized_value="yes", present=True)
        rnt = SourceValue(side=Side.RUNTIME, property="x", normalized_value=None, present=False)
        assert presence_rule(source=src, runtime=rnt) == CorrelationResult.UNKNOWN

    def test_contradiction_rule_contradiction(self) -> None:
        src = SourceValue(
            side=Side.SOURCE, property="backup", normalized_value="true", present=True
        )
        rnt = SourceValue(
            side=Side.RUNTIME, property="backup", normalized_value="false", present=True
        )
        assert contradiction_rule(source=src, runtime=rnt) == CorrelationResult.CONTRADICTION

    def test_contradiction_rule_match_when_equal(self) -> None:
        src = SourceValue(
            side=Side.SOURCE, property="backup", normalized_value="true", present=True
        )
        rnt = SourceValue(
            side=Side.RUNTIME, property="backup", normalized_value="true", present=True
        )
        assert contradiction_rule(source=src, runtime=rnt) == CorrelationResult.MATCH

    def test_contradiction_rule_unknown_when_absent(self) -> None:
        src = SourceValue(
            side=Side.SOURCE, property="backup", normalized_value="true", present=True
        )
        rnt = SourceValue(
            side=Side.RUNTIME, property="backup", normalized_value=None, present=False
        )
        assert contradiction_rule(source=src, runtime=rnt) == CorrelationResult.UNKNOWN

    def test_default_rule_registry_has_all_rules(self) -> None:
        reg = default_rule_registry()
        assert set(reg.keys()) == {
            "sr_exact",
            "sr_set",
            "sr_digest",
            "sr_presence",
            "sr_contradiction",
        }

    def test_register_rule_adds_new_rule(self) -> None:
        reg = default_rule_registry()
        custom = CorrelationRule("sr_new", "0.1.0", exact_equality, description="new")
        register_rule(reg, custom)
        assert "sr_new" in reg
        assert reg["sr_new"].version == "0.1.0"

    def test_correlation_rule_reference(self) -> None:
        rule = CorrelationRule("sr_test", "2.0.0", exact_equality)
        ref = rule.reference
        assert ref.rule_id == "sr_test"
        assert ref.version == "2.0.0"

    def test_default_property_resolver_non_comparable(self) -> None:
        reg = default_rule_registry()
        assert default_property_resolver(reg, "namespace") is None
        assert default_property_resolver(reg, "ingress_path") is None

    def test_default_property_resolver_contradiction_sensitive(self) -> None:
        reg = default_rule_registry()
        rule = default_property_resolver(reg, "backup_enabled")
        assert rule is not None
        assert rule.rule_id == "sr_contradiction"

    def test_default_property_resolver_exact(self) -> None:
        reg = default_rule_registry()
        rule = default_property_resolver(reg, "replicas")
        assert rule is not None
        assert rule.rule_id == "sr_exact"


# ──────────────────────────────────────────────────────────────────────
# 4. Confidence
# ──────────────────────────────────────────────────────────────────────


class TestSourceRuntimeConfidence:
    def test_correlation_confidence_takes_weaker(self) -> None:
        assert correlation_confidence(Confidence.LOW, Confidence.HIGH) == Confidence.LOW
        assert correlation_confidence(Confidence.HIGH, Confidence.LOW) == Confidence.LOW

    def test_correlation_confidence_equal(self) -> None:
        assert correlation_confidence(Confidence.MEDIUM, Confidence.MEDIUM) == Confidence.MEDIUM
        assert correlation_confidence(Confidence.LOW, Confidence.LOW) == Confidence.LOW

    def test_correlation_confidence_low_low_never_upgrades(self) -> None:
        result = correlation_confidence(Confidence.LOW, Confidence.LOW)
        assert result == Confidence.LOW
        assert result.to_score() < Confidence.MEDIUM.to_score()

    def test_confidence_to_score_ordering(self) -> None:
        assert Confidence.LOW.to_score() < Confidence.MEDIUM.to_score() < Confidence.HIGH.to_score()


# ──────────────────────────────────────────────────────────────────────
# 5. Redaction
# ──────────────────────────────────────────────────────────────────────


class TestSourceRuntimeRedaction:
    def test_credential_keys_frozen_set(self) -> None:
        from blackforge.source_runtime.redaction import SOURCE_RUNTIME_CREDENTIAL_KEYS
        assert "password" in SOURCE_RUNTIME_CREDENTIAL_KEYS
        assert "token" in SOURCE_RUNTIME_CREDENTIAL_KEYS
        assert "private_key" in SOURCE_RUNTIME_CREDENTIAL_KEYS
        assert "api_key" in SOURCE_RUNTIME_CREDENTIAL_KEYS

    def test_redact_source_runtime_document_nested(self) -> None:
        doc = {
            "identity": {"name": "safe"},
            "properties": {
                "password": "secret123",
                "replicas": "3",
                "nested": {"token": "abc123", "other": "keep"},
            },
        }
        redacted = redact_source_runtime_document(doc)
        assert redacted["identity"]["name"] == "safe"
        assert redacted["properties"]["replicas"] == "3"
        assert redacted["properties"]["password"] == credential_value_redacted()
        assert redacted["properties"]["nested"]["token"] == credential_value_redacted()
        assert redacted["properties"]["nested"]["other"] == "keep"

    def test_redact_source_runtime_raw_preserves_json_shape(self) -> None:
        raw = json.dumps({"a": 1, "b": {"secret": "value", "safe": "ok"}}, sort_keys=True)
        result = redact_source_runtime_raw(raw)
        parsed = json.loads(result)
        assert parsed["a"] == 1
        assert parsed["b"]["safe"] == "ok"
        assert parsed["b"]["secret"] == credential_value_redacted()

    def test_redact_source_runtime_raw_non_dict_passthrough(self) -> None:
        raw = json.dumps([1, 2, 3])
        result = redact_source_runtime_raw(raw)
        assert json.loads(result) == [1, 2, 3]

    def test_redact_source_runtime_document_list_entries(self) -> None:
        doc = {"items": [{"password": "x", "name": "y"}]}
        redacted = redact_source_runtime_document(doc)
        assert redacted["items"][0]["password"] == credential_value_redacted()
        assert redacted["items"][0]["name"] == "y"


# ──────────────────────────────────────────────────────────────────────
# 6. CorrelationEvaluator
# ──────────────────────────────────────────────────────────────────────


class TestCorrelationEvaluator:
    def _eval(self) -> CorrelationEvaluator:
        return CorrelationEvaluator(default_rule_registry())

    def _record(
        self,
        scope_kind: str,
        scope_parts: list[str],
        name: str,
        properties: dict[str, str],
    ) -> dict:
        return {
            "identity": {"scope_kind": scope_kind, "scope_parts": scope_parts, "name": name},
            "properties": properties,
        }

    def test_match_scenario(self) -> None:
        src = self._record("cluster", ["prod", "ns"], "web", {"replicas": "2", "port": "443"})
        rnt = self._record("cluster", ["prod", "ns"], "web", {"replicas": "2", "port": "443"})
        o = self._eval().compare_records(
            source_record=src,
            runtime_record=rnt,
            source_conf=Confidence.MEDIUM,
            runtime_conf=Confidence.MEDIUM,
            capability_id="cap",
        )
        assert o is not None
        assert o.result == CorrelationResult.MATCH
        assert all(c.result == CorrelationResult.MATCH for c in o.comparisons)

    def test_discrepancy_scenario(self) -> None:
        src = self._record("cluster", ["prod", "ns"], "web", {"replicas": "3"})
        rnt = self._record("cluster", ["prod", "ns"], "web", {"replicas": "5"})
        o = self._eval().compare_records(
            source_record=src,
            runtime_record=rnt,
            source_conf=Confidence.MEDIUM,
            runtime_conf=Confidence.MEDIUM,
            capability_id="cap",
        )
        assert o is not None
        assert o.result == CorrelationResult.DISCREPANCY
        assert o.comparisons[0].result == CorrelationResult.DISCREPANCY

    def test_contradiction_scenario(self) -> None:
        src = self._record("cloud", ["aws", "acct"], "db", {"backup_enabled": "true"})
        rnt = self._record("cloud", ["aws", "acct"], "db", {"backup_enabled": "false"})
        o = self._eval().compare_records(
            source_record=src,
            runtime_record=rnt,
            source_conf=Confidence.MEDIUM,
            runtime_conf=Confidence.MEDIUM,
            capability_id="cap",
        )
        assert o is not None
        assert o.result == CorrelationResult.CONTRADICTION
        assert o.comparisons[0].result == CorrelationResult.CONTRADICTION

    def test_unknown_missing_side(self) -> None:
        src = self._record("cloud", ["aws"], "db", {"engine": "postgres"})
        o = self._eval().compare_records(
            source_record=src,
            runtime_record=None,
            source_conf=Confidence.LOW,
            runtime_conf=Confidence.HIGH,
            capability_id="cap",
        )
        assert o is not None
        assert o.result == CorrelationResult.UNKNOWN
        assert o.comparisons[0].result == CorrelationResult.UNKNOWN
        assert "runtime" in o.comparisons[0].note

    def test_not_comparable_same_name_different_scope(self) -> None:
        src = self._record("cluster", ["prod", "payments"], "api", {"port": "443"})
        rnt = self._record("cluster", ["prod", "payments-prod"], "api", {"port": "443"})
        o = self._eval().compare_records(
            source_record=src,
            runtime_record=rnt,
            source_conf=Confidence.MEDIUM,
            runtime_conf=Confidence.MEDIUM,
            capability_id="cap",
        )
        assert o is not None
        assert o.result == CorrelationResult.NOT_COMPARABLE
        assert o.comparisons[0].result == CorrelationResult.NOT_COMPARABLE

    def test_both_missing_returns_none(self) -> None:
        o = self._eval().compare_records(
            source_record=None,
            runtime_record=None,
            source_conf=Confidence.MEDIUM,
            runtime_conf=Confidence.MEDIUM,
            capability_id="cap",
        )
        assert o is None

    def test_no_comparable_properties(self) -> None:
        src = self._record("cluster", ["p", "ns"], "x", {"namespace": "ns"})
        rnt = self._record("cluster", ["p", "ns"], "x", {"namespace": "ns"})
        o = self._eval().compare_records(
            source_record=src,
            runtime_record=rnt,
            source_conf=Confidence.MEDIUM,
            runtime_conf=Confidence.MEDIUM,
            capability_id="cap",
        )
        assert o is not None
        assert o.result == CorrelationResult.NOT_COMPARABLE
        assert o.comparisons[0].rule.rule_id == "sr_none"

    def test_aggregation_contradiction_outranks_discrepancy(self) -> None:
        from blackforge.source_runtime.correlation import _aggregate_result
        results = [
            CorrelationResult.MATCH,
            CorrelationResult.DISCREPANCY,
            CorrelationResult.CONTRADICTION,
        ]
        assert _aggregate_result(results) == CorrelationResult.CONTRADICTION

    def test_aggregation_discrepancy_outranks_unknown(self) -> None:
        from blackforge.source_runtime.correlation import _aggregate_result
        results = [
            CorrelationResult.MATCH,
            CorrelationResult.UNKNOWN,
            CorrelationResult.DISCREPANCY,
        ]
        assert _aggregate_result(results) == CorrelationResult.DISCREPANCY

    def test_aggregation_unknown_when_only_matches(self) -> None:
        from blackforge.source_runtime.correlation import _aggregate_result
        assert _aggregate_result([CorrelationResult.MATCH]) == CorrelationResult.MATCH

    def test_aggregation_unknown_present_no_discrepancy(self) -> None:
        from blackforge.source_runtime.correlation import _aggregate_result
        results = [CorrelationResult.MATCH, CorrelationResult.UNKNOWN]
        assert _aggregate_result(results) == CorrelationResult.UNKNOWN

    def test_confidence_floor_never_exceeds_either_side(self) -> None:
        src = self._record("cloud", ["a"], "db", {"engine": "postgres"})
        rnt = self._record("cloud", ["a"], "db", {"engine": "postgres"})
        o = self._eval().compare_records(
            source_record=src,
            runtime_record=rnt,
            source_conf=Confidence.LOW,
            runtime_conf=Confidence.HIGH,
            capability_id="cap",
        )
        assert o is not None
        assert o.confidence == Confidence.LOW

    def test_contradiction_preserves_both_sides(self) -> None:
        src = self._record(
            "cloud", ["a"], "db", {"publicly_accessible": "true", "tls_enabled": "true"}
        )
        rnt = self._record(
            "cloud", ["a"], "db", {"publicly_accessible": "false", "tls_enabled": "false"}
        )
        o = self._eval().compare_records(
            source_record=src,
            runtime_record=rnt,
            source_conf=Confidence.MEDIUM,
            runtime_conf=Confidence.MEDIUM,
            capability_id="cap",
        )
        assert o is not None
        assert o.result == CorrelationResult.CONTRADICTION
        contradictions = [c for c in o.comparisons if c.result == CorrelationResult.CONTRADICTION]
        assert len(contradictions) == 2
        assert contradictions[0].source_value != contradictions[0].runtime_value
        assert contradictions[1].source_value != contradictions[1].runtime_value


# ──────────────────────────────────────────────────────────────────────
# 7. Evidence helpers
# ──────────────────────────────────────────────────────────────────────


class TestSourceRuntimeEvidence:
    def test_source_evidence_type_and_provenance(self) -> None:
        ev = source_evidence(MID, "target", "cap", {"identity": {}, "properties": {}})
        assert ev.evidence_type == EvidenceType.SOURCE_ANALYSIS
        assert ev.provenance.provenance_type == ProvenanceType.DIRECT
        assert ev.metadata["source_runtime_side"] == "source"
        assert ev.mission_id == MID

    def test_runtime_evidence_type_and_provenance(self) -> None:
        ev = runtime_evidence(MID, "target", "cap", {"identity": {}, "properties": {}})
        assert ev.evidence_type == EvidenceType.OBSERVATION
        assert ev.provenance.provenance_type == ProvenanceType.DIRECT
        assert ev.metadata["source_runtime_side"] == "runtime"

    def test_correlation_outcome_evidence_is_derived(self) -> None:
        id_ = build_correlation_identity("cloud", ["a"], "b")
        outcome = CorrelationOutcome(
            capability_id="cap",
            identity=id_,
            result=CorrelationResult.MATCH,
            confidence=Confidence.MEDIUM,
        )
        ev = correlation_outcome_evidence(
            MID, "target", "cap", outcome,
            source_evidence_id="src1",
            runtime_evidence_id="rnt1",
        )
        assert ev.evidence_type == EvidenceType.VALIDATION_RESULT
        assert ev.provenance.provenance_type == ProvenanceType.DERIVED
        assert ev.provenance.parent_evidence_id == "src1"
        assert "match" in ev.raw_data
        assert ev.metadata["source_evidence_id"] == "src1"
        assert ev.metadata["runtime_evidence_id"] == "rnt1"

    def test_link_correlation_evidence_creates_derived_from_edges(self) -> None:
        ev = EvidenceStore(repository=InMemoryEvidenceRepository())
        id_ = build_correlation_identity("cloud", ["a"], "b")
        outcome = CorrelationOutcome(
            capability_id="cap", identity=id_,
            result=CorrelationResult.MATCH, confidence=Confidence.MEDIUM,
        )
        corr_ev = correlation_outcome_evidence(MID, "t", "cap", outcome)
        stored_corr = ev.add(corr_ev)
        src_ev = source_evidence(MID, "t", "cap", {"identity": {}, "properties": {}})
        rnt_ev = runtime_evidence(MID, "t", "cap", {"identity": {}, "properties": {}})
        src_id = ev.add(src_ev).id
        rnt_id = ev.add(rnt_ev).id
        link_correlation_evidence(ev, stored_corr.id, src_id, rnt_id,
                                  result=outcome.result, identity=outcome.identity)
        rels = ev.get_relationships(stored_corr.id)
        derived_rels = [r for r in rels if r.relation_type == EvidenceRelation.DERIVED_FROM]
        assert len(derived_rels) == 2
        targets = {r.target_id for r in derived_rels}
        assert src_id in targets
        assert rnt_id in targets

    def test_evidence_dedup_key_deterministic(self) -> None:
        ev = source_evidence(MID, "t", "cap", {"identity": {"a": 1}, "properties": {}})
        k1 = evidence_dedup_key_for(ev)
        k2 = evidence_dedup_key_for(ev)
        assert k1 == k2
        assert len(k1) > 0

    def test_existing_evidence_id_dedup(self) -> None:
        ev = EvidenceStore(repository=InMemoryEvidenceRepository())
        first = source_evidence(MID, "t", "cap", {"identity": {}, "properties": {"x": 1}})
        id1 = ev.add(first).id
        second = source_evidence(MID, "t", "cap", {"identity": {}, "properties": {"x": 1}})
        assert existing_evidence_id(ev, second) == id1
        different = source_evidence(MID, "t", "cap", {"identity": {}, "properties": {"x": 2}})
        assert existing_evidence_id(ev, different) is None

    def test_source_evidence_raw_data_redacted(self) -> None:
        ev = source_evidence(
            MID, "t", "cap", {"identity": {}, "properties": {"password": "secret"}}
        )
        assert credential_value_redacted() in ev.raw_data
        assert "secret" not in ev.raw_data


# ──────────────────────────────────────────────────────────────────────
# 8. World model materializer
# ──────────────────────────────────────────────────────────────────────


class TestSourceRuntimeWorldModel:
    def _wm(self) -> WorldModelStore:
        return WorldModelStore(repository=InMemoryWorldRepository())

    def test_materialize_match_creates_corresponds_to_edge(self) -> None:
        wm = self._wm()
        mat = SourceRuntimeWorldMaterializer(wm)
        id_ = build_correlation_identity("cloud", ["a", "b"], "db")
        outcome = CorrelationOutcome(
            capability_id="cap", identity=id_,
            result=CorrelationResult.MATCH, confidence=Confidence.MEDIUM,
        )
        report = mat.materialize(MID, [(outcome, "ev1", Confidence.MEDIUM)])
        assert report.entities_created == 1
        assert report.relationships_created >= 3
        assert report.assertions_created >= 1

        ents = wm.list_entities(WorldQuery(mission_id=MID, entity_type=EntityType.SOURCE_COMPONENT))
        ent_names = {e.name for e in ents}
        assert id_.identity in ent_names
        assert f"{id_.identity}:source" in ent_names
        assert f"{id_.identity}:runtime" in ent_names

        rels = wm.list_relationships(RelationshipQuery(mission_id=MID))
        rel_types = {r.relationship_type for r in rels}
        assert RelationshipType.DECLARED_AS in rel_types
        assert RelationshipType.OBSERVED_AS in rel_types
        assert RelationshipType.CORRESPONDS_TO in rel_types
        assert RelationshipType.DIFFERS_FROM not in rel_types

    def test_materialize_discrepancy_creates_differs_from_edge(self) -> None:
        wm = self._wm()
        mat = SourceRuntimeWorldMaterializer(wm)
        id_ = build_correlation_identity("cluster", ["prod", "ns"], "web")
        outcome = CorrelationOutcome(
            capability_id="cap", identity=id_,
            result=CorrelationResult.DISCREPANCY, confidence=Confidence.MEDIUM,
        )
        report = mat.materialize(MID, [(outcome, "ev2", Confidence.MEDIUM)])
        assert report.entities_created == 1
        assert report.relationships_created >= 3
        rels = wm.list_relationships(RelationshipQuery(mission_id=MID))
        rel_types = {r.relationship_type for r in rels}
        assert RelationshipType.DIFFERS_FROM in rel_types
        assert RelationshipType.CORRESPONDS_TO not in rel_types

    def test_materialize_assertion_value(self) -> None:
        wm = self._wm()
        mat = SourceRuntimeWorldMaterializer(wm)
        id_ = build_correlation_identity("cloud", ["a"], "db")
        outcome = CorrelationOutcome(
            capability_id="cap", identity=id_,
            result=CorrelationResult.MATCH, confidence=Confidence.MEDIUM,
        )
        mat.materialize(MID, [(outcome, "ev3", Confidence.MEDIUM)])
        ents = wm.list_entities(WorldQuery(mission_id=MID, entity_type=EntityType.SOURCE_COMPONENT))
        main = [e for e in ents if e.name == id_.identity]
        assert len(main) == 1
        assertions = wm.list_assertions(str(main[0].id))
        vals = {a.property_key: a.property_value for a in assertions}
        assert vals["correlation_result"] == "match"

    def test_materialize_re_run_corroborates(self) -> None:
        wm = self._wm()
        mat = SourceRuntimeWorldMaterializer(wm)
        id_ = build_correlation_identity("cloud", ["a"], "db")
        outcome = CorrelationOutcome(
            capability_id="cap", identity=id_,
            result=CorrelationResult.MATCH, confidence=Confidence.MEDIUM,
        )
        r1 = mat.materialize(MID, [(outcome, "ev4", Confidence.MEDIUM)])
        assert r1.entities_created == 1
        r2 = mat.materialize(MID, [(outcome, "ev5", Confidence.MEDIUM)])
        assert r2.entities_created == 0
        assert r2.entities_updated == 1
        assert r2.assertions_corroborated >= r1.assertions_created

    def test_materialize_sibling_entities(self) -> None:
        wm = self._wm()
        mat = SourceRuntimeWorldMaterializer(wm)
        id_ = build_correlation_identity("cloud", ["a"], "db")
        outcome = CorrelationOutcome(
            capability_id="cap", identity=id_,
            result=CorrelationResult.MATCH, confidence=Confidence.MEDIUM,
        )
        mat.materialize(MID, [(outcome, "ev6", Confidence.MEDIUM)])
        ents = wm.list_entities(WorldQuery(mission_id=MID, entity_type=EntityType.SOURCE_COMPONENT))
        names = {e.name for e in ents}
        assert f"{id_.identity}:source" in names
        assert f"{id_.identity}:runtime" in names
        assert id_.identity in names

    def test_materialize_report_properties(self) -> None:
        from blackforge.source_runtime.materializer import SourceRuntimeMaterializeEntry

        r = SourceRuntimeMaterializeReport()
        assert r.entities_created == 0
        assert r.entities_updated == 0
        r.entries.append(
            SourceRuntimeMaterializeEntry(
                entity_type="source_component", name="x", entity_id="1", action="created",
            )
        )
        assert r.entities_created == 1
        assert r.entities_updated == 0


# ──────────────────────────────────────────────────────────────────────
# 9. Transport
# ──────────────────────────────────────────────────────────────────────


class TestSourceRuntimeTransport:
    def test_family_scope_kind_map(self) -> None:
        from blackforge.source_runtime.transport import FAMILY_SCOPE_KIND
        assert FAMILY_SCOPE_KIND["container_configuration_correlation"] == "cluster"
        assert FAMILY_SCOPE_KIND["image_runtime_correlation"] == "image"
        assert FAMILY_SCOPE_KIND["cloud_resource_correlation"] == "cloud"
        assert len(FAMILY_SCOPE_KIND) == 10

    def test_umbrella_target_returns_all_records_for_scope_kind(self) -> None:
        t = MockSourceRuntimeTransport()
        raw = t.execute("source_runtime.cloud_resource_correlation", "cloud")
        doc = json.loads(raw)
        assert doc["scope_kind"] == "cloud"
        assert len(doc["source"]) == 1
        assert len(doc["runtime"]) == 1
        assert doc["source"][0]["identity"]["name"] == "payments-database"

    def test_scoped_cluster_target_filters_records(self) -> None:
        t = MockSourceRuntimeTransport()
        raw = t.execute(
            "source_runtime.container_configuration_correlation", "aelionix-prod/payments"
        )
        doc = json.loads(raw)
        assert len(doc["source"]) == 1
        assert doc["source"][0]["identity"]["name"] == "payment-gateway"
        assert len(doc["runtime"]) == 1
        assert doc["runtime"][0]["identity"]["name"] == "payment-gateway"

    def test_umbrella_cluster_returns_all_cluster_records(self) -> None:
        t = MockSourceRuntimeTransport()
        raw = t.execute("source_runtime.container_configuration_correlation", "cluster")
        doc = json.loads(raw)
        assert len(doc["source"]) == 3
        assert len(doc["runtime"]) == 4
        assert "payments-prod" in {r["identity"]["scope_parts"][1] for r in doc["runtime"]}

    def test_unknown_capability_returns_error(self) -> None:
        t = MockSourceRuntimeTransport()
        raw = t.execute("source_runtime.bogus_capability", "cloud")
        doc = json.loads(raw)
        assert "error" in doc
        assert doc["error"]["kind"] == "unsupported_capability"

    def test_transport_returns_valid_json(self) -> None:
        t = MockSourceRuntimeTransport()
        raw = t.execute("source_runtime.image_runtime_correlation", "registry.aelionix.io")
        doc = json.loads(raw)
        assert doc["tool"] == "source_runtime.image_runtime_correlation"
        assert "source" in doc
        assert "runtime" in doc


# ──────────────────────────────────────────────────────────────────────
# 10. Declared/Runtime fixtures
# ──────────────────────────────────────────────────────────────────────


class TestSourceRuntimeFixtures:
    def test_declared_entries_non_empty(self) -> None:
        assert len(DECLARED_ENTRIES) == 5

    def test_observed_entries_non_empty(self) -> None:
        assert len(OBSERVED_ENTRIES) == 6

    def test_source_fixture_provider_returns_copies(self) -> None:
        entries = SourceFixtureProvider.declared_entries()
        assert len(entries) == len(DECLARED_ENTRIES)
        entries[0]["properties"]["new"] = "injected"
        assert "new" not in DECLARED_ENTRIES[0]["properties"]

    def test_runtime_fixture_provider_returns_copies(self) -> None:
        entries = RuntimeFixtureProvider.observed_entries()
        assert len(entries) == len(OBSERVED_ENTRIES)
        entries[0]["properties"]["new"] = "injected"
        assert "new" not in OBSERVED_ENTRIES[0]["properties"]

    def test_fixture_identity_structure(self) -> None:
        for entry in DECLARED_ENTRIES:
            assert "scope_kind" in entry["identity"]
            assert "scope_parts" in entry["identity"]
            assert "name" in entry["identity"]

    def test_fixture_all_have_properties(self) -> None:
        for entry in DECLARED_ENTRIES + OBSERVED_ENTRIES:
            assert "properties" in entry
            assert isinstance(entry["properties"], dict)


# ──────────────────────────────────────────────────────────────────────
# 11. Capabilities
# ──────────────────────────────────────────────────────────────────────


class TestSourceRuntimeCapabilities:
    def test_ten_capability_ids(self) -> None:
        assert len(SOURCE_RUNTIME_CAPABILITY_IDS) == 10

    def test_capability_ids_prefixed(self) -> None:
        for cap_id in SOURCE_RUNTIME_CAPABILITY_IDS:
            assert cap_id.startswith("source_runtime.")

    def test_build_source_runtime_meta_count(self) -> None:
        meta_list = build_source_runtime_meta()
        assert len(meta_list) == 10

    def test_meta_has_compares_field(self) -> None:
        for m in build_source_runtime_meta():
            assert CorrelationResult.MATCH in m.compares
            assert CorrelationResult.DISCREPANCY in m.compares
            assert CorrelationResult.CONTRADICTION in m.compares

    def test_build_capabilities_returns_10(self) -> None:
        eng, _, _ = _engine()
        caps = build_capabilities(eng)
        assert len(caps) == 10
        for c in caps:
            assert isinstance(c, SourceRuntimeCorrelationCapability)

    def test_capability_has_meta_method(self) -> None:
        eng, _, _ = _engine()
        caps = build_capabilities(eng)
        meta = caps[0].meta()
        assert isinstance(meta, SourceRuntimeCapabilityMeta)
        assert meta.risk_level == RiskLevel.LOW


# ──────────────────────────────────────────────────────────────────────
# 12. Engine — end-to-end scenario matrix
# ──────────────────────────────────────────────────────────────────────


class TestSourceRuntimeEngine:
    def test_cloud_umbrella_contradiction_and_discrepancy(self) -> None:
        eng, ev, wm = _engine()
        req = _request()
        r = eng.run("source_runtime.cloud_resource_correlation", req, target="cloud")
        assert r.status == SourceRuntimeStatus.PARTIAL
        assert len(r.outcomes) == 1
        o = r.outcomes[0]
        assert o.result == CorrelationResult.CONTRADICTION
        assert o.identity.identity == "cloud:aws:acct-112233445566:us-east-1:payments-database"
        contradiction_comp = [
            c for c in o.comparisons if c.result == CorrelationResult.CONTRADICTION
        ]
        assert len(contradiction_comp) == 1
        assert contradiction_comp[0].property == "backup_enabled"
        assert contradiction_comp[0].source_value == "true"
        assert contradiction_comp[0].runtime_value == "false"
        discrepancy_comp = [
            c for c in o.comparisons if c.result == CorrelationResult.DISCREPANCY
        ]
        assert len(discrepancy_comp) == 1
        assert discrepancy_comp[0].property == "version"
        assert discrepancy_comp[0].source_value == "16"
        assert discrepancy_comp[0].runtime_value == "15"

    def test_cluster_umbrella_match_discrepancy_unknown(self) -> None:
        eng, ev, wm = _engine()
        req = _request()
        r = eng.run(
            "source_runtime.container_configuration_correlation", req, target="cluster"
        )
        assert r.status == SourceRuntimeStatus.PARTIAL
        assert len(r.outcomes) == 4
        by_id = {o.identity.identity: o for o in r.outcomes}
        assert (
            by_id["cluster:aelionix-prod:payments:payment-gateway"].result
            == CorrelationResult.MATCH
        )
        assert (
            by_id["cluster:aelionix-staging:payments:payment-gateway"].result
            == CorrelationResult.MATCH
        )
        assert (
            by_id["cluster:aelionix-prod:marketing:marketing-site"].result
            == CorrelationResult.DISCREPANCY
        )
        assert (
            by_id["cluster:aelionix-prod:payments-prod:payment-gateway"].result
            == CorrelationResult.UNKNOWN
        )

    def test_prod_payments_match(self) -> None:
        eng, _, _ = _engine()
        req = _request()
        r = eng.run(
            "source_runtime.container_configuration_correlation",
            req,
            target="aelionix-prod/payments",
        )
        assert r.status == SourceRuntimeStatus.SUCCESS
        assert len(r.outcomes) == 1
        assert r.outcomes[0].result == CorrelationResult.MATCH
        assert (
            r.outcomes[0].identity.identity
            == "cluster:aelionix-prod:payments:payment-gateway"
        )
        assert all(c.result == CorrelationResult.MATCH for c in r.outcomes[0].comparisons)

    def test_staging_payments_match(self) -> None:
        eng, _, _ = _engine()
        req = _request()
        r = eng.run(
            "source_runtime.container_configuration_correlation",
            req,
            target="aelionix-staging/payments",
        )
        assert r.status == SourceRuntimeStatus.SUCCESS
        assert r.outcomes[0].result == CorrelationResult.MATCH

    def test_image_match(self) -> None:
        eng, _, _ = _engine()
        req = _request()
        r = eng.run(
            "source_runtime.image_runtime_correlation", req, target="registry.aelionix.io"
        )
        assert r.status == SourceRuntimeStatus.SUCCESS
        assert len(r.outcomes) == 1
        assert r.outcomes[0].result == CorrelationResult.MATCH
        props = {c.property: c.result for c in r.outcomes[0].comparisons}
        assert props["digest"] == CorrelationResult.MATCH
        assert props["tag"] == CorrelationResult.MATCH

    def test_marketing_discrepancy_on_replicas(self) -> None:
        eng, _, _ = _engine()
        req = _request()
        r = eng.run(
            "source_runtime.container_configuration_correlation",
            req,
            target="aelionix-prod/marketing",
        )
        assert r.status == SourceRuntimeStatus.PARTIAL
        assert r.outcomes[0].result == CorrelationResult.DISCREPANCY
        replicas_comp = [
            c for c in r.outcomes[0].comparisons if c.property == "replicas"
        ]
        assert len(replicas_comp) == 1
        assert replicas_comp[0].source_value == "3"
        assert replicas_comp[0].runtime_value == "5"

    def test_payments_prod_unknown_missing_source(self) -> None:
        eng, _, _ = _engine()
        req = _request()
        r = eng.run(
            "source_runtime.container_configuration_correlation",
            req,
            target="cluster",
        )
        payments_prod = [o for o in r.outcomes if "payments-prod" in o.identity.identity]
        assert len(payments_prod) == 1
        assert payments_prod[0].result == CorrelationResult.UNKNOWN
        assert "source" in payments_prod[0].comparisons[0].note

    def test_unknown_capability_returns_status(self) -> None:
        eng, _, _ = _engine()
        req = _request()
        r = eng.run("source_runtime.bogus", req, target="cloud")
        assert r.status == SourceRuntimeStatus.UNKNOWN_CAPABILITY
        assert "unknown" in r.error.lower()
        assert len(r.outcomes) == 0

    def test_authz_denied_raises(self) -> None:
        eng, _, _ = _engine()
        req = _request(targets=[Target(value="cloud", target_type=TargetType.CLOUD)])
        with pytest.raises(AuthorizationError, match="denied"):
            eng.run(
                "source_runtime.container_configuration_correlation",
                req,
                target="aelionix-prod/payments",
            )

    def test_transport_no_fixture_records(self) -> None:
        transport = MockSourceRuntimeTransport()
        raw = transport.execute(
            "source_runtime.container_configuration_correlation",
            "nonexistent-ns/nonexistent-svc",
        )
        doc = json.loads(raw)
        assert doc["error"]["kind"] == "no_fixture_records"
        assert isinstance(doc["error"]["message"], str)

    def test_transport_error_document_propagates(self) -> None:
        with pytest.raises(SourceRuntimeExecutionError, match="no_fixture_records"):
            raw = MockSourceRuntimeTransport().execute(
                "source_runtime.container_configuration_correlation",
                "missing-ns/missing-app",
            )
            eng = SourceRuntimeEngine()
            eng._parse_document(raw, "missing-ns/missing-app")

    def test_evidence_persisted_cloud(self) -> None:
        eng, ev, _ = _engine()
        req = _request()
        r = eng.run("source_runtime.cloud_resource_correlation", req, target="cloud")
        assert len(r.evidence_ids) == 3
        corr_id, src_id, rnt_id = r.evidence_ids
        rels = ev.get_relationships(corr_id)
        derived = [x for x in rels if x.relation_type == EvidenceRelation.DERIVED_FROM]
        assert len(derived) >= 2

    def test_evidence_dedup_across_runs(self) -> None:
        eng, ev, _ = _engine()
        req = _request()
        r1 = eng.run("source_runtime.cloud_resource_correlation", req, target="cloud")
        r2 = eng.run("source_runtime.cloud_resource_correlation", req, target="cloud")
        assert r1.evidence_ids == r2.evidence_ids

    def test_world_model_materialized(self) -> None:
        eng, _, wm = _engine()
        req = _request()
        eng.run("source_runtime.cloud_resource_correlation", req, target="cloud")
        ents = wm.list_entities(WorldQuery(mission_id=MID, entity_type=EntityType.SOURCE_COMPONENT))
        assert len(ents) >= 3
        names = {e.name for e in ents}
        assert "cloud:aws:acct-112233445566:us-east-1:payments-database" in names
        rels = wm.list_relationships(RelationshipQuery(mission_id=MID))
        rel_types = {r.relationship_type for r in rels}
        assert RelationshipType.DECLARED_AS in rel_types
        assert RelationshipType.OBSERVED_AS in rel_types
        assert RelationshipType.DIFFERS_FROM in rel_types

    def test_world_model_corresponds_to_for_match(self) -> None:
        eng, _, wm = _engine()
        req = _request()
        eng.run("source_runtime.image_runtime_correlation", req, target="registry.aelionix.io")
        rels = wm.list_relationships(RelationshipQuery(mission_id=MID))
        rel_types = {r.relationship_type for r in rels}
        assert RelationshipType.CORRESPONDS_TO in rel_types
        assert RelationshipType.DIFFERS_FROM not in rel_types

    def test_engine_capabilities_property(self) -> None:
        eng, _, _ = _engine()
        assert len(eng.capabilities) == 10

    def test_engine_has_capability(self) -> None:
        eng, _, _ = _engine()
        assert eng.has_capability("source_runtime.cloud_resource_correlation")
        assert not eng.has_capability("source_runtime.bogus")

    def test_engine_success_for_all_match(self) -> None:
        eng, _, _ = _engine()
        req = _request()
        r = eng.run(
            "source_runtime.container_configuration_correlation",
            req,
            target="aelionix-prod/payments",
        )
        assert r.status == SourceRuntimeStatus.SUCCESS
        assert r.authorized is True
        assert r.duration_ms > 0

    def test_engine_result_metadata(self) -> None:
        eng, _, _ = _engine()
        req = _request()
        r = eng.run("source_runtime.cloud_resource_correlation", req, target="cloud")
        d = r.model_dump(mode="json")
        assert d["mission_id"] == MID
        assert d["status"] == "partial"
        assert len(d["outcomes"]) == 1

    def test_engine_coexists_with_container_engine(self) -> None:
        from blackforge.container.engine import ContainerEngine
        reg = CapabilityRegistry()
        evidence = EvidenceStore(repository=InMemoryEvidenceRepository())
        world = WorldModelStore(repository=InMemoryWorldRepository())
        auth = AuthorizationBoundary(mode="strict")
        sr = SourceRuntimeEngine(
            capability_registry=reg, evidence_store=evidence,
            world_model=world, authorization=auth,
        )
        ct = ContainerEngine(
            capability_registry=reg, evidence_store=evidence,
            world_model=world, authorization=auth,
        )
        assert len(sr.capabilities) == 10
        assert len(ct.capabilities) == 14
        assert len(reg.list_capabilities()) >= 24


# ──────────────────────────────────────────────────────────────────────
# 13. Bootstrap integration
# ──────────────────────────────────────────────────────────────────────


class TestSourceRuntimeBootstrap:
    def test_bootstrap_registry_size(self) -> None:
        app = bootstrap()
        assert len(app.capability_registry.list_capabilities()) == 105

    def test_bootstrap_source_runtime_engine_present(self) -> None:
        app = bootstrap()
        assert app.source_runtime_engine is not None
        assert len(app.source_runtime_engine.capabilities) == 10

    def test_bootstrap_verify_source_runtime_ready(self) -> None:
        app = bootstrap()
        checks = app.verify()
        assert checks["source_runtime_ready"] is True

    def test_bootstrap_all_checks_true(self) -> None:
        app = bootstrap()
        status = app.verify()
        assert all(status.values()), f"failing checks: {[k for k, v in status.items() if not v]}"

    def test_bootstrap_app_healthy(self) -> None:
        app = bootstrap()
        assert app.healthy() is True

    def test_bootstrap_source_runtime_engine_registered(self) -> None:
        app = bootstrap()
        assert app.capability_registry.has("source_runtime.cloud_resource_correlation")
        assert app.capability_registry.has("source_runtime.container_configuration_correlation")
        assert app.capability_registry.has("source_runtime.image_runtime_correlation")
        assert app.capability_registry.has("source_runtime.rbac_manifest_correlation")

    def test_bootstrap_no_existing_checks_broken(self) -> None:
        app = bootstrap()
        checks = app.verify()
        existing_checks = [
            "config_loaded", "logging_initialized", "mission_manager_ready",
            "capability_registry_ready", "memory_ready", "llm_ready",
            "authorization_ready", "evidence_store_ready", "world_model_ready",
            "model_router_ready", "recon_ready", "webapi_ready", "auth_ready",
            "business_logic_ready", "network_ready", "identity_ready",
            "cloud_ready", "container_ready",
        ]
        for key in existing_checks:
            assert key in checks, f"missing check: {key}"
            assert checks[key] is True, f"check {key} is False"

    def test_no_generic_shell_executor(self) -> None:
        for root, _dirs, files in os.walk("blackforge/source_runtime"):
            for name in files:
                if not name.endswith(".py"):
                    continue
                with open(os.path.join(root, name), encoding="utf-8") as fh:
                    text = fh.read()
                for banned in (
                    "os.system",
                    "subprocess",
                    "socket",
                    "requests.",
                    "urllib.request",
                    "http.client",
                    "eval(",
                    "exec(",
                    "pickle",
                ):
                    assert banned not in text, (name, banned)
