from __future__ import annotations

import pytest

from blackforge.core.errors import EvidenceRuleError
from blackforge.core.types import (
    Confidence,
    EvidenceID,
    EvidenceStatus,
    EvidenceType,
    MissionID,
    SessionID,
)
from blackforge.evidence.bridge import EvidenceMemoryBridge
from blackforge.evidence.models import (
    Evidence,
    EvidenceLifecycle,
    EvidenceRelation,
)
from blackforge.evidence.query import EvidenceQuery
from blackforge.evidence.repository import (
    InMemoryEvidenceRepository,
    SQLiteEvidenceRepository,
    compute_evidence_dedup_key,
)
from blackforge.evidence.store import EvidenceStore
from blackforge.memory.base import MemoryRecord, MemoryType
from blackforge.memory.manager import MemoryManager
from blackforge.memory.repository import SQLiteMemoryRepository

MID = MissionID("mission_phase3")
SID = SessionID("sess_phase3")
MID_OTHER = MissionID("mission_other")


def _evidence(
    mission_id: MissionID = MID,
    **overrides,
) -> Evidence:
    defaults: dict = {
        "mission_id": mission_id,
        "session_id": SID,
        "source_capability": "mock_discovery",
        "target": "example.com",
        "evidence_type": EvidenceType.OBSERVATION,
        "status": EvidenceStatus.OBSERVED,
        "confidence": Confidence.MEDIUM,
        "raw_data": "port 443 open",
        "summary": "443 open",
    }
    defaults.update(overrides)
    return Evidence(**defaults)


EVIDENCE_REPOS = [
    pytest.param(
        lambda tmp_path: InMemoryEvidenceRepository(),
        id="in_memory",
    ),
    pytest.param(
        lambda tmp_path: SQLiteEvidenceRepository(str(tmp_path / "evidence.db")),
        id="sqlite",
    ),
]


def _store_with(factory, tmp_path) -> EvidenceStore:
    return EvidenceStore(repository=factory(tmp_path))


@pytest.mark.parametrize("factory", EVIDENCE_REPOS)
class TestEvidenceCrudAndDedup:
    def test_create_retrieve_count(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        e = store.add(_evidence())
        assert e.id.startswith("ev_")
        assert store.get(e.id) is not None
        assert store.count() == 1
        assert store.count(MID) == 1
        assert store.count(MID_OTHER) == 0
        store.close()

    def test_get_by_mission(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        store.add(_evidence())
        store.add(_evidence(mission_id=MID_OTHER))
        store.add(_evidence(evidence_type=EvidenceType.RESPONSE))
        assert len(store.get_by_mission(MID)) == 2
        assert len(store.get_by_mission(MID_OTHER)) == 1
        store.close()

    def test_get_missing_returns_none(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        assert store.get(EvidenceID("ev_missing")) is None
        store.close()

    def test_identical_evidence_dedups(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        first = store.add(_evidence())
        second = store.add(_evidence())
        assert first.id == second.id
        assert store.count() == 1
        store.close()

    def test_distinct_observations_remain_distinct(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        a = store.add(_evidence(raw_data="port 443 open"))
        b = store.add(_evidence(raw_data="port 443 closed"))
        assert a.id != b.id
        assert store.count() == 2
        store.close()

    def test_same_payload_different_mission_do_not_dedup(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        a = store.add(_evidence(mission_id=MID))
        b = store.add(_evidence(mission_id=MID_OTHER))
        assert a.id != b.id
        assert store.count() == 2
        store.close()

    def test_dedup_key_is_deterministic_and_excludes_timestamps(self, factory, tmp_path) -> None:
        e1 = _evidence()
        e2 = _evidence()
        key = compute_evidence_dedup_key(
            e1.mission_id, e1.target, e1.source_capability, e1.evidence_type,
            {"raw_data": e1.raw_data, "reference": e1.reference},
        )
        same = compute_evidence_dedup_key(
            e2.mission_id, e2.target, e2.source_capability, e2.evidence_type,
            {"raw_data": e2.raw_data, "reference": e2.reference},
        )
        assert key == same
        assert "timestamp" not in key


@pytest.mark.parametrize("factory", EVIDENCE_REPOS)
class TestStatusTransitions:
    def test_llm_claim_starts_as_hypothesis(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        claim = store.add_claim(MID, "SQL injection may exist on /users", session_id=SID)
        assert claim.status == EvidenceStatus.HYPOTHESIZED
        assert claim.confidence == Confidence.LOW
        assert claim.provenance.provenance_type.value == "inferred"
        store.close()

    def test_creating_validated_without_validation_is_rejected(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        with pytest.raises(EvidenceRuleError):
            store.add(
                _evidence(
                    status=EvidenceStatus.VALIDATED,
                    evidence_type=EvidenceType.VALIDATION_RESULT,
                )
            )
        store.close()

    def test_validation_workflow_can_create_validated(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        claim = store.add_claim(MID, "may exist")
        validation = store.add_validation(
            MID,
            "example.com /users",
            "confirmed: parameterized query in place",
            source_capability="validate_authorized",
            validates_id=claim.id,
        )
        assert validation.status == EvidenceStatus.VALIDATED
        assert validation.evidence_type == EvidenceType.VALIDATION_RESULT
        assert store.get(claim.id).status == EvidenceStatus.HYPOTHESIZED
        store.close()

    def test_validate_unknown_evidence_rejected(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        with pytest.raises(EvidenceRuleError):
            store.add_validation(
                MID, "t", "r", source_capability="cap", validates_id=EvidenceID("ev_nope")
            )
        store.close()

    def test_legal_transitions(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        e = store.add(_evidence(status=EvidenceStatus.OBSERVED))
        store.transition_status(e.id, EvidenceStatus.INFERRED)
        assert store.get(e.id).status == EvidenceStatus.INFERRED
        store.transition_status(e.id, EvidenceStatus.HYPOTHESIZED)
        assert store.get(e.id).status == EvidenceStatus.HYPOTHESIZED
        store.transition_status(e.id, EvidenceStatus.VALIDATED, via_validation=True)
        assert store.get(e.id).status == EvidenceStatus.VALIDATED
        store.close()

    def test_validated_requires_validation_flag(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        e = store.add(_evidence(status=EvidenceStatus.OBSERVED))
        with pytest.raises(EvidenceRuleError):
            store.transition_status(e.id, EvidenceStatus.VALIDATED)
        assert store.get(e.id).status == EvidenceStatus.OBSERVED
        store.close()

    def test_downgrades_are_rejected(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        inf = store.add(_evidence(status=EvidenceStatus.INFERRED))
        with pytest.raises(EvidenceRuleError):
            store.transition_status(inf.id, EvidenceStatus.OBSERVED)
        hyp = store.add_claim(MID, "llm claim")
        with pytest.raises(EvidenceRuleError):
            store.transition_status(hyp.id, EvidenceStatus.INFERRED)
        val = store.add(
            _evidence(
                status=EvidenceStatus.VALIDATED,
                evidence_type=EvidenceType.VALIDATION_RESULT,
            ),
            via_validation=True,
        )
        with pytest.raises(EvidenceRuleError):
            store.transition_status(val.id, EvidenceStatus.HYPOTHESIZED)
        store.close()

    def test_noop_transition_allowed(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        e = store.add(_evidence())
        store.transition_status(e.id, EvidenceStatus.OBSERVED)
        assert store.get(e.id).status == EvidenceStatus.OBSERVED
        store.close()


@pytest.mark.parametrize("factory", EVIDENCE_REPOS)
class TestLifecycle:
    def test_archive(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        e = store.add(_evidence())
        store.archive(e.id)
        loaded = store.get(e.id)
        assert loaded.lifecycle == EvidenceLifecycle.ARCHIVED
        assert loaded.status == EvidenceStatus.OBSERVED
        store.close()

    def test_invalidate_preserves_history(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        e = store.add(
            _evidence(
                status=EvidenceStatus.VALIDATED,
                evidence_type=EvidenceType.VALIDATION_RESULT,
            ),
            via_validation=True,
        )
        cause = store.add(_evidence(raw_data="later scan disproved the finding"))
        store.invalidate(e.id, reason="later scan disproved", causing_evidence_id=cause.id)
        loaded = store.get(e.id)
        assert loaded.status == EvidenceStatus.VALIDATED
        assert loaded.lifecycle == EvidenceLifecycle.INVALIDATED
        assert loaded.metadata["invalidated_reason"] == "later scan disproved"
        rels = store.get_relationships(e.id)
        assert any(r.relation_type == EvidenceRelation.INVALIDATES for r in rels)
        store.close()

    def test_supersede(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        old = store.add(_evidence(raw_data="port 443 open"))
        new = store.add(_evidence(raw_data="port 443 closed"))
        store.supersede(old.id, new.id)
        assert store.get(old.id).lifecycle == EvidenceLifecycle.SUPERSEDED
        assert store.get(new.id).lifecycle == EvidenceLifecycle.ACTIVE
        rels = store.get_relationships(old.id)
        assert any(
            r.relation_type == EvidenceRelation.SUPERSEDES and str(r.source_id) == str(new.id)
            for r in rels
        )
        store.close()

    def test_supersede_unknown_new_rejected(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        old = store.add(_evidence())
        with pytest.raises(EvidenceRuleError):
            store.supersede(old.id, EvidenceID("ev_nope"))
        assert store.get(old.id).lifecycle == EvidenceLifecycle.ACTIVE
        store.close()


@pytest.mark.parametrize("factory", EVIDENCE_REPOS)
class TestRelationships:
    def test_all_relationship_types(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        base = store.add(_evidence())
        for rel in EvidenceRelation:
            other = store.add(_evidence(raw_data=f"rel-{rel.value}"))
            store.add_relationship(other.id, rel, base.id)
        rels = store.get_relationships(base.id)
        assert {r.relation_type for r in rels} == set(EvidenceRelation)
        store.close()

    def test_related_evidence_bidirectional(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        a = store.add(_evidence(raw_data="a"))
        b = store.add(_evidence(raw_data="b"))
        store.add_relationship(b.id, EvidenceRelation.CORROBORATES, a.id)
        for eid in (a.id, b.id):
            links = store.related_evidence(eid)
            assert len(links) == 1
            assert links[0].relation == EvidenceRelation.CORROBORATES
        assert store.related_evidence(a.id)[0].direction == "incoming"
        assert store.related_evidence(b.id)[0].direction == "outgoing"
        store.close()

    def test_related_evidence_filtered_by_type(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        a = store.add(_evidence(raw_data="a"))
        b = store.add(_evidence(raw_data="b"))
        c = store.add(_evidence(raw_data="c"))
        store.add_relationship(b.id, EvidenceRelation.SUPPORTS, a.id)
        store.add_relationship(c.id, EvidenceRelation.CONTRADICTS, a.id)
        supports = store.related_evidence(a.id, EvidenceRelation.SUPPORTS)
        contradicts = store.related_evidence(a.id, EvidenceRelation.CONTRADICTS)
        assert [x.evidence.id for x in supports] == [b.id]
        assert [x.evidence.id for x in contradicts] == [c.id]
        store.close()

    def test_self_relationship_rejected(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        a = store.add(_evidence())
        with pytest.raises(ValueError):
            store.add_relationship(a.id, EvidenceRelation.RELATED_TO, a.id)
        store.close()

    def test_relationship_to_unknown_evidence_rejected(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        a = store.add(_evidence())
        with pytest.raises(ValueError):
            store.add_relationship(a.id, EvidenceRelation.RELATED_TO, EvidenceID("ev_nope"))
        store.close()

    def test_related_to_query_filter(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        a = store.add(_evidence(raw_data="a"))
        b = store.add(_evidence(raw_data="b"))
        c = store.add(_evidence(raw_data="c"))
        store.add_relationship(b.id, EvidenceRelation.CORROBORATES, a.id)
        store.add_relationship(a.id, EvidenceRelation.SUPPORTS, c.id)
        q = EvidenceQuery(related_to=a.id)
        found = {e.id for e in store.search(q)}
        assert found == {b.id, c.id}
        q_corroborates = EvidenceQuery(related_to=a.id, relation_type=EvidenceRelation.CORROBORATES)
        assert {e.id for e in store.search(q_corroborates)} == {b.id}
        store.close()


@pytest.mark.parametrize("factory", EVIDENCE_REPOS)
class TestConfidence:
    def test_score_mapping_is_deterministic(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        for confidence in Confidence:
            score = confidence.to_score()
            assert 0.0 <= score <= 1.0
            assert score == confidence.to_score()
        assert Confidence.from_score(Confidence.HIGH.to_score()) == Confidence.HIGH
        store.close()

    def test_adjust_confidence_records_history_not_status(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        e = store.add(_evidence(status=EvidenceStatus.INFERRED, confidence=Confidence.LOW))
        store.adjust_confidence(e.id, Confidence.HIGH, reason="corroborated by second scan")
        loaded = store.get(e.id)
        assert loaded.confidence == Confidence.HIGH
        assert loaded.status == EvidenceStatus.INFERRED
        assert len(loaded.confidence_changes) == 1
        change = loaded.confidence_changes[0]
        assert change.previous == Confidence.LOW
        assert change.new == Confidence.HIGH
        assert "corroborated" in change.reason
        store.close()

    def test_confidence_persists_through_restart(self, factory, tmp_path) -> None:
        if isinstance(factory(tmp_path), InMemoryEvidenceRepository):
            pytest.skip("in-memory has no restart")
        db = str(tmp_path / "evidence_restart.db")
        store = EvidenceStore(repository=SQLiteEvidenceRepository(db))
        e = store.add(_evidence(confidence=Confidence.HIGH))
        store.close()
        reopened = EvidenceStore(repository=SQLiteEvidenceRepository(db))
        loaded = reopened.get(e.id)
        assert loaded.confidence == Confidence.HIGH
        reopened.close()


@pytest.mark.parametrize("factory", EVIDENCE_REPOS)
class TestContradiction:
    def test_contradict_keeps_both_active(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        a = store.add(_evidence(raw_data="port 443 open"))
        b = _evidence(raw_data="port 443 closed")
        store.contradict(a.id, b, supersede=False)
        assert store.get(a.id).lifecycle == EvidenceLifecycle.ACTIVE
        assert store.get(b.id).lifecycle == EvidenceLifecycle.ACTIVE
        rels = store.get_relationships(a.id)
        assert any(
            r.relation_type == EvidenceRelation.CONTRADICTS and str(r.source_id) == str(b.id)
            for r in rels
        )
        store.close()

    def test_contradict_supersede_marks_old(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        a = store.add(_evidence(raw_data="port 443 open"))
        b = _evidence(raw_data="port 443 closed")
        store.contradict(a.id, b, supersede=True)
        assert store.get(a.id).lifecycle == EvidenceLifecycle.SUPERSEDED
        assert store.get(b.id).lifecycle == EvidenceLifecycle.ACTIVE
        assert store.count() == 2
        store.close()

    def test_contradiction_retrieval_is_deterministic(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        a = store.add(_evidence(raw_data="a"))
        b = _evidence(raw_data="b")
        store.contradict(a.id, b)
        snap = lambda: [  # noqa: E731
            (str(link.evidence.id), link.direction)
            for link in store.related_evidence(a.id)
        ]
        assert snap() == snap()
        store.close()


@pytest.mark.parametrize("factory", EVIDENCE_REPOS)
class TestMissionSessionScoping:
    def test_session_filtered_retrieval(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        store.add(_evidence(session_id=SID))
        store.add(_evidence(session_id=SessionID("sess_other")))
        results = store.search(EvidenceQuery(session_id=SID))
        assert len(results) == 1
        assert results[0].session_id == SID
        store.close()

    def test_status_lifecycle_source_filters(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        store.add(
            _evidence(status=EvidenceStatus.OBSERVED, source_capability="cap_a", raw_data="one")
        )
        store.add(
            _evidence(status=EvidenceStatus.HYPOTHESIZED, source_capability="cap_a", raw_data="two")
        )
        store.add(
            _evidence(status=EvidenceStatus.OBSERVED, source_capability="cap_b", raw_data="three")
        )
        assert store.repository.count(EvidenceQuery(status=EvidenceStatus.OBSERVED)) == 2
        assert (
            store.repository.count(
                EvidenceQuery(status=EvidenceStatus.OBSERVED, source_capability="cap_a")
            )
            == 1
        )
        assert (
            store.repository.count(EvidenceQuery(lifecycle=EvidenceLifecycle.ACTIVE))
            == 3
        )
        store.close()

    def test_keyword_and_type_filters(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        store.add(
            _evidence(raw_data="nginx responds on 443", evidence_type=EvidenceType.OBSERVATION)
        )
        store.add(_evidence(raw_data="ssh banner", evidence_type=EvidenceType.RESPONSE))
        assert store.repository.count(EvidenceQuery(keyword="nginx")) == 1
        assert store.repository.count(EvidenceQuery(evidence_type=EvidenceType.RESPONSE)) == 1
        store.close()

    def test_mission_isolation_no_contamination(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        store.add(_evidence(mission_id=MID, raw_data="host-a"))
        store.add(_evidence(mission_id=MID_OTHER, raw_data="host-b"))
        assert store.repository.count(EvidenceQuery(mission_id=MID)) == 1
        assert store.repository.count(EvidenceQuery(mission_id=MID_OTHER)) == 1
        store.close()


class TestEvidenceMemoryBridge:
    def test_materialization_preserves_context(self) -> None:
        store = EvidenceStore()
        memory = MemoryManager()
        bridge = EvidenceMemoryBridge(store, memory)
        evidence = store.add(
            _evidence(
                status=EvidenceStatus.OBSERVED,
                confidence=Confidence.HIGH,
                evidence_type=EvidenceType.OBSERVATION,
            )
        )
        record = bridge.materialize_memory(evidence, memory_type=MemoryType.KNOWLEDGE)
        assert record is not None
        assert record.mission_id == MID
        assert record.session_id == SID
        assert record.status == EvidenceStatus.OBSERVED
        assert record.confidence == Confidence.HIGH.to_score()
        assert record.evidence_ids == [evidence.id]
        assert record.provenance.evidence_ids == [str(evidence.id)]
        assert record.provenance.capability_id == "mock_discovery"
        assert record.content["evidence_id"] == str(evidence.id)
        memory.close()

    def test_memory_for_evidence_lookup(self) -> None:
        store = EvidenceStore()
        memory = MemoryManager()
        bridge = EvidenceMemoryBridge(store, memory)
        evidence = store.add(_evidence())
        bridge.materialize_memory(evidence)
        records = bridge.memory_for_evidence(evidence.id)
        assert len(records) == 1
        assert records[0].evidence_ids == [evidence.id]
        memory.close()

    def test_evidence_for_memory_lookup(self) -> None:
        store = EvidenceStore()
        memory = MemoryManager()
        bridge = EvidenceMemoryBridge(store, memory)
        evidence = store.add(_evidence())
        record = bridge.materialize_memory(evidence)
        references = bridge.evidence_for_memory(record)
        assert [e.id for e in references] == [evidence.id]
        assert references[0].status == evidence.status
        memory.close()

    def test_missing_evidence_materializes_none(self) -> None:
        store = EvidenceStore()
        memory = MemoryManager()
        bridge = EvidenceMemoryBridge(store, memory)
        assert bridge.materialize_memory(EvidenceID("ev_nope")) is None
        assert bridge.memory_for_evidence(EvidenceID("ev_nope")) == []
        memory.close()

    def test_missing_memory_evidence_for_returns_empty(self) -> None:
        store = EvidenceStore()
        memory = MemoryManager()
        bridge = EvidenceMemoryBridge(store, memory)
        assert bridge.evidence_for_memory("mem_nope") == []
        memory.close()

    def test_create_evidence_and_memory(self) -> None:
        store = EvidenceStore()
        memory = MemoryManager()
        bridge = EvidenceMemoryBridge(store, memory)
        evidence, record = bridge.create_evidence_and_memory(_evidence())
        assert evidence is not None
        assert record is not None
        assert record.evidence_ids == [evidence.id]
        assert len(bridge.memory_for_evidence(evidence.id)) == 1
        memory.close()


class _FailingMemory(MemoryManager):
    def store(self, record: MemoryRecord) -> str:
        raise RuntimeError("simulated memory failure")


class TestTransactionBoundary:
    def test_memory_failure_leaves_no_partial_state(self) -> None:
        store = EvidenceStore()
        memory = _FailingMemory()
        bridge = EvidenceMemoryBridge(store, memory)
        with pytest.raises(RuntimeError, match="simulated memory failure"):
            bridge.create_evidence_and_memory(_evidence())
        assert memory.count() == 0
        assert store.count() == 1  # evidence is authoritative and stored
        store.close()

    def test_relationship_failure_rolls_back_atomic_unit(self, tmp_path) -> None:
        db = str(tmp_path / "evidence_txn.db")
        store = EvidenceStore(repository=SQLiteEvidenceRepository(db))
        a = store.add(_evidence(raw_data="a"))
        with pytest.raises(ValueError), store.repository.transaction():
            store.repository.store(_evidence(raw_data="midway"))
            store.repository.add_relationship(
                a.id, EvidenceRelation.RELATED_TO, EvidenceID("ev_nope")
            )
        assert store.count() == 1  # the midway evidence was rolled back
        store.close()

    def test_validate_unknown_rolls_back_whole_op(self) -> None:
        store = EvidenceStore(repository=SQLiteEvidenceRepository(":memory:"))
        with pytest.raises(EvidenceRuleError):
            store.add_validation(
                MID, "t", "r", source_capability="cap", validates_id=EvidenceID("ev_nope")
            )
        assert store.count() == 0
        store.close()


class TestRestartPersistence:
    def test_evidence_memory_relationship_survive_restart(self, tmp_path) -> None:
        evidence_db = str(tmp_path / "pev.db")
        memory_db = str(tmp_path / "pmem.db")

        store = EvidenceStore(repository=SQLiteEvidenceRepository(evidence_db))
        memory = MemoryManager(repository=SQLiteMemoryRepository(memory_db))
        bridge = EvidenceMemoryBridge(store, memory)

        evidence = store.add(_evidence())
        corrob = store.add(_evidence(raw_data="corroborating"))
        store.add_relationship(corrob.id, EvidenceRelation.CORROBORATES, evidence.id)
        record = bridge.materialize_memory(evidence)
        assert record is not None
        memory.close()
        store.close()

        reopened_store = EvidenceStore(repository=SQLiteEvidenceRepository(evidence_db))
        reopened_memory = MemoryManager(repository=SQLiteMemoryRepository(memory_db))
        reopened_bridge = EvidenceMemoryBridge(reopened_store, reopened_memory)

        loaded_evidence = reopened_store.get(evidence.id)
        assert loaded_evidence is not None
        assert loaded_evidence.status == evidence.status
        assert loaded_evidence.lifecycle == EvidenceLifecycle.ACTIVE

        relations = reopened_store.get_relationships(evidence.id)
        assert any(r.relation_type == EvidenceRelation.CORROBORATES for r in relations)

        records = reopened_bridge.memory_for_evidence(evidence.id)
        assert len(records) == 1
        assert records[0].evidence_ids == [evidence.id]
        assert records[0].confidence == evidence.confidence.to_score()

        back = reopened_bridge.evidence_for_memory(records[0])
        assert [e.id for e in back] == [evidence.id]
        assert back[0].provenance.capability_id == evidence.provenance.capability_id

        reopened_memory.close()
        reopened_store.close()

    def test_materialized_memory_is_persistent(self, tmp_path) -> None:
        memory_db = str(tmp_path / "mmem.db")
        store = EvidenceStore(repository=SQLiteEvidenceRepository(":memory:"))
        memory = MemoryManager(repository=SQLiteMemoryRepository(memory_db))
        bridge = EvidenceMemoryBridge(store, memory)
        evidence = store.add(_evidence(raw_data="persist me"))
        record = bridge.materialize_memory(evidence, key="host-scan")
        assert record is not None
        memory.close()

        reopened_memory = MemoryManager(repository=SQLiteMemoryRepository(memory_db))
        loaded = reopened_memory.retrieve(record.id)
        assert loaded is not None
        assert loaded.evidence_ids == [evidence.id]
        assert loaded.status == evidence.status
        assert loaded.provenance.evidence_ids == [str(evidence.id)]
        reopened_memory.close()


def test_provenance_full_chain_survives_persist_restart(tmp_path) -> None:
    evidence_db = str(tmp_path / "prov.db")
    memory_db = str(tmp_path / "provmem.db")

    store = EvidenceStore(repository=SQLiteEvidenceRepository(evidence_db))
    memory = MemoryManager(repository=SQLiteMemoryRepository(memory_db))
    bridge = EvidenceMemoryBridge(store, memory)

    evidence = store.add_claim(
        MID,
        "endpoint /users may expose user data",
        session_id=SID,
        source_capability="llm_analysis",
    )
    validation = store.add_validation(
        MID,
        "example.com /users",
        "authorized application analysis confirmed response contains user profile data",
        source_capability="analyze_api",
        validates_id=evidence.id,
    )
    record = bridge.materialize_memory(evidence)
    assert record is not None
    memory.close()
    store.close()

    rstore = EvidenceStore(repository=SQLiteEvidenceRepository(evidence_db))
    rmemory = MemoryManager(repository=SQLiteMemoryRepository(memory_db))
    rbridge = EvidenceMemoryBridge(rstore, rmemory)

    loaded = rstore.get(evidence.id)
    assert loaded is not None
    assert loaded.status == EvidenceStatus.HYPOTHESIZED
    assert loaded.raw_data == "endpoint /users may expose user data"

    val = rstore.get(validation.id)
    assert val is not None
    assert val.status == EvidenceStatus.VALIDATED
    links = rstore.related_evidence(evidence.id, EvidenceRelation.VALIDATES)
    assert any(x.evidence.id == validation.id for x in links)

    records = rbridge.memory_for_evidence(evidence.id)
    assert len(records) == 1
    mem = records[0]
    assert mem.mission_id == MID
    assert mem.session_id == SID
    assert mem.status == EvidenceStatus.HYPOTHESIZED
    assert mem.provenance.capability_id == "llm_analysis"
    assert mem.provenance.evidence_ids == [str(evidence.id)]

    back = rbridge.evidence_for_memory(mem)
    assert any(e.id == evidence.id for e in back)

    rmemory.close()
    rstore.close()


def test_search_does_not_load_everything_for_lookup(tmp_path) -> None:
    """Query stays on the repository; no in-memory materialization of all rows."""
    store = EvidenceStore(repository=SQLiteEvidenceRepository(str(tmp_path / "q.db")))
    for i in range(20):
        store.add(_evidence(raw_data=f"item {i}"))
    results = store.search(EvidenceQuery(keyword="5", limit=5))
    assert len(results) <= 5
    assert store.count() == 20
    store.close()
