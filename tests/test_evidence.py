from blackforge.core.types import (
    Confidence,
    EvidenceID,
    EvidenceStatus,
    EvidenceType,
    MissionID,
    ProvenanceType,
    TaskID,
)
from blackforge.evidence.models import Evidence, Provenance
from blackforge.evidence.store import EvidenceStore


class TestEvidence:
    def test_creation(self) -> None:
        e = Evidence(
            mission_id=MissionID(),
            source_capability="mock_discovery",
            target="example.com",
            evidence_type=EvidenceType.OBSERVATION,
        )
        assert e.id.startswith("ev_")
        assert e.status == EvidenceStatus.OBSERVED
        assert e.confidence == Confidence.MEDIUM

    def test_provenance(self) -> None:
        e = Evidence(
            mission_id=MissionID(),
            source_capability="cap",
            target="t",
            evidence_type=EvidenceType.ARTIFACT,
            provenance=Provenance(
                capability_id="cap",
                task_id=TaskID(),
                provenance_type=ProvenanceType.DIRECT,
            ),
        )
        assert e.provenance.provenance_type == ProvenanceType.DIRECT
        assert e.provenance.task_id is not None


class TestEvidenceStore:
    def test_add_and_get(self) -> None:
        store = EvidenceStore()
        e = Evidence(
            mission_id=MissionID(),
            source_capability="cap",
            target="t",
            evidence_type=EvidenceType.OBSERVATION,
        )
        store.add(e)
        assert store.get(e.id) is not None
        assert store.count() == 1

    def test_get_by_mission(self) -> None:
        store = EvidenceStore()
        mid = MissionID()
        e1 = Evidence(
            mission_id=mid,
            source_capability="c",
            target="t",
            evidence_type=EvidenceType.LOG,
        )
        e2 = Evidence(
            mission_id=mid,
            source_capability="c",
            target="t",
            evidence_type=EvidenceType.RESPONSE,
        )
        e3 = Evidence(
            mission_id=MissionID(),
            source_capability="c",
            target="t",
            evidence_type=EvidenceType.LOG,
        )
        store.add(e1)
        store.add(e2)
        store.add(e3)
        assert store.count(mid) == 2

    def test_get_nonexistent(self) -> None:
        store = EvidenceStore()
        assert store.get(EvidenceID("nonexistent")) is None

    def test_confidence_levels(self) -> None:
        e = Evidence(
            mission_id=MissionID(),
            source_capability="c",
            target="t",
            evidence_type=EvidenceType.OBSERVATION,
            confidence=Confidence.HIGH,
            status=EvidenceStatus.VALIDATED,
        )
        assert e.confidence == Confidence.HIGH
        assert e.status == EvidenceStatus.VALIDATED

    def test_evidence_status_represents_epistemology(self) -> None:
        statuses = [EvidenceStatus.OBSERVED, EvidenceStatus.INFERRED, EvidenceStatus.HYPOTHESIZED, EvidenceStatus.VALIDATED]
        assert len(statuses) == 4
        assert EvidenceStatus.OBSERVED != EvidenceStatus.INFERRED
        assert EvidenceStatus.VALIDATED != EvidenceStatus.HYPOTHESIZED
