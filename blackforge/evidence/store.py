from __future__ import annotations

from blackforge.core.logging import get_logger
from blackforge.core.types import EvidenceID, MissionID
from blackforge.evidence.models import Evidence

log = get_logger("evidence.store")


class EvidenceStore:
    def __init__(self) -> None:
        self._evidence: dict[EvidenceID, Evidence] = {}
        self._by_mission: dict[MissionID, list[EvidenceID]] = {}

    def add(self, evidence: Evidence) -> Evidence:
        self._evidence[evidence.id] = evidence
        self._by_mission.setdefault(evidence.mission_id, []).append(evidence.id)
        log.info(
            "evidence_stored",
            evidence_id=str(evidence.id),
            mission_id=str(evidence.mission_id),
            type=evidence.evidence_type.value,
            status=evidence.status.value,
        )
        return evidence

    def get(self, evidence_id: EvidenceID) -> Evidence | None:
        return self._evidence.get(evidence_id)

    def get_by_mission(self, mission_id: MissionID) -> list[Evidence]:
        ids = self._by_mission.get(mission_id, [])
        return [self._evidence[eid] for eid in ids if eid in self._evidence]

    def count(self, mission_id: MissionID | None = None) -> int:
        if mission_id:
            return len(self._by_mission.get(mission_id, []))
        return len(self._evidence)
