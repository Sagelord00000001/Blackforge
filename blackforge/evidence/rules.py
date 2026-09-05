from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from blackforge.core.types import EvidenceStatus, EvidenceType, MissionID
from blackforge.memory.repository import canonical_json

if TYPE_CHECKING:
    from blackforge.evidence.models import Evidence


def compute_evidence_dedup_key(
    mission_id: MissionID,
    target: str,
    source_capability: str,
    evidence_type: EvidenceType,
    content: object,
) -> str:
    """Deterministic stable identity for an evidence record.

    Two evidence records are *identical* only when these normalized fields
    match: mission, target, producing capability, evidence type, and the
    canonical serialization of the payload (``raw_data`` + ``reference``).
    Timestamps are intentionally excluded so re-scans of the same payload do
    not create duplicates, and distinct observations (different payloads) are
    never merged merely because their text is similar.

    Canonical JSON ordering means structurally equal payloads dedup equally.
    """
    payload = (
        f"{str(mission_id)}|{target}|{source_capability}|{evidence_type.value}"
        f"|{canonical_json(content)}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def evidence_dedup_content(evidence: Evidence) -> object:
    """The normalized payload used for evidence dedup identity."""
    return {"raw_data": evidence.raw_data, "reference": evidence.reference}


_STATUS_TRANSITION_TABLE: dict[EvidenceStatus, set[EvidenceStatus]] = {
    # OBSERVED -> INFERRED  : direct observation gains an interpretation
    # OBSERVED -> HYPOTHESIZED : an observation reframed as a testable claim
    EvidenceStatus.OBSERVED: {
        EvidenceStatus.INFERRED,
        EvidenceStatus.HYPOTHESIZED,
        EvidenceStatus.VALIDATED,
    },
    # INFERRED -> HYPOTHESIZED : a derived conclusion distilled into a hypothesis
    EvidenceStatus.INFERRED: {EvidenceStatus.HYPOTHESIZED, EvidenceStatus.VALIDATED},
    # HYPOTHESIZED -> VALIDATED : an authorized validation workflow may confirm it
    EvidenceStatus.HYPOTHESIZED: {EvidenceStatus.VALIDATED},
    EvidenceStatus.VALIDATED: set(),
}

# Statuses that may move to VALIDATED in a single step. Everything else
# reaching VALIDATED must pass through an intermediate state first.
_VALIDATED_SOURCES = {
    EvidenceStatus.OBSERVED,
    EvidenceStatus.INFERRED,
    EvidenceStatus.HYPOTHESIZED,
}


def can_transition_status(
    current: EvidenceStatus,
    target: EvidenceStatus,
    *,
    via_validation: bool = False,
) -> bool:
    """Deterministic epistemic-status transition rule.

    VALIDATED is the only status that requires a validation workflow. Without
    ``via_validation=True`` every path into VALIDATED is rejected, regardless
    of how high confidence is. Downgrades (e.g. INFERRED -> OBSERVED,
    VALIDATED -> HYPOTHESIZED) are rejected: contradicted or disproven claims
    are handled through lifecycle (SUPERSEDED/INVALIDATED), not status
    rewrites, so the historical epistemic record is preserved.
    """
    if current == target:
        return True
    if target == EvidenceStatus.VALIDATED:
        return via_validation and current in _VALIDATED_SOURCES
    return target in _STATUS_TRANSITION_TABLE.get(current, set())
