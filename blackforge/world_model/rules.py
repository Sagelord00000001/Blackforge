from __future__ import annotations

from blackforge.core.types import Confidence, EvidenceStatus

_STATUS_RANK: dict[EvidenceStatus, int] = {
    EvidenceStatus.HYPOTHESIZED: 0,
    EvidenceStatus.INFERRED: 1,
    EvidenceStatus.OBSERVED: 2,
    EvidenceStatus.VALIDATED: 3,
}

# Epistemic statuses strong enough to supersede an authoritative entity's
# property set when a conflicting observation arrives.
_AUTHORITATIVE_STATUSES: frozenset[EvidenceStatus] = frozenset(
    {EvidenceStatus.OBSERVED, EvidenceStatus.VALIDATED}
)


def status_rank(status: EvidenceStatus) -> int:
    """Deterministic epistemic floor ordering."""
    return _STATUS_RANK[status]


def highest_status(statuses: list[EvidenceStatus]) -> EvidenceStatus:
    """Highest epistemic status among a set of evidences (no-fake-authority)."""
    if not statuses:
        return EvidenceStatus.HYPOTHESIZED
    ranked = sorted(statuses, key=status_rank)
    return ranked[-1]


def can_supersede(incoming_status: EvidenceStatus) -> bool:
    """Only observed/validated input may supersede an authoritative record."""
    return incoming_status in _AUTHORITATIVE_STATUSES


def status_requires_evidence(status: EvidenceStatus) -> bool:
    """OBSERVED/VALIDATED status claims require supporting evidence."""
    return status in _AUTHORITATIVE_STATUSES


def stronger_confidence(current: Confidence | None, incoming: Confidence) -> Confidence:
    """Corroboration may raise confidence, never lower it."""
    if current is None or incoming.to_score() > current.to_score():
        return incoming
    return current
