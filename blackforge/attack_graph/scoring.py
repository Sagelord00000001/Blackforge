"""Explainable assessment prioritization over derived graph paths.

The planner never produces exploitability claims. ``assess`` returns a
deterministic, explainable priority score intended *only* for ordering
authorized, evidence-gathering assessments. Every factor is attributable.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AssessmentFactors:
    """Normalized (0..1) factors that feed the priority score."""

    path_depth: float
    blocked: float
    saturation: float
    focus_alignment: float
    contradiction_pressure: float
    corroboration: float
    derived_confidence: float


@dataclass(frozen=True)
class AssessmentScore:
    """A score plus its explanation; never a probability."""

    value: float
    level: str
    factors: AssessmentFactors
    explanation: list[str] = field(default_factory=list)

    @property
    def ordered_levels(self) -> list[str]:
        return _LEVELS

    def explain(self) -> str:
        if not self.explanation:
            return self.level
        return "; ".join(self.explanation)


_EXPOSURE = 0.35
_MAX_EXPOSED = 80
_LEVELS = ["LOW", "MODERATE", "ELEVATED", "HIGH"]


def assess(
    path_depth: int,
    is_blocked: bool,
    near_saturation: bool,
    exposed_ratio: float,
    focus_matches: bool,
    has_contradiction: bool,
    corroboration: int,
    derived_confidence: float,
) -> AssessmentScore:
    """Produce an explainable priority score and level from normalized inputs.

    Parity factors are converted to floats; every caller supplies them so the
    output is fully explainable.
    """
    if near_saturation:
        exposure_factor = 0.0
    elif exposed_ratio >= 1.0:
        exposure_factor = 1.0
    elif exposed_ratio > 0.0:
        exposure_factor = exposed_ratio
    else:
        exposure_factor = 0.0

    depth_factor = min(float(path_depth), 3.0) / 3.0
    saturation_credit = 0.0 if near_saturation else 0.0
    focus_credit = 1.0 if focus_matches else 0.0
    contradiction_credit = 1.0 if has_contradiction else 0.0
    corroboration_credit = min(float(corroboration), 2.0) / 2.0

    score = (
        0.15 * depth_factor
        + 0.35 * exposure_factor
        + 0.15 * saturation_credit
        + 0.15 * focus_credit
        + 0.05 * contradiction_credit
        + 0.05 * corroboration_credit
        + 0.10 * _clamp01(derived_confidence)
    )

    normalized = _warn_and_renormalize(score)
    level = _level_for(normalized)
    return AssessmentScore(
        value=normalized,
        level=level,
        factors=AssessmentFactors(
            path_depth=depth_factor,
            blocked=1.0 if is_blocked else 0.0,
            saturation=saturation_credit,
            focus_alignment=focus_credit,
            contradiction_pressure=contradiction_credit,
            corroboration=corroboration_credit,
            derived_confidence=_clamp01(derived_confidence),
        ),
        explanation=_explanation(level, normalized, exposure_factor, near_saturation, is_blocked),
    )


def _warn_and_renormalize(score: float) -> float:
    return _clamp01(score)


def _clamp01(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value


def _level_for(score: float) -> str:
    if score < 0.25:
        return _LEVELS[0]
    if score < 0.5:
        return _LEVELS[1]
    if score < 0.75:
        return _LEVELS[2]
    return _LEVELS[3]


def _explanation(
    level: str, score: float, exposure: float, near_saturation: bool, is_blocked: bool
) -> list[str]:
    parts = [f"priority {level} ({score:.2f})"]
    if is_blocked:
        parts.append("path is blocked; derived edges only")
    parts.append(f"exposure contribution {exposure:.2f}")
    if near_saturation:
        parts.append("IDE hours near saturation; downstream verification capped")
    return parts
