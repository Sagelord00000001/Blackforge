from __future__ import annotations

from blackforge.core.logging import get_logger
from blackforge.core.types import AuthorizationDecision, MissionID, RiskLevel
from blackforge.scope.models import TargetScope

log = get_logger("authorization")


class AuthorizationBoundary:
    def __init__(self, mode: str = "strict") -> None:
        self.mode = mode

    def authorize(
        self,
        mission_id: MissionID,
        scope: TargetScope,
        capability_name: str,
        target_value: str,
        risk_level: RiskLevel = RiskLevel.LOW,
    ) -> AuthorizationDecision:
        if self.mode == "disabled":
            log.warning(
                "authorization_disabled",
                mission_id=str(mission_id),
                capability=capability_name,
            )
            return AuthorizationDecision.AUTHORIZED

        if not scope.is_target_allowed(target_value):
            log.warning(
                "authorization_denied_target_scope",
                mission_id=str(mission_id),
                target=target_value,
            )
            return AuthorizationDecision.DENIED

        if not scope.is_capability_allowed(capability_name):
            log.warning(
                "authorization_denied_capability_scope",
                mission_id=str(mission_id),
                capability=capability_name,
            )
            return AuthorizationDecision.DENIED

        if risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            if scope.max_risk_level.value not in ("high", "critical"):
                log.info(
                    "authorization_requires_approval",
                    mission_id=str(mission_id),
                    capability=capability_name,
                    risk_level=risk_level.value,
                )
                return AuthorizationDecision.REQUIRES_APPROVAL

        log.info(
            "authorization_granted",
            mission_id=str(mission_id),
            capability=capability_name,
            target=target_value,
        )
        return AuthorizationDecision.AUTHORIZED
