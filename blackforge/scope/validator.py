from __future__ import annotations

from blackforge.core.logging import get_logger
from blackforge.core.types import AuthorizationDecision
from blackforge.scope.models import TargetScope

log = get_logger("scope.validator")


class ScopeValidator:
    def __init__(self, require_scope: bool = True) -> None:
        self.require_scope = require_scope

    def validate_target(self, scope: TargetScope, target_value: str) -> AuthorizationDecision:
        if not self.require_scope:
            return AuthorizationDecision.AUTHORIZED

        if scope.is_target_allowed(target_value):
            log.debug("target_authorized", target=target_value)
            return AuthorizationDecision.AUTHORIZED

        log.warning("target_denied", target=target_value, mission_id=scope.mission_id)
        return AuthorizationDecision.DENIED

    def validate_capability(self, scope: TargetScope, capability_name: str) -> AuthorizationDecision:
        if not self.require_scope:
            return AuthorizationDecision.AUTHORIZED

        if scope.is_capability_allowed(capability_name):
            log.debug("capability_authorized", capability=capability_name)
            return AuthorizationDecision.AUTHORIZED

        log.warning(
            "capability_denied",
            capability=capability_name,
            mission_id=scope.mission_id,
        )
        return AuthorizationDecision.DENIED
