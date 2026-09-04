from blackforge.authorization import AuthorizationBoundary
from blackforge.core.types import MissionID, RiskLevel, TargetType
from blackforge.scope.models import Target, TargetScope


def _make_scope(**kwargs: object) -> TargetScope:
    defaults = {
        "mission_id": "auth_test",
        "allowed_targets": [
            Target(value="example.com", target_type=TargetType.DOMAIN),
        ],
        "allowed_capabilities": ["mock_discovery"],
        "prohibited_capabilities": ["exploitation"],
        "max_risk_level": RiskLevel.MEDIUM,
    }
    defaults.update(kwargs)
    return TargetScope(**defaults)


class TestAuthorizationBoundary:
    def test_authorized_capability_and_target(self) -> None:
        boundary = AuthorizationBoundary(mode="strict")
        scope = _make_scope()
        result = boundary.authorize(
            mission_id=MissionID(),
            scope=scope,
            capability_name="mock_discovery",
            target_value="example.com",
        )
        assert result.value == "authorized"

    def test_denied_target(self) -> None:
        boundary = AuthorizationBoundary(mode="strict")
        scope = _make_scope()
        result = boundary.authorize(
            mission_id=MissionID(),
            scope=scope,
            capability_name="mock_discovery",
            target_value="evil.com",
        )
        assert result.value == "denied"

    def test_denied_capability(self) -> None:
        boundary = AuthorizationBoundary(mode="strict")
        scope = _make_scope()
        result = boundary.authorize(
            mission_id=MissionID(),
            scope=scope,
            capability_name="exploitation",
            target_value="example.com",
        )
        assert result.value == "denied"

    def test_requires_approval_high_risk(self) -> None:
        boundary = AuthorizationBoundary(mode="strict")
        scope = _make_scope()
        result = boundary.authorize(
            mission_id=MissionID(),
            scope=scope,
            capability_name="mock_discovery",
            target_value="example.com",
            risk_level=RiskLevel.CRITICAL,
        )
        assert result.value == "requires_approval"

    def test_disabled_mode(self) -> None:
        boundary = AuthorizationBoundary(mode="disabled")
        scope = _make_scope()
        result = boundary.authorize(
            mission_id=MissionID(),
            scope=scope,
            capability_name="anything",
            target_value="anywhere",
        )
        assert result.value == "authorized"
