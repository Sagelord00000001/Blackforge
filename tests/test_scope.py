from blackforge.core.types import AuthorizationDecision, RiskLevel, TargetType
from blackforge.scope.models import Target, TargetScope, detect_target_type
from blackforge.scope.validator import ScopeValidator


def _make_scope(**kwargs: object) -> TargetScope:
    defaults = {
        "mission_id": "test_mission",
        "allowed_targets": [
            Target(value="example.com", target_type=TargetType.DOMAIN),
            Target(value="192.168.1.0/24", target_type=TargetType.CIDR),
            Target(value="https://app.example.com", target_type=TargetType.URL),
        ],
        "excluded_targets": [
            Target(value="admin.example.com", target_type=TargetType.DOMAIN),
        ],
        "allowed_capabilities": ["mock_discovery"],
        "prohibited_capabilities": ["exploitation"],
    }
    defaults.update(kwargs)
    return TargetScope(**defaults)


class TestTargetScope:
    def test_allowed_domain(self) -> None:
        scope = _make_scope()
        assert scope.is_target_allowed("example.com") is True

    def test_subdomain_allowed(self) -> None:
        scope = _make_scope()
        assert scope.is_target_allowed("sub.example.com") is True

    def test_excluded_target(self) -> None:
        scope = _make_scope()
        assert scope.is_target_allowed("admin.example.com") is False

    def test_out_of_scope(self) -> None:
        scope = _make_scope()
        assert scope.is_target_allowed("evil.com") is False

    def test_cidr_match(self) -> None:
        scope = _make_scope()
        assert scope.is_target_allowed("192.168.1.50") is True

    def test_cidr_no_match(self) -> None:
        scope = _make_scope()
        assert scope.is_target_allowed("10.0.0.1") is False

    def test_url_match(self) -> None:
        scope = _make_scope()
        assert scope.is_target_allowed("https://app.example.com/features") is True

    def test_capability_allowed(self) -> None:
        scope = _make_scope()
        assert scope.is_capability_allowed("mock_discovery") is True

    def test_capability_prohibited(self) -> None:
        scope = _make_scope()
        assert scope.is_capability_allowed("exploitation") is False

    def test_capability_not_in_allowlist(self) -> None:
        scope = _make_scope()
        assert scope.is_capability_allowed("unknown_cap") is False

    def test_empty_allowlist_allows_all(self) -> None:
        scope = TargetScope(mission_id="test", allowed_capabilities=[])
        assert scope.is_capability_allowed("anything") is True


class TestDetectTargetType:
    def test_ip(self) -> None:
        assert detect_target_type("192.168.1.1") == TargetType.IP

    def test_cidr(self) -> None:
        assert detect_target_type("192.168.1.0/24") == TargetType.CIDR

    def test_url(self) -> None:
        assert detect_target_type("https://example.com") == TargetType.URL

    def test_domain(self) -> None:
        assert detect_target_type("example.com") == TargetType.DOMAIN

    def test_asset(self) -> None:
        assert detect_target_type("some-asset") == TargetType.ASSET


class TestScopeValidator:
    def test_validate_target_allowed(self) -> None:
        validator = ScopeValidator(require_scope=True)
        scope = _make_scope()
        assert validator.validate_target(scope, "example.com") == AuthorizationDecision.AUTHORIZED

    def test_validate_target_denied(self) -> None:
        validator = ScopeValidator(require_scope=True)
        scope = _make_scope()
        assert validator.validate_target(scope, "evil.com") == AuthorizationDecision.DENIED

    def test_validate_capability_allowed(self) -> None:
        validator = ScopeValidator(require_scope=True)
        scope = _make_scope()
        assert validator.validate_capability(scope, "mock_discovery") == AuthorizationDecision.AUTHORIZED

    def test_validate_capability_denied(self) -> None:
        validator = ScopeValidator(require_scope=True)
        scope = _make_scope()
        assert validator.validate_capability(scope, "exploitation") == AuthorizationDecision.DENIED

    def test_no_scope_required(self) -> None:
        validator = ScopeValidator(require_scope=False)
        scope = _make_scope()
        assert validator.validate_target(scope, "anything") == AuthorizationDecision.AUTHORIZED
