from __future__ import annotations

from blackforge.capabilities.interface import Capability, CapabilityResult
from blackforge.capabilities.models import CapabilityMeta
from blackforge.core.types import CapabilityID, RiskLevel, TargetType


class MockDiscoveryCapability(Capability):
    """Safe mock capability for testing the architecture."""

    def meta(self) -> CapabilityMeta:
        return CapabilityMeta(
            id=CapabilityID("mock_discovery"),
            name="mock_discovery",
            description="Safe mock capability for testing. Produces deterministic output.",
            version="1.0.0",
            risk_level=RiskLevel.INFORMATIONAL,
            authorization_required=False,
            supported_target_types=[
                TargetType.DOMAIN,
                TargetType.IP,
                TargetType.URL,
            ],
            input_schema={"target": {"type": "string"}},
            output_schema={"result": {"type": "string"}},
            evidence_types_produced=["observation"],
        )

    def execute(self, target: str, params: dict | None = None) -> CapabilityResult:
        return CapabilityResult(
            success=True,
            output={"result": f"mock_scan_complete for {target}"},
            metadata={"mock": True},
        )
