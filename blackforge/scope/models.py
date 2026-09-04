from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from blackforge.core.types import RiskLevel, TargetType


class Target(BaseModel):
    value: str
    target_type: TargetType
    label: str | None = None


class ExecutionLimits(BaseModel):
    max_requests_per_second: int = 10
    max_concurrent_connections: int = 5
    max_total_requests: int = 1_000
    timeout_seconds: int = 300


class TargetScope(BaseModel):
    mission_id: str
    allowed_targets: list[Target] = Field(default_factory=list)
    excluded_targets: list[Target] = Field(default_factory=list)
    allowed_capabilities: list[str] = Field(default_factory=list)
    prohibited_capabilities: list[str] = Field(default_factory=list)
    max_risk_level: RiskLevel = RiskLevel.MEDIUM
    execution_limits: ExecutionLimits = Field(default_factory=ExecutionLimits)

    def is_target_allowed(self, target_value: str) -> bool:
        for excluded in self.excluded_targets:
            if _targets_match(target_value, excluded.value, excluded.target_type):
                return False

        for allowed in self.allowed_targets:
            if _targets_match(target_value, allowed.value, allowed.target_type):
                return True

        return False

    def is_capability_allowed(self, capability_name: str) -> bool:
        if capability_name in self.prohibited_capabilities:
            return False
        if self.allowed_capabilities and capability_name not in self.allowed_capabilities:
            return False
        return True


def _targets_match(query: str, reference: str, ref_type: TargetType) -> bool:
    if query == reference:
        return True

    if ref_type == TargetType.CIDR:
        try:
            network = ipaddress.ip_network(reference, strict=False)
            addr = ipaddress.ip_address(query)
            return addr in network
        except ValueError:
            return False

    if ref_type == TargetType.DOMAIN:
        return query.endswith("." + reference) or query == reference

    if ref_type == TargetType.URL:
        return query.startswith(reference)

    return False


def detect_target_type(value: str) -> TargetType:
    if "/" in value and "." in value:
        try:
            ipaddress.ip_network(value, strict=False)
            return TargetType.CIDR
        except ValueError:
            pass

    try:
        ipaddress.ip_address(value)
        return TargetType.IP
    except ValueError:
        pass

    if value.startswith("http://") or value.startswith("https://"):
        return TargetType.URL

    if "." in value:
        return TargetType.DOMAIN

    return TargetType.ASSET
