from __future__ import annotations

import ipaddress
import re
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

    if ref_type == TargetType.DIRECTORY:
        return _directory_targets_match(query, reference)

    if ref_type == TargetType.IDENTITY:
        return query.strip().lower() == reference.strip().lower()

    if ref_type == TargetType.CLOUD:
        return _cloud_targets_match(query, reference)

    return False


_CLOUD_TARGET_RE = re.compile(r"^[a-z][a-z0-9-]*/[a-z0-9][a-z0-9._-]*$")


def _cloud_targets_match(query: str, reference: str) -> bool:
    """Match a cloud scope reference against a cloud target.

    A CLOUD reference is an umbrella: ``aws`` covers every account under the
    provider, ``aws/aelionix-aws-test`` covers that account and every
    resource sub-path beneath it. The comparison is purely lexical
    (``provider/container`` prefixes) — it decides scope membership without
    touching the data.
    """
    q = query.strip().lower()
    ref = reference.strip().lower()
    if not q or not ref:
        return False
    if "/" in ref:
        prefix = ref.rstrip("/")
        return q == prefix or q.startswith(prefix + "/")
    return q.split("/", 1)[0] == ref


def _directory_short_name(ref: str) -> str:
    """Short NetBIOS-style name for a directory: ``corp.local`` -> ``corp``."""
    if "." not in ref:
        return ref
    head = ref.split(".", 1)[0]
    return head if head else ref


def _directory_targets_match(query: str, reference: str) -> bool:
    """Match any authorized spelling of a directory against a target.

    A DIRECTORY reference is an umbrella: a bare corporate name
    (``AELIONIX-CORP``), a fully qualified domain (``AELIONIX-CORP.LOCAL``),
    UPN identities (``alice@aelionix-corp.local``), down-level identities
    (``AELIONIX-CORP\\alice``), and sub-objects of the domain
    (``srv.aelionix-corp.local``). The comparison is normalization-based and
    never touches the data: it only decides scope membership.
    """
    q = query.strip().lower()
    ref = reference.strip().lower()
    if not q or not ref:
        return False

    if q == ref:
        return True

    short = _directory_short_name(ref)

    # Fully qualified domain form, either orientation (corp <-> corp.local).
    if ref.endswith(".local") and q == ref[: -len(".local")]:
        return True
    if not ref.endswith(".local") and q == f"{ref}.local":
        return True

    # Sub-object of the directory's DNS namespace: name under corp.local
    # or a bare machine identity under the short name.
    if ref.endswith(".local"):
        if q.endswith("." + ref):
            return True
        if q.endswith("." + short):
            return True

    # UPN identities: alice@corp / alice@corp.local.
    if "@" in q:
        _, mail_domain = q.rsplit("@", 1)
        if mail_domain in (ref, f"{short}") or (
            ref.endswith(".local") and mail_domain == ref
        ):
            return True
        if not ref.endswith(".local") and mail_domain == f"{ref}.local":
            return True

    # Down-level identities: CORP\alice / CORP.LOCAL\alice.
    if "\\" in q:
        directory_part = q.split("\\", 1)[0]
        if directory_part in (ref, short):
            return True

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

    if "/" in value and _CLOUD_TARGET_RE.match(value.strip().lower()):
        return TargetType.CLOUD

    if "." in value:
        return TargetType.DOMAIN

    return TargetType.ASSET