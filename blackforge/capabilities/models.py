from __future__ import annotations

from pydantic import BaseModel, Field

from blackforge.core.types import CapabilityID, RiskLevel, TargetType


class CapabilityMeta(BaseModel):
    id: CapabilityID = Field(default_factory=CapabilityID)
    name: str
    description: str = ""
    version: str = "1.0.0"
    risk_level: RiskLevel = RiskLevel.LOW
    prerequisites: list[str] = Field(default_factory=list)
    authorization_required: bool = True
    supported_target_types: list[TargetType] = Field(default_factory=list)
    input_schema: dict = Field(default_factory=dict)
    output_schema: dict = Field(default_factory=dict)
    evidence_types_produced: list[str] = Field(default_factory=list)
