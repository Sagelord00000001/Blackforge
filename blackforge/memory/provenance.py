from __future__ import annotations

import time
from enum import Enum

from pydantic import BaseModel, Field

from blackforge.core.types import ProvenanceType, TaskID


class MemorySource(str, Enum):
    OBSERVATION = "observation"
    CAPABILITY_EXECUTION = "capability_execution"
    TOOL_OUTPUT = "tool_output"
    USER_PROVIDED = "user_provided"
    SOURCE_CODE = "source_code"
    DOCUMENT = "document"
    LLM_INFERENCE = "llm_inference"
    VALIDATED_EXPERIMENT = "validated_experiment"
    PREVIOUS_MEMORY = "previous_memory"


class MemoryProvenance(BaseModel):
    """Where a memory record's information originated.

    Provenance answers: what produced this, through which activity, and
    which evidence supports it. It is intentionally distinct from the
    ``EvidenceStatus`` field, which describes the epistemic status
    (observed/inferred/hypothesized/validated) of the content.
    """

    source: MemorySource = MemorySource.OBSERVATION
    source_detail: str | None = None
    provenance_type: ProvenanceType = ProvenanceType.DIRECT
    task_id: TaskID | None = None
    capability_id: str | None = None
    input_hash: str | None = None
    output_hash: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    recorded_at: float = Field(default_factory=time.time)
