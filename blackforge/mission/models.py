from __future__ import annotations

from pydantic import BaseModel, Field

from blackforge.core.types import MissionID, MissionStatus, TimestampedModel


class Mission(BaseModel):
    id: MissionID = Field(default_factory=MissionID)
    name: str
    description: str = ""
    status: MissionStatus = MissionStatus.CREATED
    scope_id: str | None = None
    authorized: bool = False
    metadata: dict = Field(default_factory=dict)
    created_at: float = Field(default_factory=lambda: __import__("time").time())
    updated_at: float | None = None

    def touch(self) -> None:
        self.updated_at = __import__("time").time()

    def transition_to(self, new_status: MissionStatus) -> None:
        if not _valid_transition(self.status, new_status):
            raise ValueError(
                f"Invalid transition: {self.status.value} -> {new_status.value}"
            )
        self.status = new_status
        self.touch()


_VALID_TRANSITIONS: dict[MissionStatus, set[MissionStatus]] = {
    MissionStatus.CREATED: {MissionStatus.READY, MissionStatus.CANCELLED},
    MissionStatus.READY: {MissionStatus.RUNNING, MissionStatus.CANCELLED},
    MissionStatus.RUNNING: {
        MissionStatus.PAUSED,
        MissionStatus.COMPLETED,
        MissionStatus.FAILED,
        MissionStatus.CANCELLED,
    },
    MissionStatus.PAUSED: {MissionStatus.RUNNING, MissionStatus.CANCELLED},
    MissionStatus.COMPLETED: set(),
    MissionStatus.FAILED: set(),
    MissionStatus.CANCELLED: set(),
}


def _valid_transition(current: MissionStatus, target: MissionStatus) -> bool:
    return target in _VALID_TRANSITIONS.get(current, set())
