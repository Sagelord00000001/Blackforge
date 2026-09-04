from __future__ import annotations

from blackforge.core.errors import MissionError
from blackforge.core.logging import get_logger
from blackforge.core.types import MissionID, MissionStatus
from blackforge.mission.models import Mission

log = get_logger("mission.manager")


class MissionManager:
    def __init__(self) -> None:
        self._missions: dict[MissionID, Mission] = {}

    def create(self, name: str, description: str = "", **kwargs: object) -> Mission:
        mission = Mission(name=name, description=description, **kwargs)
        self._missions[mission.id] = mission
        log.info("mission_created", mission_id=str(mission.id), name=name)
        return mission

    def get(self, mission_id: MissionID) -> Mission:
        mission = self._missions.get(mission_id)
        if not mission:
            raise MissionError(f"Mission not found: {mission_id}")
        return mission

    def list_missions(self) -> list[Mission]:
        return list(self._missions.values())

    def transition(self, mission_id: MissionID, target_status: MissionStatus) -> Mission:
        mission = self.get(mission_id)
        try:
            mission.transition_to(target_status)
        except ValueError as exc:
            raise MissionError(str(exc)) from exc
        log.info(
            "mission_transition",
            mission_id=str(mission_id),
            status=mission.status.value,
        )
        return mission
