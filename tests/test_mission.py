import pytest

from blackforge.core.types import MissionStatus
from blackforge.mission.manager import MissionManager
from blackforge.mission.models import Mission


class TestMission:
    def test_creation(self) -> None:
        m = Mission(name="Test Mission", description="A test")
        assert m.name == "Test Mission"
        assert m.status == MissionStatus.CREATED
        assert m.id.startswith("mission_")

    def test_status_transition_valid(self) -> None:
        m = Mission(name="Test")
        m.transition_to(MissionStatus.READY)
        assert m.status == MissionStatus.READY

    def test_status_transition_to_running(self) -> None:
        m = Mission(name="Test")
        m.transition_to(MissionStatus.READY)
        m.transition_to(MissionStatus.RUNNING)
        assert m.status == MissionStatus.RUNNING

    def test_status_transition_invalid(self) -> None:
        m = Mission(name="Test")
        with pytest.raises(ValueError, match="Invalid transition"):
            m.transition_to(MissionStatus.RUNNING)

    def test_terminal_state_no_transitions(self) -> None:
        m = Mission(name="Test")
        m.transition_to(MissionStatus.READY)
        m.transition_to(MissionStatus.CANCELLED)
        with pytest.raises(ValueError, match="Invalid transition"):
            m.transition_to(MissionStatus.CREATED)

    def test_full_lifecycle(self) -> None:
        m = Mission(name="Lifecycle")
        m.transition_to(MissionStatus.READY)
        m.transition_to(MissionStatus.RUNNING)
        m.transition_to(MissionStatus.COMPLETED)
        assert m.status == MissionStatus.COMPLETED

    def test_pause_resume(self) -> None:
        m = Mission(name="Pause Test")
        m.transition_to(MissionStatus.READY)
        m.transition_to(MissionStatus.RUNNING)
        m.transition_to(MissionStatus.PAUSED)
        m.transition_to(MissionStatus.RUNNING)
        m.transition_to(MissionStatus.COMPLETED)
        assert m.status == MissionStatus.COMPLETED

    def test_touch_updates_timestamp(self) -> None:
        m = Mission(name="Timestamp")
        assert m.updated_at is None
        m.touch()
        assert m.updated_at is not None


class TestMissionManager:
    def test_create(self) -> None:
        mgr = MissionManager()
        m = mgr.create("Test Mission")
        assert m.name == "Test Mission"
        assert m.id in [x.id for x in mgr.list_missions()]

    def test_get(self) -> None:
        mgr = MissionManager()
        m = mgr.create("Get Test")
        retrieved = mgr.get(m.id)
        assert retrieved.name == "Get Test"

    def test_get_not_found(self) -> None:
        mgr = MissionManager()
        with pytest.raises(Exception):
            mgr.get("nonexistent_id")

    def test_list_missions(self) -> None:
        mgr = MissionManager()
        mgr.create("M1")
        mgr.create("M2")
        assert len(mgr.list_missions()) == 2

    def test_transition(self) -> None:
        mgr = MissionManager()
        m = mgr.create("Transition Test")
        mgr.transition(m.id, MissionStatus.READY)
        assert mgr.get(m.id).status == MissionStatus.READY
