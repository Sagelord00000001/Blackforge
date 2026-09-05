from __future__ import annotations

import pytest

from blackforge.core.types import EvidenceID, EvidenceStatus, MemoryID, MissionID, SessionID
from blackforge.memory.base import MemoryLifecycle, MemoryQuery, MemoryRecord, MemoryType
from blackforge.memory.manager import MemoryManager
from blackforge.memory.provenance import MemoryProvenance, MemorySource
from blackforge.memory.repository import (
    InMemoryRepository,
    SQLiteMemoryRepository,
    canonical_json,
    compute_dedup_key,
)


def _record(**overrides) -> MemoryRecord:
    defaults: dict = {
        "memory_type": MemoryType.KNOWLEDGE,
        "key": "k",
        "content": "v",
        "status": EvidenceStatus.OBSERVED,
        "confidence": 0.8,
        "mission_id": MissionID("mission_test01"),
        "session_id": SessionID("sess_test01"),
        "source": MemorySource.TOOL_OUTPUT,
        "lifecycle": MemoryLifecycle.ACTIVE,
        "tags": ["t1", "t2"],
        "metadata": {"origin": "test"},
        "provenance": MemoryProvenance(
            source=MemorySource.CAPABILITY_EXECUTION,
            source_detail="mock_discovery",
            task_id=None,
            output_hash="abc123",
        ),
        "evidence_ids": [EvidenceID("ev_test01")],
        "expires_at": 9999999999.0,
    }
    defaults.update(overrides)
    return MemoryRecord(**defaults)


REPOSITORIES = [
    pytest.param(
        lambda tmp_path: InMemoryRepository(),
        id="in_memory",
    ),
    pytest.param(
        lambda tmp_path: SQLiteMemoryRepository(str(tmp_path / "memory.db")),
        id="sqlite",
    ),
]


@pytest.mark.parametrize("factory", REPOSITORIES)
def test_full_roundtrip_preserves_fields(factory, tmp_path) -> None:
    repo = factory(tmp_path)
    rec = _record()
    rid = repo.store(rec)
    loaded = repo.retrieve(rid)
    assert loaded is not None
    assert loaded.id == rec.id
    assert loaded.memory_type == MemoryType.KNOWLEDGE
    assert loaded.key == "k"
    assert loaded.content == "v"
    assert loaded.status == EvidenceStatus.OBSERVED
    assert loaded.confidence == 0.8
    assert loaded.mission_id == MissionID("mission_test01")
    assert loaded.session_id == SessionID("sess_test01")
    assert loaded.source == MemorySource.TOOL_OUTPUT
    assert loaded.lifecycle == MemoryLifecycle.ACTIVE
    assert loaded.tags == ["t1", "t2"]
    assert loaded.metadata == {"origin": "test"}
    assert loaded.provenance.source == MemorySource.CAPABILITY_EXECUTION
    assert loaded.provenance.output_hash == "abc123"
    assert loaded.evidence_ids == [EvidenceID("ev_test01")]
    assert loaded.version == 1
    assert loaded.supersedes is None
    assert loaded.dedup_key == compute_dedup_key(rec.memory_type, rec.key, rec.content)
    assert loaded.expires_at == 9999999999.0
    repo.close()


@pytest.mark.parametrize("factory", REPOSITORIES)
def test_complex_content_roundtrip(factory, tmp_path) -> None:
    repo = factory(tmp_path)
    complex_content = {"services": [{"name": "web", "port": 443}], "count": 3, "ok": True}
    rid = repo.store(_record(key="complex", content=complex_content))
    loaded = repo.retrieve(rid)
    assert loaded is not None
    assert loaded.content == complex_content
    repo.close()


@pytest.mark.parametrize("factory", REPOSITORIES)
def test_dedup_key_is_deterministic_for_reordered_content(factory, tmp_path) -> None:
    repo = factory(tmp_path)
    a = _record(key="dedup", content={"x": 1, "y": [1, 2]})
    b = _record(key="dedup", content={"y": [1, 2], "x": 1})
    assert compute_dedup_key(a.memory_type, a.key, a.content) == compute_dedup_key(
        b.memory_type, b.key, b.content
    )
    assert canonical_json(a.content) == canonical_json(b.content)
    repo.close()


@pytest.mark.parametrize("factory", REPOSITORIES)
def test_manager_dedup_returns_same_id_and_no_duplicate(factory, tmp_path) -> None:
    manager = MemoryManager(factory(tmp_path))
    first = manager.store(_record(key="dd", content={"a": 1}))
    second = manager.store(_record(key="dd", content={"a": 1}))
    assert first == second
    assert manager.count() == 1
    loaded = manager.retrieve(first)
    assert loaded is not None
    assert loaded.version == 1
    manager.close()


@pytest.mark.parametrize("factory", REPOSITORIES)
def test_manager_versions_logical_key_on_content_change(factory, tmp_path) -> None:
    manager = MemoryManager(factory(tmp_path))
    v1_id = manager.store(_record(key="evolve", content="v1"))
    v2_id = manager.store(_record(key="evolve", content="v2"))

    assert v1_id != v2_id
    old = manager.retrieve(v1_id)
    new = manager.retrieve(v2_id)
    assert old is not None and new is not None
    assert old.lifecycle == MemoryLifecycle.SUPERSEDED
    assert new.version == 2
    assert new.supersedes == MemoryID(str(old.id))

    current = manager.find_by_logical_key(MemoryType.KNOWLEDGE, "evolve")
    assert current is not None
    assert current.id == new.id
    assert current.version == 2

    assert manager.count() == 2
    manager.close()


@pytest.mark.parametrize("factory", REPOSITORIES)
def test_update_is_in_place_without_new_version(factory, tmp_path) -> None:
    manager = MemoryManager(factory(tmp_path))
    rid = manager.store(_record(key="mutable", content="original"))
    updated = manager.update(rid, {"content": "revised", "confidence": 0.9})
    assert updated is not None
    assert updated.id == MemoryID(str(rid))
    assert updated.version == 1
    assert updated.content == "revised"
    assert updated.confidence == 0.9
    assert updated.updated_at is not None
    assert manager.count() == 1
    assert manager.retrieve(rid).content == "revised"
    manager.close()


@pytest.mark.parametrize("factory", REPOSITORIES)
def test_search_filters_by_structured_fields(factory, tmp_path) -> None:
    manager = MemoryManager(factory(tmp_path))
    m1 = _record(
        key="k1",
        memory_type=MemoryType.KNOWLEDGE,
        status=EvidenceStatus.OBSERVED,
        confidence=0.5,
        source=MemorySource.TOOL_OUTPUT,
        mission_id=MissionID("mission_a"),
        session_id=SessionID("sess_a"),
        tags=["alpha"],
    )
    m2 = _record(
        key="k2",
        memory_type=MemoryType.KNOWLEDGE,
        status=EvidenceStatus.VALIDATED,
        confidence=0.9,
        source=MemorySource.LLM_INFERENCE,
        mission_id=MissionID("mission_a"),
        session_id=SessionID("sess_b"),
        tags=["beta"],
    )
    m3 = _record(
        key="k3",
        memory_type=MemoryType.EXPERIENCE,
        status=EvidenceStatus.OBSERVED,
        confidence=0.7,
        source=MemorySource.TOOL_OUTPUT,
        mission_id=MissionID("mission_b"),
        session_id=SessionID("sess_a"),
        tags=["alpha"],
    )
    for m in (m1, m2, m3):
        manager.store(m)

    assert len(manager.search(query=MemoryQuery(memory_type=MemoryType.KNOWLEDGE))) == 2
    assert len(manager.search(query=MemoryQuery(mission_id=MissionID("mission_a")))) == 2
    assert len(manager.search(query=MemoryQuery(session_id=SessionID("sess_a")))) == 2
    assert len(manager.search(query=MemoryQuery(status=EvidenceStatus.VALIDATED))) == 1
    assert len(manager.search(query=MemoryQuery(lifecycle=MemoryLifecycle.SUPERSEDED))) == 0
    assert len(manager.search(query=MemoryQuery(source=MemorySource.LLM_INFERENCE))) == 1
    assert len(manager.search(query=MemoryQuery(confidence_min=0.7))) == 2
    assert len(manager.search(query=MemoryQuery(confidence_max=0.51))) == 1
    assert len(manager.search(query=MemoryQuery(tags=["alpha"]))) == 2
    assert len(manager.search(query=MemoryQuery(tags=["beta"]))) == 1
    assert len(manager.search(query=MemoryQuery(keyword="k2"))) == 1
    assert manager.count(query=MemoryQuery(memory_type=MemoryType.KNOWLEDGE)) == 2

    newest_first = manager.list(limit=10)
    assert newest_first[0].key == "k3"
    page = manager.list(limit=1, offset=0)
    assert len(page) == 1
    assert page[0].key == "k3"
    manager.close()


@pytest.mark.parametrize("factory", REPOSITORIES)
def test_legacy_search_signature_still_works(factory, tmp_path) -> None:
    manager = MemoryManager(factory(tmp_path))
    manager.store(_record(key="alpha", content="needle text", tags=["important"]))
    manager.store(_record(key="beta", content="other", tags=["routine"]))
    assert len(manager.search(query="needle")) == 1
    assert len(manager.search(memory_type=MemoryType.KNOWLEDGE)) == 2
    assert len(manager.search(tags=["important"])) == 1
    assert len(manager.search(query="alpha", limit=1)) == 1
    manager.close()


@pytest.mark.parametrize("factory", REPOSITORIES)
def test_count_and_delete(factory, tmp_path) -> None:
    manager = MemoryManager(factory(tmp_path))
    a = manager.store(_record(key="a"))
    b = manager.store(_record(key="b"))
    assert manager.count() == 2
    assert manager.delete(a) is True
    assert manager.count() == 1
    assert manager.retrieve(b) is not None
    assert manager.delete("mem_nonexistent") is False
    assert manager.health_check() is True
    manager.close()


def test_sqlite_restart_persistence_and_continuous_versioning(tmp_path) -> None:
    db_path = str(tmp_path / "persist.db")

    m1 = MemoryManager(SQLiteMemoryRepository(db_path))
    first = m1.store(_record(key="survivor", content="gen1"))
    m1.close()

    m2 = MemoryManager(SQLiteMemoryRepository(db_path))
    loaded = m2.retrieve(first)
    assert loaded is not None
    assert loaded.content == "gen1"
    assert loaded.mission_id == MissionID("mission_test01")
    assert loaded.provenance.output_hash == "abc123"
    assert loaded.evidence_ids == [EvidenceID("ev_test01")]

    second = m2.store(_record(key="survivor", content="gen2"))
    assert second != first
    after = m2.find_by_logical_key(MemoryType.KNOWLEDGE, "survivor")
    assert after is not None
    assert after.version == 2
    assert m2.retrieve(first).lifecycle == MemoryLifecycle.SUPERSEDED
    m2.close()


def test_sqlite_transaction_rollback_on_failure(tmp_path) -> None:
    repo = SQLiteMemoryRepository(str(tmp_path / "txn.db"))
    rec = _record(key="txn")
    assert repo.count() == 0
    with pytest.raises(RuntimeError), repo.transaction():
        repo.store(rec)
        raise RuntimeError("simulated failure")
    assert repo.count() == 0
    assert repo.retrieve(rec.id) is None
    repo.close()


def test_sqlite_health_check_after_close(tmp_path) -> None:
    repo = SQLiteMemoryRepository(str(tmp_path / "health.db"))
    assert repo.health_check() is True
    repo.close()
    assert repo.health_check() is False


def test_sqlite_store_after_close_raises(tmp_path) -> None:
    import sqlite3

    repo = SQLiteMemoryRepository(str(tmp_path / "closed.db"))
    repo.close()
    with pytest.raises(sqlite3.ProgrammingError):
        repo.store(_record(key="late"))
