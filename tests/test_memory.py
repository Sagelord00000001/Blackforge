from blackforge.memory.base import MemoryType
from blackforge.memory.models import InMemoryBackend, SQLiteMemoryBackend
from blackforge.memory.base import MemoryRecord


class TestInMemoryBackend:
    def _backend(self) -> InMemoryBackend:
        return InMemoryBackend()

    def test_store_and_retrieve(self) -> None:
        b = self._backend()
        rec = MemoryRecord(memory_type=MemoryType.KNOWLEDGE, key="test_key", content="test_value")
        rid = b.store(rec)
        retrieved = b.retrieve(rid)
        assert retrieved is not None
        assert retrieved.key == "test_key"
        assert retrieved.content == "test_value"

    def test_update(self) -> None:
        b = self._backend()
        rec = MemoryRecord(memory_type=MemoryType.WORKING, key="k", content="v1")
        rid = b.store(rec)
        updated = b.update(rid, {"content": "v2"})
        assert updated is not None
        assert updated.content == "v2"

    def test_delete(self) -> None:
        b = self._backend()
        rec = MemoryRecord(memory_type=MemoryType.EXPERIENCE, key="k", content="v")
        rid = b.store(rec)
        assert b.delete(rid) is True
        assert b.retrieve(rid) is None

    def test_search(self) -> None:
        b = self._backend()
        b.store(MemoryRecord(memory_type=MemoryType.KNOWLEDGE, key="alpha", content="content_a"))
        b.store(MemoryRecord(memory_type=MemoryType.KNOWLEDGE, key="beta", content="content_b"))
        b.store(MemoryRecord(memory_type=MemoryType.WORKING, key="gamma", content="content_c"))
        results = b.search(query="alpha")
        assert len(results) == 1
        assert results[0].key == "alpha"

    def test_search_by_type(self) -> None:
        b = self._backend()
        b.store(MemoryRecord(memory_type=MemoryType.KNOWLEDGE, key="k1", content="v1"))
        b.store(MemoryRecord(memory_type=MemoryType.WORKING, key="k2", content="v2"))
        results = b.search(memory_type=MemoryType.KNOWLEDGE)
        assert len(results) == 1
        assert results[0].memory_type == MemoryType.KNOWLEDGE

    def test_search_by_tags(self) -> None:
        b = self._backend()
        b.store(MemoryRecord(memory_type=MemoryType.KNOWLEDGE, key="k1", content="v1", tags=["important"]))
        b.store(MemoryRecord(memory_type=MemoryType.KNOWLEDGE, key="k2", content="v2", tags=["routine"]))
        results = b.search(tags=["important"])
        assert len(results) == 1

    def test_delete_nonexistent(self) -> None:
        b = self._backend()
        assert b.delete("nonexistent") is False

    def test_update_nonexistent(self) -> None:
        b = self._backend()
        assert b.update("nonexistent", {"content": "v"}) is None


class TestSQLiteMemoryBackend:
    def _backend(self, tmp_path: object) -> SQLiteMemoryBackend:
        import os
        db_path = os.path.join(str(tmp_path), "test_memory.db")
        return SQLiteMemoryBackend(db_path=db_path)

    def test_store_and_retrieve(self, tmp_path: object) -> None:
        b = self._backend(tmp_path)
        rec = MemoryRecord(memory_type=MemoryType.KNOWLEDGE, key="sk", content="sv")
        rid = b.store(rec)
        retrieved = b.retrieve(rid)
        assert retrieved is not None
        assert retrieved.key == "sk"
        b.close()

    def test_search(self, tmp_path: object) -> None:
        b = self._backend(tmp_path)
        b.store(MemoryRecord(memory_type=MemoryType.KNOWLEDGE, key="findme", content="data"))
        b.store(MemoryRecord(memory_type=MemoryType.WORKING, key="other", content="data"))
        results = b.search(query="findme")
        assert len(results) == 1
        b.close()

    def test_update(self, tmp_path: object) -> None:
        b = self._backend(tmp_path)
        rec = MemoryRecord(memory_type=MemoryType.WORKING, key="k", content="old")
        rid = b.store(rec)
        updated = b.update(rid, {"content": "new"})
        assert updated is not None
        assert updated.content == "new"
        b.close()

    def test_delete(self, tmp_path: object) -> None:
        b = self._backend(tmp_path)
        rec = MemoryRecord(memory_type=MemoryType.EXPERIENCE, key="k", content="v")
        rid = b.store(rec)
        assert b.delete(rid) is True
        assert b.retrieve(rid) is None
        b.close()
