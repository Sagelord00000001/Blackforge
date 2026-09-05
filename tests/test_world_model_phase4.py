from __future__ import annotations

import pytest
from pydantic import ValidationError

from blackforge.core.errors import WorldRuleError
from blackforge.core.types import (
    Confidence,
    EvidenceID,
    EvidenceStatus,
    MissionID,
    SessionID,
)
from blackforge.world_model.canonical import (
    build_entity_canonical_key,
    compute_entity_dedup_key,
    normalize_entity_name,
)
from blackforge.world_model.materializer import EntityFact, RelationshipFact, WorldMaterializer
from blackforge.world_model.models import (
    AssertionSpec,
    EntitySpec,
    EntityType,
    EvidenceLinkRef,
    RelationshipSpec,
    RelationshipType,
    WorldLifecycle,
    WorldMutation,
)
from blackforge.world_model.query import RelationshipQuery, WorldQuery
from blackforge.world_model.repository import (
    InMemoryWorldRepository,
    SQLiteWorldRepository,
)
from blackforge.world_model.store import WorldModelStore

MID = MissionID("mission_phase4")
SID = SessionID("sess_phase4")
MID_OTHER = MissionID("mission_other")
SID_OTHER = SessionID("sess_other")


def _entity(**overrides) -> EntitySpec:
    defaults: dict = {
        "mission_id": MID,
        "session_id": SID,
        "entity_type": EntityType.ENDPOINT,
        "name": "https://web.example.com",
        "properties": {"port": 443},
        "epistemic_status": EvidenceStatus.OBSERVED,
        "confidence": Confidence.HIGH,
        "evidence": [EvidenceLinkRef(evidence_id=EvidenceID("ev_e1"))],
    }
    defaults.update(overrides)
    return EntitySpec(**defaults)


def _relationship(**overrides) -> RelationshipSpec:
    defaults: dict = {
        "mission_id": MID,
        "session_id": SID,
        "relationship_type": RelationshipType.HOSTS,
        "confidence": Confidence.MEDIUM,
        "evidence": [EvidenceLinkRef(evidence_id=EvidenceID("ev_r"))],
    }
    defaults.update(overrides)
    return RelationshipSpec(**defaults)


WORLD_REPOS = [
    pytest.param(
        lambda tmp_path: InMemoryWorldRepository(),
        id="in_memory",
    ),
    pytest.param(
        lambda tmp_path: SQLiteWorldRepository(str(tmp_path / "world_model.db")),
        id="sqlite",
    ),
]


def _store_with(factory, tmp_path) -> WorldModelStore:
    return WorldModelStore(repository=factory(tmp_path))


def _endpoint_pair(store, mission_id: MissionID = MID, session_id: SessionID = SID):
    a = store.add_entity(
        _entity(
            mission_id=mission_id,
            session_id=session_id,
            name="https://app-a.example.com",
            entity_type=EntityType.ENDPOINT,
            properties={"port": 443},
        )
    )
    b = store.add_entity(
        _entity(
            mission_id=mission_id,
            session_id=session_id,
            name="https://app-b.example.com",
            entity_type=EntityType.ENDPOINT,
            properties={"port": 443},
        )
    )
    return a.entity, b.entity


@pytest.mark.parametrize("factory", WORLD_REPOS)
class TestEntityCrudAndIdentity:
    def test_create_retrieve_count(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        result = store.add_entity(_entity())
        assert result.action == WorldMutation.CREATED
        assert str(result.entity.id).startswith("went_")
        assert store.get_entity(str(result.entity.id)) is not None
        assert store.count_entities(MID) == 1
        assert store.count_entities(MID_OTHER) == 0
        store.close()

    def test_missing_evidence_for_authoritative_status(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        with pytest.raises(WorldRuleError):
            store.add_entity(
                _entity(epistemic_status=EvidenceStatus.OBSERVED, evidence=[])
            )
        with pytest.raises(WorldRuleError):
            store.add_entity(
                _entity(epistemic_status=EvidenceStatus.VALIDATED, evidence=[])
            )
        store.close()

    def test_hypothesized_without_evidence_is_allowed(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        result = store.add_entity(
            _entity(
                epistemic_status=EvidenceStatus.HYPOTHESIZED,
                evidence=[],
                confidence=Confidence.LOW,
            )
        )
        assert result.action == WorldMutation.CREATED
        store.close()

    def test_same_identity_corroborates(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        first = store.add_entity(_entity())
        second = store.add_entity(_entity())
        assert second.action == WorldMutation.CORROBORATED
        assert second.entity.id == first.entity.id
        assert second.entity.version == 1
        assert store.count_entities(MID) == 1
        store.close()

    def test_canonical_key_is_deterministic(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        store.add_entity(
            _entity(name="HTTPS://WEB.EXAMPLE.COM", properties={"port": 443})
        )
        normalized = normalize_entity_name(EntityType.ENDPOINT, "https://web.example.com")
        key = build_entity_canonical_key(EntityType.ENDPOINT, normalized)
        found = store.find_entity(MID, EntityType.ENDPOINT, "https://web.example.com")
        assert found is not None
        assert found.canonical_key == key
        assert found.dedup_key == compute_entity_dedup_key(MID, key)
        store.close()

    def test_similar_but_distinct_names_never_merge(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        store.add_entity(_entity(name="web.example.com", entity_type=EntityType.SERVICE))
        store.add_entity(
            _entity(name="web-1.example.com", entity_type=EntityType.SERVICE)
        )
        assert store.count_entities(MID) == 2
        store.close()

    def test_namespace_scopes_identity(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        store.add_entity(_entity(name="app", entity_type=EntityType.SERVICE, namespace="prod"))
        store.add_entity(_entity(name="app", entity_type=EntityType.SERVICE, namespace="dev"))
        assert store.count_entities(MID) == 2
        store.close()

    def test_invalid_network_name_raises(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        with pytest.raises(WorldRuleError):
            store.add_entity(
                _entity(
                    entity_type=EntityType.NETWORK,
                    name="not-an-ip",
                    properties={"cidr": "10.0.0.0/24"},
                )
            )
        store.close()


@pytest.mark.parametrize("factory", WORLD_REPOS)
class TestRelationshipCrudAndDirection:
    def test_create_and_neighborhood(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        a, b = _endpoint_pair(store)
        result = store.add_relationship(
            _relationship(source_entity_id=a.id, target_entity_id=b.id)
        )
        assert result.action == WorldMutation.CREATED
        assert str(result.relationship.id).startswith("wrel_")
        out = store.neighborhood(str(a.id), direction="out")
        assert out is not None
        assert [str(e.id) for e in out.entities] == [str(b.id)]
        assert len(out.relationships) == 1
        incoming = store.neighborhood(str(b.id), direction="in")
        assert incoming is not None
        assert [str(e.id) for e in incoming.entities] == [str(a.id)]
        store.close()

    def test_directed_edges_keep_direction(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        a, b = _endpoint_pair(store)
        fwd = store.add_relationship(
            _relationship(
                relationship_type=RelationshipType.TRUSTS,
                source_entity_id=a.id,
                target_entity_id=b.id,
            )
        )
        rev = store.add_relationship(
            _relationship(
                relationship_type=RelationshipType.TRUSTS,
                source_entity_id=b.id,
                target_entity_id=a.id,
            )
        )
        assert fwd.relationship.id != rev.relationship.id
        assert store.count_entities(MID) == 2
        assert len(
            store.list_relationships(
                RelationshipQuery(mission_id=MID, relationship_type=RelationshipType.TRUSTS)
            )
        ) == 2
        store.close()

    def test_symmetric_edges_dedup_order_insensitively(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        a, b = _endpoint_pair(store)
        ab = store.add_relationship(
            _relationship(
                relationship_type=RelationshipType.CONNECTS_TO,
                source_entity_id=a.id,
                target_entity_id=b.id,
            )
        )
        ba = store.add_relationship(
            _relationship(
                relationship_type=RelationshipType.CONNECTS_TO,
                source_entity_id=b.id,
                target_entity_id=a.id,
            )
        )
        assert ba.action == WorldMutation.CORROBORATED
        assert ba.relationship.id == ab.relationship.id
        store.close()

    def test_self_loop_rejected(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        a, _ = _endpoint_pair(store)
        with pytest.raises(WorldRuleError):
            store.add_relationship(
                _relationship(
                    relationship_type=RelationshipType.TRUSTS,
                    source_entity_id=a.id,
                    target_entity_id=a.id,
                )
            )
        store.close()

    def test_nonexistent_endpoint_rejected(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        a, _ = _endpoint_pair(store)
        ghost = "went_0000000000000000"
        with pytest.raises(WorldRuleError):
            store.add_relationship(
                _relationship(source_entity_id=a.id, target_entity_id=ghost)
            )
        store.close()

    def test_cross_mission_endpoint_rejected(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        a, _ = _endpoint_pair(store)
        other, _ = _endpoint_pair(store, mission_id=MID_OTHER, session_id=SID_OTHER)
        with pytest.raises(WorldRuleError):
            store.add_relationship(
                _relationship(source_entity_id=a.id, target_entity_id=other.id)
            )
        store.close()

    def test_relationship_to_archived_endpoint_rejected(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        a, b = _endpoint_pair(store)
        store.archive_entity(str(b.id))
        with pytest.raises(WorldRuleError):
            store.add_relationship(
                _relationship(source_entity_id=a.id, target_entity_id=b.id)
            )
        store.close()

    def test_corroboration_merges_evidence(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        a, b = _endpoint_pair(store)
        first = store.add_relationship(
            _relationship(
                source_entity_id=a.id,
                target_entity_id=b.id,
                evidence=[EvidenceLinkRef(evidence_id=EvidenceID("ev_r1"))],
            )
        )
        second = store.add_relationship(
            _relationship(
                source_entity_id=a.id,
                target_entity_id=b.id,
                evidence=[EvidenceLinkRef(evidence_id=EvidenceID("ev_r2"))],
            )
        )
        assert second.action == WorldMutation.CORROBORATED
        assert second.relationship.id == first.relationship.id
        assert {
            ref["evidence_id"]
            for ref in store.evidence_for_relationship(str(first.relationship.id))
        } == {"ev_r1", "ev_r2"}
        store.close()

    def test_forbidden_relationship_types_do_not_exist(self, factory, tmp_path) -> None:
        with pytest.raises(ValidationError):
            RelationshipSpec(
                mission_id=MID,
                session_id=SID,
                relationship_type="leads_to",
                source_entity_id="went_1",
                target_entity_id="went_2",
            )
        for forbidden in ("leads_to", "enables", "exploits"):
            assert not any(
                rt.value == forbidden for rt in RelationshipType
            ), forbidden


@pytest.mark.parametrize("factory", WORLD_REPOS)
class TestEvidenceLinkage:
    def test_entity_evidence_property_scoped(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        result = store.add_entity(
            _entity(evidence=[EvidenceLinkRef(evidence_id=EvidenceID("ev_e1"))])
        )
        refs = store.evidence_for_entity(str(result.entity.id))
        assert len(refs) == 1
        assert refs[0]["evidence_id"] == "ev_e1"
        store.close()

    def test_reverse_lookup_entities_for_evidence(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        first = store.add_entity(
            _entity(evidence=[EvidenceLinkRef(evidence_id=EvidenceID("ev_shared"))])
        )
        second = store.add_entity(
            _entity(
                name="https://other.example.com",
                evidence=[EvidenceLinkRef(evidence_id=EvidenceID("ev_shared"))],
            )
        )
        assert sorted(store.entities_for_evidence("ev_shared")) == sorted(
            [str(first.entity.id), str(second.entity.id)]
        )
        store.close()

    def test_property_scoped_evidence_distinct_refs(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        result = store.add_entity(
            _entity(
                properties={"port": 443, "tls": True},
                evidence=[
                    EvidenceLinkRef(
                        evidence_id=EvidenceID("ev_port"), property_key="port", property_value="443"
                    ),
                    EvidenceLinkRef(
                        evidence_id=EvidenceID("ev_tls"), property_key="tls", property_value="True"
                    ),
                ],
            )
        )
        refs = store.evidence_for_entity(str(result.entity.id))
        assert {r["property_key"] for r in refs} == {"port", "tls"}
        store.close()

    def test_assertion_evidence_linked(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        result = store.add_entity(_entity())
        spec = AssertionSpec(
            mission_id=MID,
            session_id=SID,
            entity_id=result.entity.id,
            property_key="port",
            property_value="8080",
            epistemic_status=EvidenceStatus.HYPOTHESIZED,
            evidence=[EvidenceLinkRef(evidence_id=EvidenceID("ev_assert"))],
        )
        assertion = store.add_assertion(spec)
        assert assertion.action == WorldMutation.CREATED
        refs = store.evidence_for_assertion(str(assertion.assertion.id))
        assert [r["evidence_id"] for r in refs] == ["ev_assert"]
        assert len(store.list_assertions(str(result.entity.id))) == 1
        store.close()


@pytest.mark.parametrize("factory", WORLD_REPOS)
class TestConfidence:
    def test_corroboration_raises_to_max_never_lowers(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        first = store.add_entity(_entity(confidence=Confidence.LOW))
        second = store.add_entity(_entity(confidence=Confidence.HIGH))
        assert second.action == WorldMutation.CORROBORATED
        assert second.entity.confidence == Confidence.HIGH
        assert store.get_entity(str(first.entity.id)).confidence == Confidence.HIGH
        again = store.add_entity(_entity(confidence=Confidence.LOW))
        assert again.entity.confidence == Confidence.HIGH
        store.close()

    def test_confidence_round_trips_through_persistence(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        result = store.add_entity(_entity(confidence=Confidence.CONFIRMED))
        fetched = store.get_entity(str(result.entity.id))
        assert fetched is not None
        assert fetched.confidence == Confidence.CONFIRMED
        store.close()


@pytest.mark.parametrize("factory", WORLD_REPOS)
class TestContradictionAndSupersession:
    def test_weak_contradiction_recorded_not_overwritten(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        result = store.add_entity(_entity(properties={"port": 443}))
        conflicting = store.add_entity(
            _entity(
                properties={"port": 8080},
                epistemic_status=EvidenceStatus.HYPOTHESIZED,
                confidence=Confidence.LOW,
                evidence=[],
            )
        )
        assert conflicting.action == WorldMutation.CONTRADICTION_RECORDED
        assert conflicting.entity.id == result.entity.id
        assert conflicting.entity.properties == {"port": 443}
        assert conflicting.assertion is not None
        stored = store.get_entity(str(result.entity.id))
        assert stored is not None
        assert stored.lifecycle == WorldLifecycle.ACTIVE
        assert stored.properties == {"port": 443}
        assertions = store.list_assertions(str(result.entity.id))
        assert len(assertions) == 1
        assert assertions[0].property_key == "port"
        assert assertions[0].property_value == "8080"
        store.close()

    def test_authoritative_supersession_preserves_history(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        first = store.add_entity(_entity(properties={"port": 443}))
        second = store.add_entity(_entity(properties={"port": 8443}))
        assert second.action == WorldMutation.SUPERSEDED
        assert second.previous is not None
        assert second.previous.id == first.entity.id
        assert second.entity.version == 2
        assert second.entity.supersedes == first.entity.id
        old = store.get_entity(str(first.entity.id))
        assert old is not None
        assert old.lifecycle == WorldLifecycle.SUPERSEDED
        assert old.properties == {"port": 443}
        new = store.get_entity(str(second.entity.id))
        assert new is not None
        assert new.lifecycle == WorldLifecycle.ACTIVE
        assert new.properties == {"port": 8443}
        assert store.count_entities(MID) == 2
        assert len(
            store.list_entities(WorldQuery(mission_id=MID))
        ) == 2
        store.close()

    def test_archived_then_reobserved_spawns_again(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        first = store.add_entity(_entity(properties={"port": 443}))
        store.archive_entity(str(first.entity.id))
        second = store.add_entity(_entity(properties={"port": 443}))
        assert second.action == WorldMutation.CREATED
        assert second.entity.version == 2
        assert second.entity.supersedes == first.entity.id
        store.close()

    def test_inferred_disagreement_never_supersedes(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        store.add_entity(_entity(properties={"port": 443}))
        weak = store.add_entity(
            _entity(
                properties={"port": 8080},
                epistemic_status=EvidenceStatus.INFERRED,
                confidence=Confidence.MEDIUM,
            )
        )
        assert weak.action == WorldMutation.CONTRADICTION_RECORDED
        current = store.find_entity(MID, EntityType.ENDPOINT, "https://web.example.com")
        assert current is not None
        assert current.properties == {"port": 443}
        store.close()


@pytest.mark.parametrize("factory", WORLD_REPOS)
class TestMissionAndSessionIsolation:
    def test_same_identity_across_missions_is_distinct(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        a = store.add_entity(_entity(mission_id=MID))
        b = store.add_entity(_entity(mission_id=MID_OTHER, session_id=SID_OTHER))
        assert a.entity.id != b.entity.id
        assert store.count_entities(MID) == 1
        assert store.count_entities(MID_OTHER) == 1
        assert len(store.list_entities(WorldQuery(mission_id=MID))) == 1
        assert len(store.list_entities(WorldQuery(mission_id=MID_OTHER))) == 1
        store.close()

    def test_session_filter_narrows_within_mission(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        store.add_entity(_entity(session_id=SID))
        store.add_entity(
            _entity(name="https://other.example.com", session_id=SID_OTHER)
        )
        assert len(
            store.list_entities(WorldQuery(mission_id=MID, session_id=SID))
        ) == 1
        assert len(
            store.list_entities(WorldQuery(mission_id=MID, session_id=SID_OTHER))
        ) == 1
        assert len(store.list_entities(WorldQuery(mission_id=MID))) == 2
        store.close()


@pytest.mark.parametrize("factory", WORLD_REPOS)
class TestMaterializer:
    def test_no_fake_authority_without_evidence(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        materializer = WorldMaterializer(store)
        fact = EntityFact(
            entity_type=EntityType.TECHNOLOGY,
            name="PostgreSQL 16",
            properties={"purpose": "database"},
            confidence=Confidence.LOW,
            evidence=[],
        )
        result = materializer.materialize_entity(MID, fact, evidence_statuses=[])
        assert result.action == WorldMutation.CREATED
        assert result.entity.epistemic_status == EvidenceStatus.HYPOTHESIZED
        assert result.entity.confidence == Confidence.LOW
        store.close()

    def test_evidence_floor_is_highest_status(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        materializer = WorldMaterializer(store)
        fact = EntityFact(
            entity_type=EntityType.APPLICATION,
            name="billing-app",
            evidence=[EvidenceLinkRef(evidence_id=EvidenceID("ev_obs"))],
        )
        result = materializer.materialize_entity(
            MID,
            fact,
            evidence_statuses=[EvidenceStatus.HYPOTHESIZED, EvidenceStatus.OBSERVED],
        )
        assert result.entity.epistemic_status == EvidenceStatus.OBSERVED
        store.close()

    def test_identical_materialization_corroborates(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        materializer = WorldMaterializer(store)
        fact = EntityFact(
            entity_type=EntityType.SERVICE,
            name="api-gateway",
            evidence=[EvidenceLinkRef(evidence_id=EvidenceID("ev_gw"))],
        )
        first = materializer.materialize_entity(
            MID, fact, evidence_statuses=[EvidenceStatus.OBSERVED]
        )
        second = materializer.materialize_entity(
            MID, fact, evidence_statuses=[EvidenceStatus.OBSERVED]
        )
        assert second.action == WorldMutation.CORROBORATED
        assert second.entity.id == first.entity.id
        store.close()

    def test_relationship_materialization_requires_entity_ids(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        materializer = WorldMaterializer(store)
        with pytest.raises(WorldRuleError):
            materializer.materialize_relationship(
                MID,
                RelationshipFact(
                    relationship_type=RelationshipType.HOSTS,
                    source_entity_id="went_0000000000000000",
                    target_entity_id="went_0000000000000001",
                ),
            )
        store.close()


@pytest.mark.parametrize("factory", WORLD_REPOS)
class TestQueryDeterminism:
    def test_list_order_is_stable(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        for name in ("z.example.com", "a.example.com", "m.example.com"):
            store.add_entity(
                _entity(name=name, entity_type=EntityType.SERVICE)
            )
        query = WorldQuery(mission_id=MID)
        first = [e.canonical_key for e in store.list_entities(query)]
        second = [e.canonical_key for e in store.list_entities(query)]
        assert first == sorted(first)
        assert first == second
        store.close()

    def test_neighborhood_is_stable_and_bounded(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        a, b = _endpoint_pair(store)
        for name in ("https://x1.example.com", "https://x2.example.com", "https://x3.example.com"):
            node = store.add_entity(_entity(name=name))
            store.add_relationship(
                _relationship(
                    relationship_type=RelationshipType.USES,
                    source_entity_id=a.id,
                    target_entity_id=node.entity.id,
                )
            )
        first = store.neighborhood(str(a.id), direction="out", max_depth=2)
        second = store.neighborhood(str(a.id), direction="out", max_depth=2)
        assert first is not None and second is not None
        assert first.depth == 1
        assert [str(e.id) for e in first.entities] == [
            str(e.id) for e in second.entities
        ]
        assert [str(r.id) for r in first.relationships] == [
            str(r.id) for r in second.relationships
        ]
        store.close()

    def test_neighborhood_returns_none_for_unknown_entity(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        assert store.neighborhood("went_0000000000000000") is None
        store.close()


@pytest.mark.parametrize("factory", WORLD_REPOS)
class TestHealthAndLifecycle:
    def test_health_check(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        assert store.health_check()
        store.close()

    def test_archive_is_soft(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        result = store.add_entity(_entity())
        archived = store.archive_entity(str(result.entity.id))
        assert archived is not None
        assert archived.lifecycle == WorldLifecycle.ARCHIVED
        fetched = store.get_entity(str(result.entity.id))
        assert fetched is not None
        assert fetched.lifecycle == WorldLifecycle.ARCHIVED
        store.close()


@pytest.mark.parametrize("factory", WORLD_REPOS)
class TestTransactionAtomicity:
    def test_rule_error_leaves_no_partial_state(self, factory, tmp_path) -> None:
        store = _store_with(factory, tmp_path)
        a, _ = _endpoint_pair(store)
        before = store.count_entities(MID)
        with pytest.raises(WorldRuleError):
            store.add_relationship(
                _relationship(
                    source_entity_id=a.id,
                    target_entity_id="went_0000000000000000",
                )
            )
        assert store.count_entities(MID) == before
        assert len(store.list_relationships(RelationshipQuery(mission_id=MID))) == 0
        store.close()


class TestSqlitePersistence:
    def _store(self, path) -> WorldModelStore:
        return WorldModelStore(repository=SQLiteWorldRepository(str(path)))

    def test_restart_preserves_entities_relationships_and_evidence(self, tmp_path) -> None:
        path = tmp_path / "world_model.db"
        first = self._store(path)
        result = first.add_entity(_entity())
        a, b = _endpoint_pair(first)
        rel = first.add_relationship(
            _relationship(
                relationship_type=RelationshipType.HOSTS,
                source_entity_id=a.id,
                target_entity_id=b.id,
                evidence=[EvidenceLinkRef(evidence_id=EvidenceID("ev_r_persist"))],
            )
        )
        first.close()

        second = self._store(path)
        assert second.get_entity(str(result.entity.id)) is not None
        assert second.get_relationship(str(rel.relationship.id)) is not None
        assert {
            ref["evidence_id"]
            for ref in second.evidence_for_relationship(str(rel.relationship.id))
        } == {"ev_r_persist"}
        assert second.count_entities(MID) == 3
        second.close()

    def test_transaction_rollback_on_mid_transaction_failure(self, tmp_path) -> None:
        repo = SQLiteWorldRepository(str(tmp_path / "rollback.db"))
        store = WorldModelStore(repository=repo)
        store.add_entity(_entity())
        with pytest.raises(RuntimeError), repo.transaction():
            store.add_entity(_entity(name="https://rolled-back.example.com"))
            raise RuntimeError("boom")
        assert store.count_entities(MID) == 1
        assert (
            store.find_entity(
                MID, EntityType.ENDPOINT, "https://rolled-back.example.com"
            )
            is None
        )
        store.close()
