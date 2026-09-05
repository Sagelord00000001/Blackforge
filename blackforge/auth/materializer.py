from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from blackforge.auth.models import (
    AccessControlObservation,
    AuthSurfaceObservation,
    Observation,
    PermissionObservation,
    ResourceAccessObservation,
    RoleObservation,
)
from blackforge.core.types import (
    Confidence,
    EvidenceID,
    EvidenceStatus,
    MissionID,
    SessionID,
)
from blackforge.world_model.materializer import (
    EntityFact,
    RelationshipFact,
    WorldMaterializer,
)
from blackforge.world_model.models import (
    AssertionSpec,
    EntityType,
    EvidenceLinkRef,
    RelationshipType,
    WorldEntity,
)

if TYPE_CHECKING:
    from blackforge.world_model.store import WorldModelStore

_OBSERVED = [EvidenceStatus.OBSERVED]
_VALIDATED = [EvidenceStatus.OBSERVED, EvidenceStatus.VALIDATED]


def _ref(evidence_id: EvidenceID, **properties: str | None) -> EvidenceLinkRef:
    return EvidenceLinkRef(
        evidence_id=evidence_id,
        property_key=properties.get("property_key"),
        property_value=properties.get("property_value"),
    )


class AuthMaterializeEntry(BaseModel):
    entity_type: str
    name: str
    namespace: str | None = None
    entity_id: str
    action: str


class AuthMaterializeReport(BaseModel):
    entries: list[AuthMaterializeEntry] = Field(default_factory=list)
    relationships_created: int = 0
    relationships_corroborated: int = 0
    assertions_created: int = 0
    assertions_corroborated: int = 0

    @property
    def entities_created(self) -> int:
        return sum(1 for e in self.entries if e.action == "created")

    @property
    def entities_updated(self) -> int:
        return len(self.entries) - self.entities_created


class AuthWorldMaterializer:
    """Maps typed auth observations into world model records.

    Mapping is fixed and deterministic — never inferred from free text:

    An application-scoped chain (all entities namespaced by host):

    * IDENTITY --HAS_ROLE--> ROLE --HAS_PERMISSION--> PERMISSION
      --APPLIES_TO--> RESOURCE  (from role / permission observations)
    * Auth-scheme observations create an AUTHENTICATION entity (named by the
      scheme, namespaced by host) and link the host's ENDPOINT with
      --REQUIRES--> AUTHENTICATION when an ENDPOINT exists; otherwise a root
      endpoint ``https://{host}/`` is created and linked so REQUIRES always
      has a concrete subject.

    Validation/analysis observations become ASSERTIONS (bound to the host's
    identity or application entity) rather than entity properties, so a
    re-run never churns entity versions.
    """

    def __init__(self, store: WorldModelStore) -> None:
        self._store = store
        self._materializer = WorldMaterializer(store)

    @property
    def store(self) -> WorldModelStore:
        return self._store

    def materialize(
        self,
        mission_id: MissionID,
        observations: list[tuple[Observation, EvidenceID, Confidence]],
        *,
        session_id: SessionID | None = None,
    ) -> AuthMaterializeReport:
        report = AuthMaterializeReport()
        for observation, evidence_id, confidence in observations:
            self._materialize_one(
                mission_id,
                observation,
                evidence_id,
                confidence,
                report,
                session_id=session_id,
            )
        return report

    # ------------------------------------------------------------------
    # Per-kind mapping
    # ------------------------------------------------------------------
    def _materialize_one(
        self,
        mission_id: MissionID,
        observation: Observation,
        evidence_id: EvidenceID,
        confidence: Confidence,
        report: AuthMaterializeReport,
        *,
        session_id: SessionID | None,
    ) -> None:
        if isinstance(observation, AuthSurfaceObservation):
            self._materialize_auth_scheme(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
            self._assert_on_application(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif isinstance(observation, RoleObservation):
            self._materialize_role(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif isinstance(observation, PermissionObservation):
            self._materialize_permission(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif isinstance(
            observation, (ResourceAccessObservation, AccessControlObservation)
        ):
            self._assert_on_identity(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
        elif observation.kind in {
            "auth_scheme",
            "session",
            "oauth_metadata",
            "oidc_metadata",
            "mfa_surface",
            "authorization_surface",
        }:
            self._assert_on_application(
                mission_id, observation, evidence_id, confidence, report, session_id
            )

    # ------------------------------------------------------------------
    def _materialize_auth_scheme(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        auth_entity, action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.AUTHENTICATION,
                name=obs.scheme,
                namespace=obs.host,
                properties={
                    "scheme": obs.scheme,
                    "scheme_type": obs.scheme_type,
                    "source": "auth.authentication_surface",
                },
                confidence=confidence,
                evidence=[
                    _ref(evidence_id, property_key="url", property_value=obs.url)
                ],
            ),
            session_id,
        )
        endpoint = self._ensure_endpoint_for_host(
            mission_id, obs.host, obs.url, evidence_id, confidence, session_id
        )
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=RelationshipType.REQUIRES,
                source_entity_id=str(endpoint.id),
                target_entity_id=str(auth_entity.id),
                note="endpoint requires an authentication scheme",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )
        report.entries.append(
            AuthMaterializeEntry(
                entity_type="authentication",
                name=auth_entity.name,
                namespace=auth_entity.namespace,
                entity_id=str(auth_entity.id),
                action=action,
            )
        )

    def _materialize_role(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        role, role_action = self._upsert_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.ROLE,
                name=obs.role,
                namespace=obs.host,
                properties={
                    "description": obs.description,
                    "scope": obs.scope,
                    "source": "auth.role_observation",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            session_id,
        )
        application = self._ensure_application(
            mission_id, obs.host, evidence_id, confidence, session_id
        )
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=RelationshipType.RUNS,
                source_entity_id=str(application.id),
                target_entity_id=str(role.id),
                note="application defines role",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            report,
            session_id,
        )
        report.entries.append(
            AuthMaterializeEntry(
                entity_type="role",
                name=role.name,
                namespace=role.namespace,
                entity_id=str(role.id),
                action=role_action,
            )
        )

    def _materialize_permission(
        self, mission_id, obs, evidence_id, confidence, report, session_id
    ) -> None:
        host = obs.host or ""
        identity = (
            self._ensure_identity(
                mission_id, host, obs.identity, evidence_id, confidence, session_id
            )
            if obs.identity
            else None
        )
        role = (
            self._ensure_role(mission_id, host, obs.role, evidence_id, confidence, session_id)
            if obs.role
            else None
        )
        permission = self._ensure_permission(
            mission_id, host, obs.permission, obs.resource, evidence_id, confidence, session_id
        )
        resource = (
            self._ensure_resource(
                mission_id, host, obs.resource, evidence_id, confidence, session_id
            )
            if obs.resource
            else None
        )
        if identity is not None and role is not None:
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=RelationshipType.HAS_ROLE,
                    source_entity_id=str(identity.id),
                    target_entity_id=str(role.id),
                    note="identity holds role",
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )
        if role is not None:
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=RelationshipType.HAS_PERMISSION,
                    source_entity_id=str(role.id),
                    target_entity_id=str(permission.id),
                    note="role grants permission",
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )
        if resource is not None:
            self._link_report(
                mission_id,
                RelationshipFact(
                    relationship_type=RelationshipType.APPLIES_TO,
                    source_entity_id=str(permission.id),
                    target_entity_id=str(resource.id),
                    note="permission applies to resource",
                    confidence=confidence,
                    evidence=[_ref(evidence_id)],
                ),
                report,
                session_id,
            )
        report.entries.append(
            AuthMaterializeEntry(
                entity_type="permission",
                name=permission.name,
                namespace=permission.namespace,
                entity_id=str(permission.id),
                action="created",
            )
        )

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------
    def _ensure_application(
        self,
        mission_id: MissionID,
        host: str,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
    ) -> WorldEntity:
        existing = self._store.find_entity(mission_id, EntityType.APPLICATION, host)
        if existing is not None:
            return existing
        result = self._materializer.materialize_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.APPLICATION,
                name=host,
                properties={"host": host, "source": "auth"},
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            _OBSERVED,
            session_id,
        )
        return result.entity

    def _ensure_endpoint_for_host(
        self,
        mission_id: MissionID,
        host: str,
        url: str,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
    ) -> WorldEntity:
        exact = self._store.find_entity(mission_id, EntityType.ENDPOINT, url)
        if exact is not None:
            return exact
        from blackforge.world_model.query import WorldQuery

        endpoints = self._store.list_entities(
            WorldQuery(
                mission_id=mission_id,
                entity_type=EntityType.ENDPOINT,
                namespace=host,
                limit=1000,
            )
        )
        if endpoints:
            return endpoints[0]
        root_url = f"https://{host}/"
        root = self._store.find_entity(mission_id, EntityType.ENDPOINT, root_url)
        if root is not None:
            return root
        result = self._materializer.materialize_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.ENDPOINT,
                name=root_url,
                namespace=None,
                properties={"url": root_url, "host": host, "source": "auth"},
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            _OBSERVED,
            session_id,
        )
        application = self._ensure_application(
            mission_id, host, evidence_id, confidence, session_id
        )
        self._link_report(
            mission_id,
            RelationshipFact(
                relationship_type=RelationshipType.CONTAINS,
                source_entity_id=str(application.id),
                target_entity_id=str(result.entity.id),
                note="root web endpoint for auth surface",
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            None,
            session_id,
        )
        return result.entity

    def _ensure_identity(
        self,
        mission_id: MissionID,
        host: str,
        name: str | None,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
    ) -> WorldEntity | None:
        if not name:
            return None
        result = self._materializer.materialize_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.IDENTITY,
                name=name,
                namespace=host,
                properties={"host": host, "source": "auth"},
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            _OBSERVED,
            session_id,
        )
        return result.entity

    def _ensure_role(
        self,
        mission_id: MissionID,
        host: str,
        name: str | None,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
    ) -> WorldEntity | None:
        if not name:
            return None
        result = self._materializer.materialize_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.ROLE,
                name=name,
                namespace=host,
                properties={"host": host, "source": "auth"},
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            _OBSERVED,
            session_id,
        )
        return result.entity

    def _ensure_permission(
        self,
        mission_id: MissionID,
        host: str,
        name: str | None,
        resource: str | None,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
    ) -> WorldEntity:
        entity_name = f"{name}::{resource}" if resource else (name or "permission")
        result = self._materializer.materialize_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.PERMISSION,
                name=entity_name,
                namespace=host,
                properties={
                    "permission": name,
                    "resource": resource,
                    "host": host,
                    "source": "auth",
                },
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            _OBSERVED,
            session_id,
        )
        return result.entity

    def _ensure_resource(
        self,
        mission_id: MissionID,
        host: str,
        name: str | None,
        evidence_id: EvidenceID,
        confidence: Confidence,
        session_id: SessionID | None,
    ) -> WorldEntity | None:
        if not name:
            return None
        result = self._materializer.materialize_entity(
            mission_id,
            EntityFact(
                entity_type=EntityType.RESOURCE,
                name=name,
                namespace=host,
                properties={"host": host, "source": "auth"},
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            ),
            _OBSERVED,
            session_id,
        )
        return result.entity

    def _upsert_entity(
        self,
        mission_id: MissionID,
        fact: EntityFact,
        session_id: SessionID | None,
    ) -> tuple[WorldEntity, str]:
        result = self._materializer.materialize_entity(
            mission_id, fact, _OBSERVED, session_id
        )
        return result.entity, result.action.value

    def _assert_on_application(
        self,
        mission_id: MissionID,
        observation: Observation,
        evidence_id: EvidenceID,
        confidence: Confidence,
        report: AuthMaterializeReport,
        session_id: SessionID | None,
    ) -> None:
        application = self._ensure_application(
            mission_id, observation.host, evidence_id, confidence, session_id
        )
        for key, value in _auth_assertion_pairs(observation):
            self._add_assertion(
                mission_id,
                application.id,
                key,
                value,
                observation,
                evidence_id,
                confidence,
                report,
                session_id,
            )

    def _assert_on_identity(
        self,
        mission_id: MissionID,
        observation: Observation,
        evidence_id: EvidenceID,
        confidence: Confidence,
        report: AuthMaterializeReport,
        session_id: SessionID | None,
    ) -> None:
        identity_name = observation.identity
        if identity_name is None:
            self._assert_on_application(
                mission_id, observation, evidence_id, confidence, report, session_id
            )
            return
        identity = self._ensure_identity(
            mission_id, observation.host, identity_name, evidence_id, confidence, session_id
        )
        for key, value in _auth_assertion_pairs(observation):
            self._add_assertion(
                mission_id,
                identity.id,
                key,
                value,
                observation,
                evidence_id,
                confidence,
                report,
                session_id,
            )

    def _add_assertion(
        self,
        mission_id: MissionID,
        entity_id,
        key: str,
        value: str,
        observation: Observation,
        evidence_id: EvidenceID,
        confidence: Confidence,
        report: AuthMaterializeReport,
        session_id: SessionID | None,
    ) -> None:
        status = (
            EvidenceStatus.VALIDATED
            if observation.kind in {"resource_access", "access_control"}
            else EvidenceStatus.OBSERVED
        )
        result = self._store.add_assertion(
            AssertionSpec(
                mission_id=mission_id,
                session_id=session_id,
                entity_id=entity_id,
                property_key=key,
                property_value=value,
                epistemic_status=status,
                confidence=confidence,
                evidence=[_ref(evidence_id)],
            )
        )
        if result.action.value == "created":
            report.assertions_created += 1
        else:
            report.assertions_corroborated += 1

    def _link_report(
        self,
        mission_id: MissionID,
        fact: RelationshipFact,
        report: AuthMaterializeReport | None,
        session_id: SessionID | None,
    ) -> None:
        result = self._materializer.materialize_relationship(mission_id, fact, session_id)
        if report is None:
            return
        if result.action.value == "created":
            report.relationships_created += 1
        else:
            report.relationships_corroborated += 1

    @staticmethod
    def _record(
        report: AuthMaterializeReport,
        entity_type: str,
        entity: WorldEntity,
        action: str,
    ) -> None:
        report.entries.append(
            AuthMaterializeEntry(
                entity_type=entity_type,
                name=entity.name,
                namespace=entity.namespace,
                entity_id=str(entity.id),
                action=action,
            )
        )


def _auth_assertion_pairs(observation: Observation) -> list[tuple[str, str]]:
    """Stable property_key/property_value pairs for an auth analysis observation."""
    if observation.kind == "session":
        flags = sorted(observation.flags)
        return [
            (
                f"session.{observation.name}",
                (
                    f"secure={str(observation.secure).lower()} "
                    f"httponly={str(observation.httponly).lower()} "
                    f"flags={','.join(flags) or 'none'}"
                    f"{' samesite=' + observation.samesite if observation.samesite else ''}"
                ),
            )
        ]
    if observation.kind == "auth_surface":
        label = observation.scheme_type or "observed"
        return [(f"auth_scheme.{observation.scheme}", label)]
    if observation.kind == "auth_scheme":
        policy = (
            observation.password_policy
            if observation.password_policy_observed and observation.password_policy
            else "not_observed"
        )
        return [
            (
                f"auth_scheme.detected.{observation.scheme}",
                (
                    f"present={str(observation.present).lower()} "
                    f"password_policy={policy} "
                    f"session_timeout_minutes={observation.session_timeout_minutes or 'unknown'}"
                ),
            )
        ]
    if observation.kind == "oauth_metadata":
        return [
            (
                "oauth.metadata",
                (
                    f"grants={','.join(observation.grant_types) or 'none'} "
                    f"scopes={','.join(observation.scopes) or 'none'} "
                    f"pkce={str(observation.pkce_supported).lower()}"
                ),
            )
        ]
    if observation.kind == "oidc_metadata":
        return [
            (
                "oidc.metadata",
                (
                    f"issuer={observation.issuer or 'unknown'} "
                    f"alg={observation.id_token_signing_alg or 'unknown'}"
                ),
            )
        ]
    if observation.kind == "mfa_surface":
        return [
            (
                "mfa",
                (
                    f"status={observation.mfa_status.value} "
                    f"factors={','.join(observation.factors) or 'none'}"
                ),
            )
        ]
    if observation.kind == "authorization_surface":
        return [
            (
                "authorization.model",
                f"{observation.authz_model} enforcement={observation.enforcement or 'unknown'}",
            )
        ]
    if observation.kind == "resource_access":
        return [
            (
                f"access.{observation.resource}",
                (
                    f"access={observation.access.value} "
                    f"identity={observation.identity or 'none'} "
                    f"role={observation.role or 'none'}"
                ),
            )
        ]
    if observation.kind == "access_control":
        return [
            (
                f"access_control.{observation.resource}",
                (
                    f"access={observation.access.value} "
                    f"expected={observation.expected_access.value} "
                    f"consistent={str(observation.consistent).lower()} "
                    f"identity={observation.identity or 'none'}"
                ),
            )
        ]
    return []
