import hashlib
import ipaddress
from urllib.parse import urlparse

from blackforge.core.types import EvidenceStatus, MissionID
from blackforge.world_model.models import EntityType, RelationshipType

RELATIONSHIP_DIRECTION_SYMMETRIC: set[RelationshipType] = {
    RelationshipType.CONNECTS_TO,
    RelationshipType.ASSOCIATED_WITH,
}

RELATIONSHIP_DIRECTION_DIRECTED: set[RelationshipType] = {
    rt for rt in RelationshipType if rt not in RELATIONSHIP_DIRECTION_SYMMETRIC
}


def normalize_hostname(value: str) -> str:
    """Cautious hostname normalization.

    Only mechanical, unambiguous transformations: trim whitespace, lowercase,
    strip a single trailing dot. Distinct-but-similar names (``web`` vs
    ``web-1``) are deliberately NOT merged.
    """
    name = value.strip().rstrip(".").lower()
    if not name or len(name) > 253:
        raise ValueError("invalid hostname")
    return name


def normalize_url(value: str) -> str:
    """Cautious URL normalization.

    Lowercases scheme/host, keeps explicit non-default ports, and
    canonicalizes an empty path to ``/``. Query strings and fragments are
    preserved so distinct resources are never merged.
    """
    parsed = urlparse(value.strip())
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("invalid url")
    scheme = parsed.scheme.lower()
    host = parsed.netloc.lower()
    if (scheme == "http" and host.endswith(":80")) or (
        scheme == "https" and host.endswith(":443")
    ):
        host = host.rsplit(":", 1)[0]
    path = parsed.path or "/"
    rebuilt = f"{scheme}://{host}{path}"
    if parsed.query:
        rebuilt += f"?{parsed.query}"
    if parsed.fragment:
        rebuilt += f"#{parsed.fragment}"
    return rebuilt


def normalize_ip(value: str) -> str:
    """Validate an IP literal and return the canonical form."""
    return str(ipaddress.ip_address(value.strip()))


def normalize_hostname_or_ip(value: str) -> str:
    """Normalize an asset name: an IP literal when it parses, otherwise a hostname."""
    text = value.strip()
    try:
        return normalize_ip(text)
    except ValueError:
        return normalize_hostname(text)


def normalize_network(value: str) -> str:
    """Normalize a network to canonical form.

    Accepts a CIDR prefix (``192.0.2.0/24``) or a bare IP literal (treated as a
    single-address network). Rejects everything else.
    """
    text = value.strip()
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        pass
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise ValueError("invalid network") from exc


def normalize_port(value: int | str) -> str:
    """Validate a port and return it as a normal decimal string."""
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid port") from exc
    if not 1 <= port <= 65535:
        raise ValueError("port out of range")
    return str(port)


_NAME_NORMALIZERS: dict[EntityType, str] = {
    EntityType.ENDPOINT: "url",
    EntityType.NETWORK: "network",
    EntityType.ASSET: "hostname-or-ip",
    EntityType.SERVICE: "hostname",
    EntityType.APPLICATION: "hostname",
    EntityType.IDENTITY: "hostname",
    EntityType.ROLE: "slug",
    EntityType.PERMISSION: "slug",
    EntityType.RESOURCE: "slug",
    EntityType.AUTHENTICATION: "slug",
    EntityType.TECHNOLOGY: "slug",
    EntityType.CLOUD_RESOURCE: "slug",
    EntityType.CONTAINER: "slug",
    EntityType.SOURCE_COMPONENT: "slug",
    EntityType.DATA_STORE: "hostname",
    EntityType.TRUST_RELATION: "slug",
    EntityType.WORKFLOW: "slug",
    EntityType.BUSINESS_ACTION: "slug",
    EntityType.BUSINESS_STATE: "slug",
    EntityType.BUSINESS_RULE: "slug",
}


def normalize_entity_name(entity_type: EntityType, name: str) -> str:
    """Normalize an entity name by its type.

    Endpoints are treated as URLs (they are reachable targets), networks as
    CIDR ranges or IP literals, assets as IP literals or hostnames, other
    IP-family entities as IP literals where applicable, and abstract kinds as
    slashed slugs. ``slug`` does no aggressive stemming — only whitespace trim +
    lowercase — so distinct names stay distinct.
    """
    normalizer = _NAME_NORMALIZERS.get(entity_type, "slug")
    if normalizer == "url":
        return normalize_url(name)
    if normalizer == "network":
        return normalize_network(name)
    if normalizer == "hostname-or-ip":
        return normalize_hostname_or_ip(name)
    if normalizer == "ip":
        return normalize_ip(name)
    if normalizer == "hostname":
        return normalize_hostname(name)
    return name.strip().lower()


def build_entity_canonical_key(
    entity_type: EntityType,
    normalized_name: str,
    namespace: str | None = None,
) -> str:
    """Deterministic identity for an entity (readable, not hashed).

    The canonical key is scoped per mission at the persistence layer; the
    namespace disambiguates same-named entities of the same type when needed.
    """
    ns = namespace or ""
    return f"{entity_type.value}|{ns}|{normalized_name}"


def compute_entity_dedup_key(mission_id: MissionID, canonical_key: str) -> str:
    """Indexable hash form of an entity's canonical identity."""
    payload = f"entity|{mission_id}|{canonical_key}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_relationship_canonical_key(
    relationship_type: RelationshipType,
    source_canonical_key: str,
    target_canonical_key: str,
) -> str:
    """Deterministic identity for a relationship.

    Symmetric types (CONNECTS_TO, ASSOCIATED_WITH) sort the endpoints so the
    reverse edge dedups to the same record; directed types preserve the
    caller-specified direction, so ``A -> B`` and ``B -> A`` remain distinct.
    """
    if relationship_type in RELATIONSHIP_DIRECTION_SYMMETRIC:
        return "|".join(sorted((source_canonical_key, target_canonical_key)))
    return f"{source_canonical_key}|{target_canonical_key}"


def compute_relationship_dedup_key(
    mission_id: MissionID,
    relationship_type: RelationshipType,
    canonical_pair: str,
) -> str:
    """Indexable hash form of a relationship's canonical identity."""
    payload = f"rel|{mission_id}|{relationship_type.value}|{canonical_pair}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compute_assertion_dedup_key(
    mission_id: MissionID,
    entity_id: str,
    property_key: str,
    property_value: str | None,
    epistemic_status: EvidenceStatus,
) -> str:
    """Indexable hash form of an assertion's identity.

    Value and epistemic status are part of the identity so distinct beliefs
    about the same property are preserved instead of silently overwritten.
    """
    payload = (
        f"assert|{mission_id}|{entity_id}|{property_key}|"
        f"{property_value or ''}|{epistemic_status.value}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
