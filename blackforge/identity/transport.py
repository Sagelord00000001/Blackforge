from __future__ import annotations

import json
from typing import Any

from blackforge.identity.models import IdentityMode

# ---------------------------------------------------------------------------
# Deterministic mock identity directory (AELIONIX-CORP).
#
# The dataset is fixed fixture data: one active-domain-style directory with
# human/service/computer identities, groups, roles, permissions, resources,
# and their descriptive relationships. Nothing here requires a real directory
# and nothing in here is ever queried or mutated at runtime. Credential-like
# fields below exist ONLY to prove the redaction boundary: they are stripped
# before any evidence row or world record is produced.
# ---------------------------------------------------------------------------

IDENTITY_DIRECTORY = "AELIONIX-CORP"
IDENTITY_DIRECTORY_DNS = "AELIONIX-CORP.LOCAL"

_IDENTITIES: dict[str, dict[str, Any]] = {
    "alice": {
        "principal_type": "human",
        "display_name": "Alice Engineer",
        "email": "alice@aelionix-corp.local",
        "enabled": True,
        "locked": False,
        "privilege_level": "standard",
    },
    "bob": {
        "principal_type": "human",
        "display_name": "Bob Operator",
        "email": "bob@aelionix-corp.local",
        "enabled": True,
        "locked": False,
        "privilege_level": "elevated",
    },
    "build-service": {
        "principal_type": "service_account",
        "display_name": "Build Automation Service",
        "email": "build-service@aelionix-corp.local",
        "enabled": True,
        "locked": False,
        "privilege_level": "service",
    },
    "api-service": {
        "principal_type": "service_account",
        "display_name": "Inventory API Service",
        "email": "api-service@aelionix-corp.local",
        "enabled": True,
        "locked": False,
        "privilege_level": "service",
    },
    "web-server-01$": {
        "principal_type": "computer",
        "display_name": "WEB-SERVER-01",
        "email": None,
        "enabled": True,
        "locked": False,
        "privilege_level": "standard",
    },
}

_GROUPS: dict[str, dict[str, Any]] = {
    "engineering": {"scope_type": "domain_local"},
    "operations": {"scope_type": "domain_local"},
    "administrators": {"scope_type": "domain_local"},
    "read-only": {"scope_type": "domain_local"},
}

_ROLES: dict[str, dict[str, Any]] = {
    "application-admin": {"privilege_level": "administrator"},
    "deployment-operator": {"privilege_level": "elevated"},
    "viewer": {"privilege_level": "standard"},
    "service-operator": {"privilege_level": "service"},
}

_PERMISSIONS: dict[str, dict[str, Any]] = {
    "deploy": {},
    "manage": {},
    "read": {},
    "view_logs": {},
}

_RESOURCES: dict[str, dict[str, Any]] = {
    "production-api": {"resource_type": "api_endpoint"},
    "internal-dashboard": {"resource_type": "web_application"},
    "deployment-system": {"resource_type": "automation_system"},
    "database-cluster": {"resource_type": "data_store"},
}

_MEMBERSHIPS: dict[str, list[str]] = {
    "alice": ["engineering"],
    "bob": ["operations", "administrators"],
    "build-service": ["operations"],
    "api-service": ["read-only"],
    "web-server-01$": ["administrators"],
}

_ROLE_ASSIGNMENTS: dict[str, list[str]] = {
    "alice": ["viewer"],
    "bob": ["deployment-operator"],
    "build-service": ["service-operator"],
    "api-service": ["service-operator"],
    "web-server-01$": ["viewer"],
}

_PERMISSION_ASSIGNMENTS: dict[str, list[str]] = {
    "application-admin": ["deploy"],
    "deployment-operator": ["deploy", "view_logs"],
    "viewer": ["read"],
    "service-operator": ["manage"],
}

_PERMISSION_RESOURCES: dict[str, list[str]] = {
    "deploy": ["production-api", "deployment-system"],
    "manage": ["internal-dashboard", "database-cluster"],
    "read": ["internal-dashboard"],
    "view_logs": ["deployment-system"],
}

# (key, value, source, resolved)
_METADATA: dict[str, list[tuple[str, str, str, bool]]] = {
    "alice": [
        ("department", "engineering", "directory", True),
        ("department", "sales", "secondary_hr_feed", True),
    ],
    "api-service": [
        ("owning_team", "platform", "directory", True),
        ("manager", "ghost-manager", "identity_api", False),
    ],
    "build-service": [
        ("purpose", "build_automation", "directory", True),
    ],
}

# Credential-like demo fields used ONLY to prove artifact redaction.
_SECRET_DEMO_FIELDS: dict[str, dict[str, Any]] = {
    "build-service": {
        "password_hash": "demo-build-secret-hash-0000",
        "session_token": "demo-session-token-0000",
    },
    "api-service": {
        "credentials": {"api_key": "demo-api-key-0000"},
    },
}

_ERROR_TABLE: dict[str, dict[str, str]] = {
    "snail-dir": {"kind": "timeout", "message": "directory observation timed out"},
    "bursty-dir": {"kind": "rate_limited", "message": "directory observation rate limit exceeded"},
    "locked-dir": {"kind": "unauthorized", "message": "directory observation not authorized"},
    "garbled-dir": {"kind": "malformed", "message": "directory returned a malformed response"},
    "fabricated-dir": {"kind": "unsupported_directory", "message": "directory not modeled"},
}


class MockIdentityTransport:
    """Deterministic mock directory transport.

    Every method returns a JSON document just like a real directory adapter
    would: ``{"tool", "mode", "target", "observations": [...]}`` for success
    or ``{"tool", "mode", "target", "error": {"kind", "message"}}`` for a
    handled negative outcome. Target strings may be a directory
    (``AELIONIX-CORP``), a directory DNS name (``AELIONIX-CORP.LOCAL``), an
    identity (``alice``, ``alice@aelionix-corp.local``,
    ``AELIONIX-CORP\\alice``), or a synthetic error fixture.
    """

    # ------------------------------------------------------------------
    # Resolution helpers
    # ------------------------------------------------------------------
    def _split_target(
        self, target: str, identity: str | None = None
    ) -> tuple[str, str, str | None]:
        """Resolve (state, directory, identity) from any authorized spelling."""
        lowered = target.strip().lower().rstrip(".")
        if identity:
            return (*self._resolve_directory(lowered), identity)
        if "@" in lowered:
            _, mail = lowered.rsplit("@", 1)
            return (*self._resolve_directory(mail), lowered.split("@", 1)[0])
        if "\\" in lowered:
            directory_part, _, name = lowered.partition("\\")
            return (*self._resolve_directory(directory_part), name)
        return (*self._resolve_directory(lowered), None)

    @staticmethod
    def _resolve_directory(value: str) -> tuple[str, str]:
        cleaned = value.strip().lower().rstrip(".")
        if cleaned in _ERROR_TABLE:
            return ("error", cleaned)
        if cleaned in ("aelionix-corp", "aelionix-corp.local"):
            return ("ok", IDENTITY_DIRECTORY)
        return ("unsupported", cleaned)

    @staticmethod
    def _emit(doc: dict[str, Any]) -> str:
        return json.dumps(doc, sort_keys=True)

    def _document(
        self, tool: str, target: str, mode: IdentityMode, **fields: object
    ) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "tool": tool,
            "mode": mode.value,
            "target": target,
            "directory": IDENTITY_DIRECTORY,
        }
        doc.update(fields)
        return doc

    def _error(
        self, tool: str, target: str, kind: str, message: str
    ) -> str:
        doc = self._document(tool, target, IdentityMode.CONTROLLED)
        doc["error"] = {"kind": kind, "message": message}
        return self._emit(doc)

    def _identity_target(
        self, tool: str, target: str, identity: str | None
    ) -> tuple[str, str] | str:
        """Resolve an identity-level target: returns (directory, identity)."""
        status, directory, name = self._split_target(target, identity)
        if status == "error":
            error = _ERROR_TABLE[directory]
            return self._error(
                tool, target, error["kind"], error["message"]
            )
        if status == "unsupported":
            return self._error(
                tool,
                target,
                "unsupported_directory",
                f"directory not modeled: {directory}",
            )
        if name is None:
            return self._error(
                tool,
                target,
                "unsupported_directory",
                "identity-level capability requires an identity target",
            )
        if name not in _IDENTITIES:
            return self._error(
                tool,
                target,
                "unknown_identity",
                f"identity not present in directory: {name}",
            )
        return directory, name

    def _directory_target(
        self, tool: str, target: str, identity: str | None = None
    ) -> tuple[str, str] | str:
        """Resolve a directory-level target: returns (directory, identity_hint)."""
        status, directory, name = self._split_target(target, identity)
        if status == "error":
            error = _ERROR_TABLE[directory]
            return self._error(
                tool, target, error["kind"], error["message"]
            )
        if status == "unsupported":
            return self._error(
                tool,
                target,
                "unsupported_directory",
                f"directory not modeled: {directory}",
            )
        return directory, name or identity or ""

    # ------------------------------------------------------------------
    # Directory-level tools
    # ------------------------------------------------------------------
    def discover_directories(
        self, target: str, mode: IdentityMode = IdentityMode.CONTROLLED
    ) -> str:
        resolved = self._directory_target("discover_directories", target)
        if isinstance(resolved, str):
            return resolved
        directory = resolved[0]
        return self._emit(
            self._document(
                "discover_directories",
                target,
                mode,
                observations=[
                    {
                        "kind": "directory",
                        "directory": directory,
                        "dns_name": IDENTITY_DIRECTORY_DNS,
                        "directory_type": "active_directory_domain",
                        "forest": "AELIONIX",
                    }
                ],
            )
        )

    def inventory_identities(
        self, target: str, mode: IdentityMode = IdentityMode.CONTROLLED
    ) -> str:
        resolved = self._directory_target("inventory_identities", target)
        if isinstance(resolved, str):
            return resolved
        output: list[dict[str, Any]] = []
        for name, record in _IDENTITIES.items():
            entry: dict[str, Any] = {
                "kind": "identity",
                "directory": IDENTITY_DIRECTORY,
                "identity": name,
            }
            entry.update(record)
            entry.update(_SECRET_DEMO_FIELDS.get(name, {}))
            output.append(entry)
        return self._emit(
            self._document(
                "inventory_identities",
                target,
                mode,
                observations=output,
            )
        )

    def inventory_groups(
        self, target: str, mode: IdentityMode = IdentityMode.CONTROLLED
    ) -> str:
        resolved = self._directory_target("inventory_groups", target)
        if isinstance(resolved, str):
            return resolved
        output = [
            {
                "kind": "group",
                "directory": IDENTITY_DIRECTORY,
                "group": group,
                "scope_type": record.get("scope_type"),
                "membership_count": sum(
                    1 for members in _MEMBERSHIPS.values() if group in members
                ),
            }
            for group, record in _GROUPS.items()
        ]
        return self._emit(
            self._document(
                "inventory_groups",
                target,
                mode,
                observations=output,
            )
        )

    def inventory_roles(
        self, target: str, mode: IdentityMode = IdentityMode.CONTROLLED
    ) -> str:
        resolved = self._directory_target("inventory_roles", target)
        if isinstance(resolved, str):
            return resolved
        output = [
            {
                "kind": "role",
                "directory": IDENTITY_DIRECTORY,
                "role": role,
                "privilege_level": record.get("privilege_level"),
            }
            for role, record in _ROLES.items()
        ]
        return self._emit(
            self._document(
                "inventory_roles",
                target,
                mode,
                observations=output,
            )
        )

    def inventory_permissions(
        self, target: str, mode: IdentityMode = IdentityMode.CONTROLLED
    ) -> str:
        resolved = self._directory_target("inventory_permissions", target)
        if isinstance(resolved, str):
            return resolved
        output = [
            {
                "kind": "permission",
                "directory": IDENTITY_DIRECTORY,
                "permission": permission,
            }
            for permission in _PERMISSIONS
        ]
        return self._emit(
            self._document(
                "inventory_permissions",
                target,
                mode,
                observations=output,
            )
        )

    def inventory_resources(
        self, target: str, mode: IdentityMode = IdentityMode.CONTROLLED
    ) -> str:
        resolved = self._directory_target("inventory_resources", target)
        if isinstance(resolved, str):
            return resolved
        output = [
            {
                "kind": "resource",
                "directory": IDENTITY_DIRECTORY,
                "resource": resource,
                "resource_type": record.get("resource_type"),
            }
            for resource, record in _RESOURCES.items()
        ]
        return self._emit(
            self._document(
                "inventory_resources",
                target,
                mode,
                observations=output,
            )
        )

    # ------------------------------------------------------------------
    # Identity-level tools
    # ------------------------------------------------------------------
    def observe_membership(
        self,
        target: str,
        mode: IdentityMode = IdentityMode.CONTROLLED,
        identity: str | None = None,
    ) -> str:
        resolved = self._identity_target("observe_membership", target, identity)
        if isinstance(resolved, str):
            return resolved
        directory, name = resolved
        output: list[dict[str, Any]] = []
        for group in _MEMBERSHIPS.get(name, []):
            entry = {
                "kind": "membership",
                "directory": directory,
                "identity": name,
                "group": group,
                "resolved": group in _GROUPS,
            }
            output.append(entry)
            # Duplicate observation record to prove deterministic collapse.
            output.append(dict(entry))
        return self._emit(
            self._document(
                "observe_membership",
                target,
                mode,
                identity=name,
                observations=output,
            )
        )

    def observe_role_assignment(
        self,
        target: str,
        mode: IdentityMode = IdentityMode.CONTROLLED,
        identity: str | None = None,
    ) -> str:
        resolved = self._identity_target("observe_role_assignment", target, identity)
        if isinstance(resolved, str):
            return resolved
        directory, name = resolved
        output = [
            {
                "kind": "role_assignment",
                "directory": directory,
                "identity": name,
                "role": role,
            }
            for role in _ROLE_ASSIGNMENTS.get(name, [])
        ]
        return self._emit(
            self._document(
                "observe_role_assignment",
                target,
                mode,
                identity=name,
                observations=output,
            )
        )

    def observe_permission_assignment(
        self,
        target: str,
        mode: IdentityMode = IdentityMode.CONTROLLED,
        identity: str | None = None,
    ) -> str:
        resolved = self._identity_target(
            "observe_permission_assignment", target, identity
        )
        if isinstance(resolved, str):
            return resolved
        directory, name = resolved
        roles = _ROLE_ASSIGNMENTS.get(name, [])
        output = [
            {
                "kind": "permission_assignment",
                "directory": directory,
                "role": role,
                "permission": permission,
            }
            for role in roles
            for permission in _PERMISSION_ASSIGNMENTS.get(role, [])
        ]
        return self._emit(
            self._document(
                "observe_permission_assignment",
                target,
                mode,
                identity=name,
                observations=output,
            )
        )

    def analyze_relationships(
        self,
        target: str,
        mode: IdentityMode = IdentityMode.CONTROLLED,
        identity: str | None = None,
    ) -> str:
        resolved = self._identity_target("analyze_relationships", target, identity)
        if isinstance(resolved, str):
            return resolved
        directory, name = resolved
        memberships = _MEMBERSHIPS.get(name, [])
        roles = _ROLE_ASSIGNMENTS.get(name, [])
        permissions = sorted(
            {p for role in roles for p in _PERMISSION_ASSIGNMENTS.get(role, [])}
        )
        output: list[dict[str, Any]] = []
        relationship = lambda rel, source, target: {  # noqa: E731
            "kind": "relationship",
            "directory": directory,
            "relationship_type": rel,
            "source": source,
            "target": target,
        }
        for group in memberships:
            output.append(relationship("member_of", name, group))
        for role in roles:
            output.append(relationship("has_role", name, role))
        for role in roles:
            for permission in _PERMISSION_ASSIGNMENTS.get(role, []):
                output.append(relationship("has_permission", role, permission))
        for permission in permissions:
            for resource in _PERMISSION_RESOURCES.get(permission, []):
                output.append(relationship("applies_to", permission, resource))
        return self._emit(
            self._document(
                "analyze_relationships",
                target,
                mode,
                identity=name,
                observations=output,
            )
        )

    def observe_metadata(
        self,
        target: str,
        mode: IdentityMode = IdentityMode.CONTROLLED,
        identity: str | None = None,
    ) -> str:
        resolved = self._identity_target("observe_metadata", target, identity)
        if isinstance(resolved, str):
            return resolved
        directory, name = resolved
        output: list[dict[str, Any]] = []
        for key, value, source, resolved in _METADATA.get(name, []):
            entry: dict[str, Any] = {
                "kind": "metadata",
                "directory": directory,
                "identity": name,
                "attribute_key": key,
                "attribute_value": value,
                "source": source,
                "resolved": resolved,
            }
            if not resolved:
                entry["missing_reference"] = value
            output.append(entry)
        return self._emit(
            self._document(
                "observe_metadata",
                target,
                mode,
                identity=name,
                observations=output,
            )
        )


__all__ = [
    "IDENTITY_DIRECTORY",
    "IDENTITY_DIRECTORY_DNS",
    "MockIdentityTransport",
]
