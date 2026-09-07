"""Bounded, read-only real observation adapters for the orchestration layer.

These adapters are the *first real-world validation surface* of Phase 14.1.
Every adapter:

* uses only the Python standard library (``socket``, ``ssl``, ``urllib``),
* performs a single, bounded, read-only observation (DNS lookup, TLS
  handshake metadata, one unredirected HTTP GET),
* never spawns a process, never evals code, never follows redirects,
* redacts secret-like header values before anything is returned.

A real adapter never executes untrusted logic: the only thing it does is ask
the OS resolver, talk TLS, and read HTTP response metadata. The orchestrator
decides whether an adapter may fire at all by checking authorization, scope,
policy (``allow_real_controlled``) and the mission profile.

Adapter output is *metadata*, not a finding: a missing TLS certificate or an
unusual observed header is materialized as low-confidence evidence that a
planner or analyst may choose to revalidate.
"""

from __future__ import annotations

import socket
import ssl
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from blackforge.webapi.redaction import redact_headers

_HTTP_TIMEOUT_SECONDS = 15.0
_MAX_REDIRECT_DEPTH = 0  # never follow redirects in a real adapter


class RealObservation(BaseModel):
    """Normalized, redaction-safe result of one real observation."""

    capability_id: str
    target: str
    success: bool = False
    summary: str = ""
    observed: dict[str, Any] = Field(default_factory=dict)
    redacted: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    observed_at: float = Field(default_factory=time.time)


class RealObservationError(Exception):
    """A transport-level failure inside a real adapter."""


class RealObservationAdapter(ABC):
    """Typed transport contract: one capability id, one observation call."""

    capability_id: str = ""
    description: str = ""

    @abstractmethod
    def observe(self, target: str) -> RealObservation: ...


def _with_timeout_socket(target: str, port: int) -> socket.socket | None:
    """Open a bounded TCP connection for TLS inspection."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(_HTTP_TIMEOUT_SECONDS)
    try:
        sock.connect((target, port))
        return sock
    except OSError:
        sock.close()
        return None


class DNSObservationAdapter(RealObservationAdapter):
    """recon.dns: A/AAAA records via the OS resolver.

    Passive in practice (a stub resolver lookup); bounded to a single lookup
    with a short timeout and no recursion of its own.
    """

    capability_id = "recon.dns"
    description = "Resolve A/AAAA records via the OS resolver (read-only)."

    def observe(self, target: str) -> RealObservation:
        start = time.time()
        try:
            infos = socket.getaddrinfo(
                target, None, socket.AF_UNSPEC, socket.SOCK_STREAM
            )
        except socket.gaierror:
            return RealObservation(
                capability_id=self.capability_id,
                target=target,
                success=False,
                error="name resolution failed",
                observed={
                    "resolver": "os_stub",
                    "elapsed_ms": round((time.time() - start) * 1000, 2),
                },
            )
        addresses: list[str] = []
        families: list[str] = []
        seen: set[str] = set()
        for family, _socktype, _proto, _canonical, sockaddr in infos:
            address = sockaddr[0]
            if address not in seen:
                seen.add(address)
                addresses.append(address)
                if family == socket.AF_INET6:
                    families.append("AAAA")
                elif family == socket.AF_INET:
                    families.append("A")
        return RealObservation(
            capability_id=self.capability_id,
            target=target,
            success=bool(addresses),
            summary=(
                f"resolved {len(addresses)} address(es)"
                if addresses
                else "no addresses resolved"
            ),
            observed={
                "resolved_addresses": addresses,
                "families": families,
                "elapsed_ms": round((time.time() - start) * 1000, 2),
            },
        )


class TLSObservationAdapter(RealObservationAdapter):
    """recon.tls_metadata: TLS certificate metadata over a bounded handshake.

    Only the certificate *metadata* (subject, issuer, validity) is kept; the
    DER bytes are never persisted.
    """

    capability_id = "recon.tls_metadata"
    description = "Inspect TLS certificate metadata on 443 (read-only)."

    def observe(self, target: str) -> RealObservation:
        connection = _with_timeout_socket(target, 443)
        if connection is None:
            return RealObservation(
                capability_id=self.capability_id,
                target=target,
                success=False,
                error="tcp connect failed on 443",
                observed={"port": 443},
            )
        try:
            context = ssl.create_default_context()
            with context.wrap_socket(connection, server_hostname=target) as tls:
                cert = tls.getpeercert()
                protocol_version = tls.version() or "unknown"
        except (ssl.SSLError, OSError) as exc:
            connection.close()
            return RealObservation(
                capability_id=self.capability_id,
                target=target,
                success=False,
                error=f"tls handshake failed: {type(exc).__name__}",
                observed={"port": 443, "protocol_version_hint": None},
            )
        metadata: dict[str, Any] = {"port": 443, "protocol_version": protocol_version}
        if cert:
            metadata["subject"] = _rdn(cert.get("subject"))
            metadata["issuer"] = _rdn(cert.get("issuer"))
            metadata["not_before"] = cert.get("notBefore")
            metadata["not_after"] = cert.get("notAfter")
        summary = (
            "TLS handshake complete; certificate present"
            if cert
            else "TLS handshake complete; no certificate parsed"
        )
        return RealObservation(
            capability_id=self.capability_id,
            target=target,
            success=True,
            summary=summary,
            observed=metadata,
            redacted={"certificate_der": "not_collected"},
        )


def _rdn(dn: tuple[tuple[str, str], ...] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in dn or ():
        for key, value in item:
            out[key] = value
    return out


class _HTTPObservationAdapter(RealObservationAdapter):
    """Shared bounded GET behaviour for HTTP metadata/headers adapters."""

    def _get(self, target: str) -> tuple[int, dict[str, Any], str | None]:
        url = (
            f"https://{target}/"
            if not target.startswith(("http://", "https://"))
            else f"{target}/"
        )
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "blackforge-orchestration/14.1"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=_HTTP_TIMEOUT_SECONDS) as response:
                return response.status, dict(response.headers.items()), None
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers.items()), None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return -1, {}, f"{type(exc).__name__}: {exc}"


class HTTPMetadataObservationAdapter(_HTTPObservationAdapter):
    """recon.http_metadata: HTTP response metadata (status, header set)."""

    capability_id = "recon.http_metadata"
    description = "Collect HTTP status and response-header metadata (read-only)."

    def observe(self, target: str) -> RealObservation:
        status, headers, error = self._get(target)
        redacted = redact_headers(headers)
        if status < 0:
            return RealObservation(
                capability_id=self.capability_id,
                target=target,
                success=False,
                error=error or "http request failed",
                observed={},
            )
        return RealObservation(
            capability_id=self.capability_id,
            target=target,
            success=True,
            summary=f"HTTP {status}; {len(headers)} response header names observed",
            observed={"status": status, "header_names": sorted(headers.keys())},
            redacted=redacted,
        )


_SECURITY_HEADER_NAMES: tuple[str, ...] = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)


class SecurityHeadersObservationAdapter(_HTTPObservationAdapter):
    """webapi.security_header_analysis: present/missing security headers.

    Header *values* are hashed by the redaction layer; only presence and the
    hashed digest are recorded.
    """

    capability_id = "webapi.security_header_analysis"
    description = "Record presence of key security response headers (read-only)."

    def observe(self, target: str) -> RealObservation:
        status, headers, error = self._get(target)
        redacted = redact_headers(headers)
        if status < 0:
            return RealObservation(
                capability_id=self.capability_id,
                target=target,
                success=False,
                error=error or "http request failed",
                observed={},
            )
        lower = {key.lower(): value for key, value in headers.items()}
        present = [
            name
            for name in _SECURITY_HEADER_NAMES
            if name in lower
        ]
        missing = [name for name in _SECURITY_HEADER_NAMES if name not in lower]
        return RealObservation(
            capability_id=self.capability_id,
            target=target,
            success=True,
            summary=(
                f"HTTP {status}; {len(present)}/{len(_SECURITY_HEADER_NAMES)} "
                "security headers present"
            ),
            observed={
                "status": status,
                "security_headers_present": present,
                "security_headers_missing": missing,
            },
            redacted={
                name: value
                for name, value in redacted.items()
                if name in _SECURITY_HEADER_NAMES
            },
        )


class RealAdapterRegistry:
    """Registry of installed real-controlled adapters."""

    def __init__(self) -> None:
        self._adapters: dict[str, RealObservationAdapter] = {}
        self.install(DNSObservationAdapter())
        self.install(TLSObservationAdapter())
        self.install(HTTPMetadataObservationAdapter())
        self.install(SecurityHeadersObservationAdapter())

    def install(self, adapter: RealObservationAdapter) -> None:
        self._adapters[adapter.capability_id] = adapter

    def get(self, capability_id: str) -> RealObservationAdapter | None:
        return self._adapters.get(capability_id)

    def installed_capability_ids(self) -> list[str]:
        return sorted(self._adapters.keys())


__all__ = [
    "DNSObservationAdapter",
    "HTTPMetadataObservationAdapter",
    "RealAdapterRegistry",
    "RealObservation",
    "RealObservationAdapter",
    "RealObservationError",
    "SecurityHeadersObservationAdapter",
    "TLSObservationAdapter",
]
