from __future__ import annotations

import ipaddress
from enum import Enum

from blackforge.core.types import TargetType


class AddressType(str, Enum):
    """Explicitly classified address classes.

    Classification is deterministic and never *assumed*: IP literals are
    checked against known private ranges (RFC 1918, CGNAT, link-local, etc.)
    via the standard library; hostnames fall back to documented internal
    suffixes. A private/internal address is always modeled as
    ``PRIVATE_ADDRESS`` regardless of how it appears — format alone never
    promotes an address to public.
    """

    PUBLIC_ADDRESS = "public_address"
    PRIVATE_ADDRESS = "private_address"


_INTERNAL_HOST_SUFFIXES = (
    ".internal.example",
    ".internal",
    ".local",
    ".lan",
)

_DOCUMENTATION_NETS = (
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
)

_CGNAT_NETS = (
    ipaddress.IPv4Network("100.64.0.0/10"),
)


def _is_documentation(address: ipaddress._BaseAddress) -> bool:
    return any(address in net for net in _DOCUMENTATION_NETS)


def _is_cgnat(address: ipaddress._BaseAddress) -> bool:
    return any(address in net for net in _CGNAT_NETS)


def classify_address(value: str) -> AddressType:
    """Deterministically classify ``value`` as public or private.

    * ``10/8``, ``172.16/12``, ``192.168/16``, ``100.64/10`` (CGNAT),
      ``169.254/16`` (link-local), loopback, and multicast classify as
      ``PRIVATE_ADDRESS``.
    * Documentation ranges (``192.0.2/24``, ``198.51.100/24``,
      ``203.0.113/24``) are treated as ``PUBLIC_ADDRESS``: they are
      externally-referenced in fixtures to stand in for routable host
      addresses and are never part of a real internal network.
    * Hostnames carrying a documented internal suffix (``.internal.example``,
      ``.internal``, ``.local``, ``.lan``) or an ``internal`` hostname label
      classify as ``PRIVATE_ADDRESS``; all other hostnames are treated as
      ``PUBLIC_ADDRESS`` (external-facing).
    """
    host = str(value).strip().lower()
    if ":" in host and host.count(":") == 1:
        host = host.rsplit(":", 1)[0].strip()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        for suffix in _INTERNAL_HOST_SUFFIXES:
            if host.endswith(suffix):
                return AddressType.PRIVATE_ADDRESS
        if "internal" in host.split("."):
            return AddressType.PRIVATE_ADDRESS
        return AddressType.PUBLIC_ADDRESS
    if _is_documentation(address):
        return AddressType.PUBLIC_ADDRESS
    if _is_cgnat(address):
        return AddressType.PRIVATE_ADDRESS
    if address.is_loopback or address.is_link_local or address.is_multicast:
        return AddressType.PRIVATE_ADDRESS
    if address.is_private or address.is_reserved:
        return AddressType.PRIVATE_ADDRESS
    return AddressType.PUBLIC_ADDRESS


def address_target_type(value: str) -> TargetType:
    """Map a classified address to the address-observation target type.

    Public addresses are DOMAIN-class targets (reachable surfaces) while
    private addresses are ASSET-class (internal surfaces) — matching the
    scope model's distinction between externally reachable and internal
    surfaces.
    """
    if classify_address(value) is AddressType.PUBLIC_ADDRESS:
        return TargetType.DOMAIN
    return TargetType.ASSET


__all__ = [
    "AddressType",
    "address_target_type",
    "classify_address",
]
