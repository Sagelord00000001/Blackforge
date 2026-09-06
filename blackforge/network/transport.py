from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from blackforge.network.models import NetworkMode, PortState

# Deterministic demo topology (all addresses reserved TEST-NET-2 192.0.2.0/24).
# Five functional hosts, three network devices, one quiet host, and a bounded
# set of error hosts whose outcomes are fixed fixture data.
_DEMO_HOSTS: dict[str, dict[str, Any]] = {
    "web.internal.example": {
        "ip": "192.0.2.10",
        "domain": "internal.example",
        "role": "web_server",
        "operating_system": "linux",
        "network_device": False,
        "tcp": {
            22: {"state": "open", "service": "ssh", "version": "OpenSSH_8.9",
                 "banner": "SSH-2.0-OpenSSH_8.9"},
            80: {"state": "open", "service": "http", "version": "nginx/1.24.0",
                 "banner": "HTTP/1.1 200 OK", "banner_is_json": False},
            443: {"state": "open", "service": "https", "version": "nginx/1.24.0",
                  "banner": "TLSv1.3", "banner_is_json": False},
        },
        "udp": {},
        "applications": {
            22: "ssh_server",
            80: "landing",
            443: "web_console",
        },
        "tls": {
            443: {
                "version": "TLSv1.3",
                "certificate_subject": "CN=web.internal.example",
                "certificate_issuer": "CN=Blackforge Demo CA",
                "certificate_expiry": "2027-01-01",
                "cipher_suite": "TLS_AES_256_GCM_SHA384",
            }
        },
        "interfaces": [
            {"name": "eth0", "exposed": True, "public": True},
            {"name": "lo", "exposed": False, "public": False},
        ],
        "networks": ["internal"],
    },
    "api.internal.example": {
        "ip": "192.0.2.11",
        "domain": "internal.example",
        "role": "api_server",
        "operating_system": "linux",
        "network_device": False,
        "tcp": {
            443: {"state": "open", "service": "https", "version": "nginx/1.24.0",
                  "banner": "TLSv1.3", "banner_is_json": False},
            8080: {
                "state": "open",
                "service": "api",
                "version": "api-gateway/2.1",
                "banner": json.dumps(
                    {
                        "service": "inventory_api",
                        "version": "2.1",
                        "access_token": "demo-token-123",
                        "api_key": "demo-key-abc",
                        "credentials": {"api_password": "top-secret"},
                    }
                ),
                "banner_is_json": True,
            },
        },
        "udp": {},
        "applications": {443: "api_gateway", 8080: "inventory_api"},
        "tls": {
            443: {
                "version": "TLSv1.3",
                "certificate_subject": "CN=api.internal.example",
                "certificate_issuer": "CN=Blackforge Demo CA",
                "certificate_expiry": "2027-01-01",
                "cipher_suite": "TLS_AES_256_GCM_SHA384",
            }
        },
        "interfaces": [
            {"name": "eth0", "exposed": True, "public": True},
            {"name": "lo", "exposed": False, "public": False},
        ],
        "networks": ["internal"],
    },
    "dns.internal.example": {
        "ip": "192.0.2.12",
        "domain": "internal.example",
        "role": "dns_server",
        "operating_system": "linux",
        "network_device": False,
        "tcp": {},
        "udp": {53: {"state": "open", "service": "dns", "version": "bind/9.18"}},
        "applications": {},
        "tls": {},
        "dns_records": [
            {"name": "web.internal.example", "record_type": "A",
             "value": "192.0.2.10", "ttl": 300},
            {"name": "api.internal.example", "record_type": "A",
             "value": "192.0.2.11", "ttl": 300},
            {"name": "mail.internal.example", "record_type": "A",
             "value": "192.0.2.13", "ttl": 300},
            {"name": "dns.internal.example", "record_type": "A",
             "value": "192.0.2.12", "ttl": 86400},
            {"name": "www.internal.example", "record_type": "CNAME",
             "value": "web.internal.example", "ttl": 3600},
            {"name": "mail.internal.example", "record_type": "MX",
             "value": "10 mail.internal.example", "ttl": 3600},
            {"name": "internal.example", "record_type": "NS",
             "value": "ns1.internal.example", "ttl": 86400},
            {"name": "internal.example", "record_type": "TXT",
             "value": "v=spf1 -all", "ttl": 86400},
        ],
        "interfaces": [
            {"name": "eth0", "exposed": True, "public": True},
            {"name": "lo", "exposed": False, "public": False},
        ],
        "networks": ["internal"],
    },
    "mail.internal.example": {
        "ip": "192.0.2.13",
        "domain": "internal.example",
        "role": "mail_server",
        "operating_system": "linux",
        "network_device": False,
        "tcp": {
            25: {"state": "open", "service": "smtp", "version": "postfix/3.7",
                 "banner": "220 mail.internal.example ESMTP Postfix",
                 "banner_is_json": False},
        },
        "udp": {},
        "applications": {25: "mail_server"},
        "tls": {},
        "interfaces": [
            {"name": "eth0", "exposed": True, "public": True},
            {"name": "lo", "exposed": False, "public": False},
        ],
        "networks": ["internal"],
    },
    "quiet.internal.example": {
        "ip": "192.0.2.14",
        "domain": "internal.example",
        "role": "internal_asset",
        "operating_system": "linux",
        "network_device": False,
        "tcp": {},
        "udp": {},
        "applications": {},
        "tls": {},
        "interfaces": [
            {"name": "eth0", "exposed": False, "public": False},
        ],
        "networks": ["internal"],
    },
    # Infrastructure devices modeled through infrastructure_modeling only.
    "gateway.internal.example": {
        "ip": "192.0.2.1",
        "domain": "internal.example",
        "role": "gateway",
        "operating_system": "routeros",
        "network_device": True,
        "interfaces": [],
        "networks": ["internal"],
    },
    "core-switch.internal.example": {
        "ip": "192.0.2.2",
        "domain": "internal.example",
        "role": "core_switch",
        "operating_system": "switchos",
        "network_device": True,
        "interfaces": [],
        "networks": ["internal"],
    },
    "firewall.internal.example": {
        "ip": "192.0.2.3",
        "domain": "internal.example",
        "role": "firewall",
        "operating_system": "firewallos",
        "network_device": True,
        "interfaces": [],
        "networks": ["internal"],
    },
}

# Fixed negative-outcome hosts (deterministic fixture data).
_ERROR_HOSTS: dict[str, dict[str, Any]] = {
    "refused.internal.example": {
        "ip": "192.0.2.21",
        "error": {"kind": "connection_refused", "message": "connection refused"},
    },
    "slow.internal.example": {
        "ip": "192.0.2.22",
        "error": {"kind": "timeout", "message": "connection timed out"},
    },
    "throttled.internal.example": {
        "ip": "192.0.2.23",
        "error": {"kind": "rate_limited", "message": "probe rate limit exceeded"},
    },
    "filtered.internal.example": {
        "ip": "192.0.2.24",
        "error": {"kind": "filtered", "message": "no response; traffic filtered"},
    },
    "malformed.internal.example": {
        "ip": "192.0.2.25",
        "error": {"kind": "malformed_response", "message": "malformed probe response"},
    },
    "unauthorized.internal.example": {
        "ip": "192.0.2.26",
        "error": {"kind": "unauthorized", "message": "probe not authorized"},
    },
    "others.internal.example": {
        "ip": "192.0.2.27",
        "error": {"kind": "out_of_scope", "message": "target outside mission scope"},
    },
}

_FUNCTIONAL_HOSTS = (
    "web.internal.example",
    "api.internal.example",
    "dns.internal.example",
    "mail.internal.example",
    "quiet.internal.example",
)
_DEVICE_HOSTS = (
    "gateway.internal.example",
    "core-switch.internal.example",
    "firewall.internal.example",
)

_MAX_BANNER_CHARS = 200


def _error_record_for_none(target: str) -> dict[str, Any]:
    return {
        "error": {
            "kind": "connection_refused",
            "message": "no network record modeled for this target",
        }
    }


class MockNetworkTransport:
    """Deterministic, mock-only network observation source.

    Never touches the network: all probing iterates over a fixed in-process
    dataset of the ``internal.example`` demo topology. Port probing is bounded,
    UDP is limited to the single DNS service in the mock, banners are capped
    and redacted, and TLS/DNS/exposure/infrastructure outcomes are fixture
    data. Known error hosts surface structured negative outcomes; any other
    host yields a stable ``connection_refused`` error document.
    """

    def __init__(self) -> None:
        self._records: dict[str, dict[str, Any]] = {
            **{name: dict(record) for name, record in _DEMO_HOSTS.items()},
            **{name: dict(record) for name, record in _ERROR_HOSTS.items()},
        }
        self._by_ip: dict[str, str] = {
            record["ip"]: name for name, record in self._records.items()
        }

    def _host_for(self, target: str) -> str:
        text = target.strip()
        if text.startswith("http://") or text.startswith("https://"):
            host = urlparse(text).netloc
        else:
            host = text
        if host.startswith("[") and "]" in host:
            host = host.split("]", 1)[0].strip("[]")
        if host.count(":") == 1:
            candidate, _, suffix = host.rpartition(":")
            if suffix.isdigit():
                host = candidate
        return host

    def _record_for(self, target: str) -> tuple[str, dict[str, Any]]:
        host = self._host_for(target)
        if host in self._records:
            return host, dict(self._records[host])
        via_ip = self._by_ip.get(host)
        if via_ip is not None:
            return via_ip, dict(self._records[via_ip])
        return host, _error_record_for_none(host)

    def _hosts_for_target(self, target: str) -> list[str]:
        """Functional hosts for a target: one host, or all hosts in a CIDR."""
        text = target.strip()
        if "/" in text:
            network = self._network_for(text)
            return [name for name in _FUNCTIONAL_HOSTS if self._ip_in(network, name)]
        host, _ = self._record_for(target)
        return [host]

    def _network_for(self, target: str):
        import ipaddress

        try:
            return ipaddress.ip_network(target, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid CIDR target: {target}") from exc

    @staticmethod
    def _ip_in(network, hostname: str) -> bool:
        import ipaddress

        record = _DEMO_HOSTS.get(hostname)
        if record is None:
            return False
        try:
            return ipaddress.ip_address(record["ip"]) in network
        except ValueError:
            return False

    def _document(
        self,
        tool: str,
        target: str,
        mode: NetworkMode,
        host: str,
        record: dict[str, Any],
    ) -> dict[str, Any]:
        return {"tool": tool, "mode": mode.value, "target": target, "host": host}

    def _error_output(
        self, tool: str, target: str, host: str, record: dict[str, Any]
    ) -> str:
        doc = {
            "tool": tool,
            "mode": "active",
            "target": target,
            "host": host,
        }
        doc["error"] = dict(record.get("error", {}))
        return json.dumps(doc, sort_keys=True)

    def _base(
        self,
        tool: str,
        target: str,
        mode: NetworkMode,
        record: dict[str, Any],
        host: str,
    ) -> dict[str, Any] | None:
        if "error" in record:
            return None
        doc = self._document(tool, target, mode, host, record)
        doc["ip"] = record.get("ip")
        return doc

    def _emit(self, doc: dict[str, Any]) -> str:
        return json.dumps(doc, sort_keys=True)

    def _ports_for(
        self, record: dict[str, Any], ports: list[int] | None, transport: str = "tcp"
    ) -> list[int]:
        table = dict(record.get(transport, {}))
        if ports:
            return [p for p in ports if 1 <= p <= 65535]
        return sorted(int(p) for p in table)

    @staticmethod
    def _port_state(record: dict[str, Any], port: int, transport: str = "tcp") -> PortState:
        table = dict(record.get(transport, {}))
        entry = table.get(port)
        if entry is None:
            return PortState.CLOSED
        return PortState(str(entry.get("state", "unknown")))

    def _host_doc(
        self, base: dict[str, Any], record: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "kind": "host",
            "host": base["host"],
            "ip": record["ip"],
            "domain": record.get("domain"),
            "is_network_device": bool(record.get("network_device", False)),
            "role": record.get("role"),
            "operating_system": record.get("operating_system"),
        }

    # ------------------------------------------------------------------
    # Typed observation tools
    # ------------------------------------------------------------------
    def discover_hosts(
        self, target: str, mode: NetworkMode = NetworkMode.ACTIVE
    ) -> str:
        hosts = self._hosts_for_target(target)
        output: list[dict[str, Any]] = []
        for hostname in hosts:
            record = self._records.get(hostname)
            if record is None:
                _, record = self._record_for(hostname)
            base = self._base("discover_hosts", target, mode, record, hostname)
            if base is None:
                return self._error_output("discover_hosts", target, hostname, record)
            output.append(self._host_doc(base, record))
        doc = {
            "tool": "discover_hosts",
            "mode": mode.value,
            "target": target,
            "observations": output,
        }
        if not output:
            doc["note"] = "no hosts discovered in the target network"
        return self._emit(doc)

    def discover_ports(
        self,
        target: str,
        mode: NetworkMode = NetworkMode.ACTIVE,
        ports: list[int] | None = None,
    ) -> str:
        hosts = self._hosts_for_target(target)
        output: list[dict[str, Any]] = []
        for hostname in hosts:
            record = self._records.get(hostname)
            if record is None:
                _, record = self._record_for(hostname)
            base = self._base("discover_ports", target, mode, record, hostname)
            if base is None:
                return self._error_output("discover_ports", target, hostname, record)
            for port in self._ports_for(record, ports):
                output.append(
                    {
                        "kind": "port",
                        "host": hostname,
                        "ip": record["ip"],
                        "port": port,
                        "transport": "tcp",
                        "state": self._port_state(record, port).value,
                        "service": record.get("tcp", {}).get(port, {}).get("service"),
                    }
                )
        doc = {
            "tool": "discover_ports",
            "mode": mode.value,
            "target": target,
            "observations": output,
        }
        if not output:
            doc["note"] = "no open or documented ports for the target"
        return self._emit(doc)

    def observe_services(
        self,
        target: str,
        mode: NetworkMode = NetworkMode.ACTIVE,
        ports: list[int] | None = None,
    ) -> str:
        host, record = self._record_for(target)
        base = self._base("observe_services", target, mode, record, host)
        if base is None:
            return self._error_output("observe_services", target, host, record)
        output: list[dict[str, Any]] = []
        for transport in ("tcp", "udp"):
            for port in self._ports_for(record, ports, transport):
                entry = record.get(transport, {}).get(port)
                if entry is None or entry.get("state") != "open":
                    continue
                output.append(
                    {
                        "kind": "service",
                        "host": host,
                        "ip": record["ip"],
                        "port": port,
                        "transport": transport,
                        "service": entry["service"],
                        "version": entry.get("version"),
                    }
                )
        doc = {
            "tool": "observe_services",
            "mode": mode.value,
            "target": target,
            "host": host,
            "observations": output,
        }
        return self._emit(doc)

    def identify_protocols(
        self,
        target: str,
        mode: NetworkMode = NetworkMode.ACTIVE,
        ports: list[int] | None = None,
    ) -> str:
        host, record = self._record_for(target)
        base = self._base("identify_protocols", target, mode, record, host)
        if base is None:
            return self._error_output("identify_protocols", target, host, record)
        output: list[dict[str, Any]] = []
        for transport in ("tcp", "udp"):
            for port in self._ports_for(record, ports, transport):
                table = record.get(transport, {})
                entry = table.get(port)
                if entry is None or entry.get("state") != "open":
                    continue
                service = entry.get("service", "")
                output.append(
                    {
                        "kind": "protocol",
                        "host": host,
                        "ip": record["ip"],
                        "port": port,
                        "transport": transport,
                        "protocol": _protocol_for(transport, port, service),
                    }
                )
        doc = {
            "tool": "identify_protocols",
            "mode": mode.value,
            "target": target,
            "host": host,
            "observations": output,
        }
        return self._emit(doc)

    def observe_banners(
        self,
        target: str,
        mode: NetworkMode = NetworkMode.ACTIVE,
        ports: list[int] | None = None,
    ) -> str:
        host, record = self._record_for(target)
        base = self._base("observe_banners", target, mode, record, host)
        if base is None:
            return self._error_output("observe_banners", target, host, record)
        output: list[dict[str, Any]] = []
        for transport in ("tcp", "udp"):
            for port in self._ports_for(record, ports, transport):
                entry = record.get(transport, {}).get(port)
                if entry is None or entry.get("state") != "open":
                    continue
                banner = entry.get("banner")
                if banner is None:
                    continue
                text = str(banner)
                output.append(
                    {
                        "kind": "banner",
                        "host": host,
                        "ip": record["ip"],
                        "port": port,
                        "transport": transport,
                        "service": entry.get("service"),
                        "banner": text,
                        "banner_is_json": bool(entry.get("banner_is_json", False)),
                        "truncated": len(text) > _MAX_BANNER_CHARS,
                    }
                )
        doc = {
            "tool": "observe_banners",
            "mode": mode.value,
            "target": target,
            "host": host,
            "observations": output,
        }
        return self._emit(doc)

    def observe_dns(
        self, target: str, mode: NetworkMode = NetworkMode.ACTIVE
    ) -> str:
        host, record = self._record_for(target)
        base = self._base("observe_dns", target, mode, record, host)
        if base is None:
            return self._error_output("observe_dns", target, host, record)
        output: list[dict[str, Any]] = []
        for entry in record.get("dns_records", []):
            output.append(
                {
                    "kind": "dns",
                    "server": host,
                    "name": entry["name"],
                    "record_type": entry["record_type"],
                    "value": entry["value"],
                    "ttl": int(entry.get("ttl", 0)),
                }
            )
        doc = {
            "tool": "observe_dns",
            "mode": mode.value,
            "target": target,
            "host": host,
            "observations": output,
        }
        return self._emit(doc)

    def observe_tls(
        self,
        target: str,
        mode: NetworkMode = NetworkMode.ACTIVE,
        ports: list[int] | None = None,
    ) -> str:
        host, record = self._record_for(target)
        base = self._base("observe_tls", target, mode, record, host)
        if base is None:
            return self._error_output("observe_tls", target, host, record)
        output: list[dict[str, Any]] = []
        for port in self._ports_for(record, ports):
            entry = record.get("tls", {}).get(port)
            if entry is None:
                continue
            output.append(
                {
                    "kind": "tls",
                    "host": host,
                    "ip": record["ip"],
                    "port": port,
                    "version": entry.get("version"),
                    "certificate_subject": entry.get("certificate_subject"),
                    "certificate_issuer": entry.get("certificate_issuer"),
                    "certificate_expiry": entry.get("certificate_expiry"),
                    "cipher_suite": entry.get("cipher_suite"),
                }
            )
        doc = {
            "tool": "observe_tls",
            "mode": mode.value,
            "target": target,
            "host": host,
            "observations": output,
        }
        if not output:
            doc["note"] = "no TLS services observed on the target"
        return self._emit(doc)

    def analyze_exposure(
        self, target: str, mode: NetworkMode = NetworkMode.ACTIVE
    ) -> str:
        host, record = self._record_for(target)
        base = self._base("analyze_exposure", target, mode, record, host)
        if base is None:
            return self._error_output("analyze_exposure", target, host, record)
        output: list[dict[str, Any]] = []
        for interface in record.get("interfaces", []):
            output.append(
                {
                    "kind": "exposure",
                    "host": host,
                    "ip": record["ip"],
                    "interface": interface.get("name"),
                    "exposed": bool(interface.get("exposed", False)),
                    "public": bool(interface.get("public", False)),
                }
            )
        doc = {
            "tool": "analyze_exposure",
            "mode": mode.value,
            "target": target,
            "host": host,
            "observations": output,
        }
        return self._emit(doc)

    def model_infrastructure(
        self, target: str, mode: NetworkMode = NetworkMode.ACTIVE
    ) -> str:
        hosts = self._hosts_for_target(target)
        if hosts:
            host = hosts[0]
        else:
            host, _ = self._record_for(target)
        record = self._records.get(host)
        if record is None:
            _, record = self._record_for(host)
        base = self._base("model_infrastructure", target, mode, record, host)
        if base is None:
            return self._error_output("model_infrastructure", target, host, record)
        output: list[dict[str, Any]] = []
        hostname = base["host"]
        networks = list(record.get("networks", []))
        for network in networks:
            output.append(
                {
                    "kind": "infrastructure",
                    "host": hostname,
                    "infrastructure": network,
                    "role": record.get("role"),
                    "network_device": bool(record.get("network_device", False)),
                }
            )
            for device in _DEVICE_HOSTS:
                device_record = self._records[device]
                if network in device_record.get("networks", []):
                    output.append(
                        {
                            "kind": "infrastructure",
                            "host": device,
                            "infrastructure": network,
                            "role": device_record.get("role"),
                            "network_device": True,
                        }
                    )
        doc = {
            "tool": "model_infrastructure",
            "mode": mode.value,
            "target": target,
            "host": hostname,
            "observations": output,
        }
        return self._emit(doc)

    def correlate_service_applications(
        self, target: str, mode: NetworkMode = NetworkMode.ACTIVE
    ) -> str:
        host, record = self._record_for(target)
        base = self._base(
            "correlate_service_applications", target, mode, record, host
        )
        if base is None:
            return self._error_output(
                "correlate_service_applications", target, host, record
            )
        output: list[dict[str, Any]] = []
        for transport in ("tcp", "udp"):
            for port, entry in record.get(transport, {}).items():
                if entry.get("state") != "open":
                    continue
                application = record.get("applications", {}).get(int(port))
                if application is None:
                    continue
                output.append(
                    {
                        "kind": "service_application",
                        "host": host,
                        "ip": record["ip"],
                        "service": entry["service"],
                        "application": application,
                        "transport": transport,
                        "port": int(port),
                    }
                )
        doc = {
            "tool": "correlate_service_applications",
            "mode": mode.value,
            "target": target,
            "host": host,
            "observations": output,
        }
        return self._emit(doc)

    def collect_network_evidence(
        self, target: str, mode: NetworkMode = NetworkMode.ACTIVE
    ) -> str:
        host, record = self._record_for(target)
        base = self._base("collect_network_evidence", target, mode, record, host)
        if base is None:
            return self._error_output(
                "collect_network_evidence", target, host, record
            )
        open_tcp = [p for p, e in record.get("tcp", {}).items()
                    if e.get("state") == "open"]
        open_udp = [p for p, e in record.get("udp", {}).items()
                    if e.get("state") == "open"]
        output = [
            {
                "kind": "network_evidence",
                "host": host,
                "ip": record["ip"],
                "detail": (
                    f"open_tcp={len(open_tcp)} open_udp={len(open_udp)} "
                    f"tls={len(record.get('tls', {}))} "
                    f"dns_records={len(record.get('dns_records', []))}"
                ),
            }
        ]
        doc = {
            "tool": "collect_network_evidence",
            "mode": mode.value,
            "target": target,
            "host": host,
            "observations": output,
            "note": (
                "network evidence harvested deterministically from the mock "
                "internal.example topology"
            ),
        }
        return self._emit(doc)


def _protocol_for(transport: str, port: int, service: str) -> str:
    """Deterministic protocol label for a port/service in the mock dataset."""
    if transport == "udp":
        return "dns"
    return {"ssh": "ssh", "http": "http", "https": "tls", "api": "http",
            "smtp": "smtp"}.get(service, service)


__all__ = ["MockNetworkTransport"]
