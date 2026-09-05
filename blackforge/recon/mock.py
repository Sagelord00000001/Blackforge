from __future__ import annotations

import hashlib
import json
from typing import Any

from blackforge.recon.models import ReconMode

_POOL_PORTS = [22, 80, 443, 8080, 8443]
_POOL_SERVICES = {
    22: "ssh",
    80: "http",
    443: "https",
    8080: "http-alt",
    8443: "https-alt",
}
_POOL_TECHNOLOGIES = [
    ("apache", "server"),
    ("nginx", "server"),
    ("php", "programming_language"),
    ("jquery", "javascript_library"),
    ("express", "javascript_framework"),
]

_DEMO_HOSTS: dict[str, dict[str, Any]] = {
    "web.example.com": {
        "ip": "192.0.2.10",
        "os": "linux",
        "neighbours": ["www.example.com", "api.example.com"],
        "services": [
{
                "port": 22,
                "protocol": "tcp",
                "service": "ssh",
                "version": "OpenSSH_8.2p1",
                "banner": None,
                "state": "open"
            },{
                "port": 80,
                "protocol": "tcp",
                "service": "http",
                "version": "1.1",
                "banner": "Apache/2.4.41 (Ubuntu)",
                "state": "open"
            },{
                "port": 443,
                "protocol": "tcp",
                "service": "https",
                "version": "1.1",
                "banner": "nginx/1.24.0",
                "state": "open"
            },        ],
        "technologies": [
{
                "name": "nginx",
                "category": "server",
                "version": "1.24.0",
                "port": 443,
                "confidence": "high"
            },{
                "name": "php",
                "category": "programming_language",
                "version": "8.1",
                "port": 80,
                "confidence": "medium"
            },{
                "name": "jquery",
                "category": "javascript_library",
                "version": "3.6.0",
                "port": 80,
                "confidence": "medium"
            },        ],
        "dns": [
            {"type": "A", "answers": ["192.0.2.10"]},
            {"type": "AAAA", "answers": ["2001:db8::10"]},
            {"type": "CNAME", "answers": ["web.example.com."]},
        ],
        "http": {
            "url": "https://web.example.com/",
            "port": 443,
            "status_code": 200,
            "server": "nginx/1.24.0",
            "title": "Example Web Server",
            "redirect_location": None,
            "headers": {
                "Server": "nginx/1.24.0",
                "Content-Type": "text/html; charset=UTF-8",
                "X-Powered-By": "PHP/8.1",
            },
        },
    },
    "www.example.com": {
        "ip": "192.0.2.12",
        "os": "linux",
        "neighbours": [],
        "services": [
{
                "port": 443,
                "protocol": "tcp",
                "service": "https",
                "version": "1.1",
                "banner": "nginx/1.24.0",
                "state": "open"
            },        ],
        "technologies": [
{
                "name": "nginx",
                "category": "server",
                "version": "1.24.0",
                "port": 443,
                "confidence": "high"
            },        ],
        "dns": [
            {"type": "A", "answers": ["192.0.2.12"]},
        ],
        "http": {
            "url": "https://www.example.com/",
            "port": 443,
            "status_code": 200,
            "server": "nginx/1.24.0",
            "title": "Example Home",
            "redirect_location": None,
            "headers": {"Server": "nginx/1.24.0"},
        },
    },
    "api.example.com": {
        "ip": "192.0.2.13",
        "os": "linux",
        "neighbours": [],
        "services": [
{
                "port": 443,
                "protocol": "tcp",
                "service": "https",
                "version": "1.1",
                "banner": "nginx/1.24.0",
                "state": "open"
            },{
                "port": 8443,
                "protocol": "tcp",
                "service": "https-alt",
                "version": None,
                "banner": None,
                "state": "open"
            },        ],
        "technologies": [
{
                "name": "express",
                "category": "javascript_framework",
                "version": "4.18.2",
                "port": 443,
                "confidence": "medium"
            },        ],
        "dns": [
            {"type": "A", "answers": ["192.0.2.13"]},
        ],
        "http": {
            "url": "https://api.example.com/v1/health",
            "port": 443,
            "status_code": 200,
            "server": "nginx/1.24.0",
            "title": None,
            "redirect_location": None,
            "headers": {"Server": "nginx/1.24.0", "Content-Type": "application/json"},
        },
    },
    "mail.example.com": {
        "ip": "198.51.100.21",
        "os": "linux",
        "neighbours": [],
        "services": [
{
                "port": 25,
                "protocol": "tcp",
                "service": "smtp",
                "version": "Postfix",
                "banner": "220 mail.example.com ESMTP Postfix",
                "state": "open"
            },{
                "port": 587,
                "protocol": "tcp",
                "service": "submission",
                "version": "Postfix",
                "banner": None,
                "state": "open"
            },        ],
        "technologies": [
{
                "name": "postfix",
                "category": "mail_server",
                "version": "3.4",
                "port": 25,
                "confidence": "high"
            },        ],
        "dns": [
            {"type": "A", "answers": ["198.51.100.21"]},
            {"type": "MX", "answers": ["mail.example.com."]},
        ],
        "http": None,
    },
    "db.example.com": {
        "ip": "203.0.113.30",
        "os": "linux",
        "neighbours": [],
        "services": [
{
                "port": 5432,
                "protocol": "tcp",
                "service": "postgresql",
                "version": "15.2",
                "banner": None,
                "state": "open"
            },{
                "port": 3306,
                "protocol": "tcp",
                "service": "mysql",
                "version": "8.0.32",
                "banner": None,
                "state": "filtered"
            },        ],
        "technologies": [
{
                "name": "postgresql",
                "category": "database",
                "version": "15.2",
                "port": 5432,
                "confidence": "high"
            },        ],
        "dns": [
            {"type": "A", "answers": ["203.0.113.30"]},
        ],
        "http": None,
    },
}

_RANGE_CIDR = "192.0.2.0/24"


def _fallback_record(target: str) -> dict[str, Any]:
    digest = hashlib.sha256(target.encode("utf-8")).hexdigest()
    ip_last = (int(digest[:2], 16) % 254) + 1
    ip = f"192.0.2.{ip_last}"
    slot = int(digest[2:4], 16)
    port_count = 1 + (slot % 3)
    start = slot % len(_POOL_PORTS)
    ports = sorted(
        _POOL_PORTS[(start + i) % len(_POOL_PORTS)] for i in range(port_count)
    )
    services = [
        {
            "port": p,
            "protocol": "tcp",
            "service": _POOL_SERVICES[p],
            "version": None,
            "banner": None,
            "state": "open",
        }
        for p in ports
    ]
    tech_count = min(port_count, len(_POOL_TECHNOLOGIES))
    tech_start = (slot // 4) % len(_POOL_TECHNOLOGIES)
    technologies = [
        {
            "name": _POOL_TECHNOLOGIES[(tech_start + i) % len(_POOL_TECHNOLOGIES)][0],
            "category": _POOL_TECHNOLOGIES[(tech_start + i) % len(_POOL_TECHNOLOGIES)][1],
            "version": None,
            "port": ports[0],
            "confidence": "medium",
        }
        for i in range(tech_count)
    ]
    http = None
    if 443 in ports or 80 in ports:
        http_port = 443 if 443 in ports else 80
        http = {
            "url": f"{'https' if http_port == 443 else 'http'}://{target}/",
            "port": http_port,
            "status_code": 200,
            "server": "WebServer/1.0",
            "title": f"{target} default page",
            "redirect_location": None,
            "headers": {"Server": "WebServer/1.0"},
        }
    return {
        "host": target,
        "ip": ip,
        "os": "unknown",
        "neighbours": [],
        "services": services,
        "technologies": technologies,
        "dns": [{"type": "A", "answers": [ip]}],
        "http": http,
    }


class MockReconTool:
    """Deterministic, mock-only reconnaissance source.

    Never touches the network. Returns raw JSON *text* (simulating untrusted
    tool output) that normalization adapters must parse and validate. Known
    demo hosts use a fixed dataset; any other target yields a stable
    hash-derived dataset so behaviour is reproducible across runs.
    """

    def __init__(self) -> None:
        self._records: dict[str, dict[str, Any]] = dict(_DEMO_HOSTS)

    def _record_for(self, target: str) -> dict[str, Any]:
        key = target.strip()
        record = self._records.get(key)
        if record is not None:
            return {"host": key, **record}
        for host, rec in self._records.items():
            if rec["ip"] == key:
                return {"host": host, **rec}
        return _fallback_record(key)

    def discover_hosts(
        self, target: str, mode: ReconMode = ReconMode.ACTIVE
    ) -> str:
        record = self._record_for(target)
        hostnames = [record["host"]] + record.get("neighbours", [])
        hosts = []
        for name in hostnames:
            rec = self._record_for(name)
            hosts.append(
                {
                    "host": rec["host"],
                    "ip_addresses": [rec["ip"]],
                    "os": rec["os"],
                    "status": "up",
                    "notes": ["mock_observed"],
                }
            )
        networks = (
            [
                {
                    "cidr": _RANGE_CIDR,
                    "name": "doc-net",
                    "hosts": [h["host"] for h in hosts],
                    "exposure": "internet-facing",
                }
            ]
            if mode == ReconMode.PASSIVE and record["ip"].startswith("192.0.2.")
            else []
        )
        return json.dumps(
            {
                "tool": "discover_hosts",
                "mode": mode.value,
                "target": target,
                "hosts": hosts,
                "networks": networks,
            },
            sort_keys=True,
        )

    def enumerate_services(
        self, target: str, mode: ReconMode = ReconMode.ACTIVE
    ) -> str:
        record = self._record_for(target)
        services = list(record["services"])
        if mode == ReconMode.PASSIVE:
            services = [{**s, "state": "inferred"} for s in services]
        return json.dumps(
            {
                "tool": "enumerate_services",
                "mode": mode.value,
                "target": target,
                "host": record["host"],
                "services": services,
            },
            sort_keys=True,
        )

    def identify_technologies(
        self, target: str, mode: ReconMode = ReconMode.PASSIVE
    ) -> str:
        record = self._record_for(target)
        return json.dumps(
            {
                "tool": "identify_technologies",
                "mode": mode.value,
                "target": target,
                "host": record["host"],
                "technologies": record["technologies"],
            },
            sort_keys=True,
        )

    def inspect_dns(
        self, target: str, mode: ReconMode = ReconMode.PASSIVE
    ) -> str:
        record = self._record_for(target)
        records = list(record["dns"])
        if not any(r["type"] == "A" for r in records):
            records = [{"type": "A", "answers": [record["ip"]]}] + records
        return json.dumps(
            {
                "tool": "inspect_dns",
                "mode": mode.value,
                "target": target,
                "host": record["host"],
                "records": records,
            },
            sort_keys=True,
        )

    def inspect_http_metadata(
        self, target: str, mode: ReconMode = ReconMode.ACTIVE
    ) -> str:
        record = self._record_for(target)
        return json.dumps(
            {
                "tool": "inspect_http_metadata",
                "mode": mode.value,
                "target": target,
                "host": record["host"],
                "http": record["http"],
            },
            sort_keys=True,
        )

    def inspect_tls(
        self, target: str, mode: ReconMode = ReconMode.PASSIVE
    ) -> str:
        record = self._record_for(target)
        ports = [s["port"] for s in record["services"] if s["port"] in (443, 8443)]
        entries = []
        for port in ports:
            entries.append(
                {
                    "host": record["host"],
                    "port": port,
                    "certificate": {
                        "subject": f"CN={record['host']}",
                        "issuer": "CN=Example Root CA",
                        "not_before": "2024-01-01T00:00:00Z",
                        "not_after": "2026-01-01T00:00:00Z",
                    },
                    "tls_version": "TLSv1.3",
                    "cipher": "TLS_AES_128_GCM_SHA256",
                    "sni_required": True,
                    "hostname_matches": True,
                }
            )
        return json.dumps(
            {
                "tool": "inspect_tls",
                "mode": mode.value,
                "target": target,
                "host": record["host"],
                "certificates": entries,
            },
            sort_keys=True,
        )
