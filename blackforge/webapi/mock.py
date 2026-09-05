from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.parse import urlparse

from blackforge.webapi.models import WebApiMode
from blackforge.webapi.redaction import redact_headers, redact_secret


def _cookie_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


_DEMO_WEB: dict[str, dict[str, Any]] = {
    "web.example.com": {
        "ip": "192.0.2.20",
        "url": "https://web.example.com/",
        "title": "Example Web Server",
        "technologies": ["nginx", "php", "jquery"],
        "scheme": "https",
        "tls_version": "TLSv1.3",
        "endpoints": [
            {
                "url": "https://web.example.com/",
                "method": "GET",
                "status_code": 200,
                "content_type": "text/html",
                "title": "Example Web Server",
            },
            {
                "url": "https://web.example.com/login",
                "method": "GET",
                "status_code": 200,
                "content_type": "text/html",
                "title": "Sign in",
            },
            {
                "url": "https://web.example.com/api/v1/status",
                "method": "GET",
                "status_code": 200,
                "content_type": "application/json",
                "title": None,
            },
        ],
        "api_surfaces": [
            {
                "url": "https://web.example.com/api/v1/",
                "style": "rest",
                "kind": "internal_rest_api",
                "docs_url": None,
            }
        ],
        "security_headers": {
            "Server": "nginx/1.24.0",
            "X-Powered-By": "PHP/8.1",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        },
        "cookies": [
            {
                "name": "session",
                "value_hashed": _cookie_hash("mock-session-web"),
                "domain": "web.example.com",
                "path": "/",
                "flags": ["HttpOnly", "Secure", "SameSite=Lax"],
            }
        ],
        "cors": None,
        "auth_schemes": [
            {
                "scheme": "session_cookie",
                "type": "cookie_session",
                "parameter_name": "session",
            }
        ],
        "openapi": None,
        "graphql": None,
        "request_responses": [
            {
                "url": "https://web.example.com/",
                "method": "GET",
                "status_code": 200,
                "http_version": "HTTP/2",
                "tls_version": "TLSv1.3",
                "server_header": "nginx/1.24.0",
                "content_type": "text/html",
                "rtt_ms": 12,
                "headers": {
                    "Server": "nginx/1.24.0",
                    "Content-Type": "text/html; charset=UTF-8",
                },
            },
            {
                "url": "https://web.example.com/login",
                "method": "GET",
                "status_code": 200,
                "http_version": "HTTP/2",
                "tls_version": "TLSv1.3",
                "server_header": "nginx/1.24.0",
                "content_type": "text/html",
                "rtt_ms": 14,
                "headers": {
                    "Server": "nginx/1.24.0",
                    "Set-Cookie": (
                    f"session=REDACTED:{redact_secret('mock-session-web')[:16]}"),
                },
            },
        ],
    },
    "www.example.com": {
        "ip": "192.0.2.21",
        "url": "https://www.example.com/",
        "title": "Example Home",
        "technologies": ["nginx"],
        "scheme": "https",
        "tls_version": "TLSv1.3",
        "endpoints": [
            {
                "url": "https://www.example.com/",
                "method": "GET",
                "status_code": 200,
                "content_type": "text/html",
                "title": "Example Home",
            },
            {
                "url": "https://www.example.com/account",
                "method": "GET",
                "status_code": 200,
                "content_type": "text/html",
                "title": "My account",
            },
        ],
        "api_surfaces": [],
        "security_headers": {"Server": "nginx/1.24.0"},
        "cookies": [
            {
                "name": "session",
                "value_hashed": _cookie_hash("mock-session-www"),
                "domain": "www.example.com",
                "path": "/",
                "flags": ["HttpOnly", "Secure"],
            }
        ],
        "cors": {
            "allow_origins": ["https://web.example.com"],
            "allow_methods": ["GET"],
            "allow_headers": [],
            "expose_headers": [],
            "allow_credentials": True,
        },
        "auth_schemes": [
            {
                "scheme": "session_cookie",
                "type": "cookie_session",
                "parameter_name": "session",
            }
        ],
        "openapi": None,
        "graphql": None,
        "request_responses": [
            {
                "url": "https://www.example.com/",
                "method": "GET",
                "status_code": 200,
                "http_version": "HTTP/2",
                "tls_version": "TLSv1.3",
                "server_header": "nginx/1.24.0",
                "content_type": "text/html",
                "rtt_ms": 16,
                "headers": {"Server": "nginx/1.24.0"},
            }
        ],
    },
    "api.example.com": {
        "ip": "192.0.2.22",
        "url": "https://api.example.com/",
        "title": "Example API",
        "technologies": ["express", "nginx"],
        "scheme": "https",
        "tls_version": "TLSv1.3",
        "endpoints": [
            {
                "url": "https://api.example.com/v1/health",
                "method": "GET",
                "status_code": 200,
                "content_type": "application/json",
                "title": None,
            },
            {
                "url": "https://api.example.com/v1/users",
                "method": "GET",
                "status_code": 200,
                "content_type": "application/json",
                "title": None,
            },
            {
                "url": "https://api.example.com/v2/status",
                "method": "GET",
                "status_code": 200,
                "content_type": "application/json",
                "title": None,
            },
        ],
        "api_surfaces": [
            {
                "url": "https://api.example.com/openapi.json",
                "style": "rest",
                "kind": "openapi",
                "docs_url": "https://api.example.com/docs",
            },
            {
                "url": "https://api.example.com/swagger.json",
                "style": "rest",
                "kind": "swagger",
                "docs_url": None,
            },
            {
                "url": "https://api.example.com/graphql",
                "style": "graphql",
                "kind": "graphql",
                "docs_url": None,
            },
        ],
        "security_headers": {
            "Server": "nginx/1.24.0",
            "Content-Type": "application/json",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'",
        },
        "cookies": [],
        "cors": {
            "allow_origins": ["https://web.example.com"],
            "allow_methods": ["GET", "POST"],
            "allow_headers": ["Authorization", "Content-Type"],
            "expose_headers": ["X-Rate-Limit"],
            "allow_credentials": False,
        },
        "auth_schemes": [
            {
                "scheme": "bearer",
                "type": "oauth_bearer",
                "parameter_name": "Authorization",
            }
        ],
        "openapi": {
            "openapi": "3.0.3",
            "info": {"title": "Example API", "version": "1.0.0"},
            "paths": {
                "/v1/health": {
                    "get": {"operationId": "getHealth", "responses": {"200": {}}}
                },
                "/v1/users": {
                    "get": {
                        "operationId": "listUsers",
                        "security": [{"bearerAuth": []}],
                        "responses": {"200": {}},
                    }
                },
                "/v1/token": {
                    "post": {
                        "operationId": "issueToken",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "username": {"type": "string"},
                                            "password": {
                                                "type": "string",
                                            "example": (
                                                f"REDACTED:{redact_secret('mock-password')[:16]}"
                                            ),
                                        },
                                        },
                                    }
                                }
                            }
                        },
                        "responses": {"200": {}},
                    }
                },
            },
            "components": {
                "securitySchemes": {
                    "bearerAuth": {"type": "http", "scheme": "bearer"},
                    "apiKeyAuth": {
                        "type": "apiKey",
                        "in": "header",
                        "name": "X-API-Key",
                    },
                }
            },
        },
        "graphql": {
            "endpoint": "https://api.example.com/graphql",
            "introspection": True,
            "types": 14,
            "operation_names": ["health", "user"],
            "queries": ["health", "user"],
            "mutations": [],
        },
        "request_responses": [
            {
                "url": "https://api.example.com/v1/health",
                "method": "GET",
                "status_code": 200,
                "http_version": "HTTP/2",
                "tls_version": "TLSv1.3",
                "server_header": "nginx/1.24.0",
                "content_type": "application/json",
                "rtt_ms": 9,
                "headers": {
                    "Server": "nginx/1.24.0",
                    "Content-Type": "application/json",
                    "Authorization": (
                        f"Bearer REDACTED:{redact_secret('mock-bearer')[:16]}"
                    ),
                },
            },
            {
                "url": "https://api.example.com/v1/users",
                "method": "GET",
                "status_code": 200,
                "http_version": "HTTP/2",
                "tls_version": "TLSv1.3",
                "server_header": "nginx/1.24.0",
                "content_type": "application/json",
                "rtt_ms": 11,
                "headers": {
                    "Server": "nginx/1.24.0",
                    "Authorization": (
                        f"Bearer REDACTED:{redact_secret('mock-bearer')[:16]}"
                    ),
                },
            },
            {
                "url": "https://api.example.com/v1/users",
                "method": "GET",
                "status_code": 401,
                "http_version": "HTTP/2",
                "tls_version": "TLSv1.3",
                "server_header": "nginx/1.24.0",
                "content_type": "application/json",
                "rtt_ms": 8,
                "headers": {"Server": "nginx/1.24.0"},
            },
        ],
    },
    "mail.example.com": {
        "ip": "198.51.100.23",
        "url": None,
        "title": None,
        "technologies": [],
        "web": False,
        "note": "no web application observed",
    },
    "unreachable.example.com": {
        "ip": "203.0.113.40",
        "error": {"kind": "connection_refused", "message": "connection refused"},
    },
    "throttled.example.com": {
        "ip": "203.0.113.41",
        "error": {"kind": "rate_limited", "message": "rate limited"},
    },
}


def _fallback_record(target: str) -> dict[str, Any]:
    digest = hashlib.sha256(target.encode("utf-8")).hexdigest()
    host_normalized = target.strip().lower()
    services = ["webserver"] if int(digest[:1], 16) % 2 else ["nginx"]
    base = f"https://{host_normalized}/"
    return {
        "ip": f"192.0.2.{(int(digest[:2], 16) % 254) + 1}",
        "url": base,
        "title": f"{host_normalized} default page",
        "technologies": services,
        "scheme": "https",
        "tls_version": "TLSv1.3",
        "endpoints": [
            {
                "url": base,
                "method": "GET",
                "status_code": 200,
                "content_type": "text/html",
                "title": f"{host_normalized} default page",
            }
        ],
        "api_surfaces": [],
        "security_headers": {"Server": "WebServer/1.0"},
        "cookies": [],
        "cors": None,
        "auth_schemes": [],
        "openapi": None,
        "graphql": None,
        "request_responses": [
            {
                "url": base,
                "method": "GET",
                "status_code": 200,
                "http_version": "HTTP/1.1",
                "tls_version": "TLSv1.3",
                "server_header": "WebServer/1.0",
                "content_type": "text/html",
                "rtt_ms": 20,
                "headers": {"Server": "WebServer/1.0"},
            }
        ],
    }


class MockWebTransport:
    """Deterministic, mock-only web/api observation source.

    Never touches the network and never returns real credentials: cookie
    values, authorization headers, and API keys are produced as one-way
    digests (``REDACTED:<hash>``) so raw artifacts are safe to persist.
    Known demo hosts use a fixed dataset; any other host yields a stable
    hash-derived dataset so behaviour is reproducible across runs.
    """

    def __init__(self) -> None:
        self._records: dict[str, dict[str, Any]] = dict(_DEMO_WEB)

    def _record_for(self, target: str) -> dict[str, Any]:
        host = self._host_for(target)
        record = self._records.get(host)
        if record is not None:
            return {"host": host, **record}
        for name, rec in self._records.items():
            if rec.get("ip") == host:
                return {"host": name, **rec}
        return {"host": host, **_fallback_record(host)}

    @staticmethod
    def _host_for(target: str) -> str:
        text = target.strip()
        if "://" in text:
            return urlparse(text).netloc.rsplit(":", 1)[0]
        return text

    # ------------------------------------------------------------------ #
    # Capability-backed observation methods
    # ------------------------------------------------------------------ #
    def discover_web_applications(
        self, target: str, mode: WebApiMode = WebApiMode.ACTIVE
    ) -> str:
        record = self._record_for(target)
        if not record.get("url"):
            return self._emit(
                "discover_web_applications",
                target,
                mode,
                record,
                {"apps": [], "note": record.get("note", "no web application observed")},
            )
        return self._emit(
            "discover_web_applications",
            target,
            mode,
            record,
            {
                "apps": [
                    {
                        "url": record["url"],
                        "host": record["host"],
                        "title": record.get("title"),
                        "technologies": list(record.get("technologies", [])),
                        "scheme": record.get("scheme", "https"),
                        "tls_version": record.get("tls_version"),
                    }
                ]
            },
        )

    def enumerate_endpoints(
        self, target: str, mode: WebApiMode = WebApiMode.ACTIVE
    ) -> str:
        record = self._record_for(target)
        if not record.get("url"):
            return self._emit(
                "enumerate_endpoints",
                target,
                mode,
                record,
                {"endpoints": [], "note": record.get("note")},
            )
        endpoints = [
            {**ep, "host": record["host"], "scheme": record.get("scheme", "https")}
            for ep in record.get("endpoints", [])
        ]
        return self._emit(
            "enumerate_endpoints", target, mode, record, {"endpoints": endpoints}
        )

    def identify_api_surfaces(
        self, target: str, mode: WebApiMode = WebApiMode.PASSIVE
    ) -> str:
        record = self._record_for(target)
        surfaces = [
            {**s, "host": record["host"]}
            for s in record.get("api_surfaces", [])
        ]
        return self._emit(
            "identify_api_surfaces", target, mode, record, {"api_surfaces": surfaces}
        )

    def inspect_security_headers(
        self, target: str, mode: WebApiMode = WebApiMode.PASSIVE
    ) -> str:
        record = self._record_for(target)
        url = record.get("url") or f"https://{record['host']}/"
        return self._emit(
            "inspect_security_headers",
            target,
            mode,
            record,
            {
                "observed_url": url,
                "scheme": record.get("scheme", "https"),
                "tls_version": record.get("tls_version"),
                "headers": dict(record.get("security_headers", {})),
            },
        )

    def inspect_cookies(
        self, target: str, mode: WebApiMode = WebApiMode.PASSIVE
    ) -> str:
        record = self._record_for(target)
        url = record.get("url") or f"https://{record['host']}/"
        return self._emit(
            "inspect_cookies",
            target,
            mode,
            record,
            {
                "observed_url": url,
                "cookies": [dict(c) for c in record.get("cookies", [])],
            },
        )

    def analyze_cors(
        self, target: str, mode: WebApiMode = WebApiMode.PASSIVE
    ) -> str:
        record = self._record_for(target)
        url = record.get("url") or f"https://{record['host']}/"
        cors = record.get("cors")
        return self._emit(
            "analyze_cors",
            target,
            mode,
            record,
            {
                "observed_url": url,
                "cors": dict(cors) if cors is not None else None,
            },
        )

    def inspect_authentication(
        self, target: str, mode: WebApiMode = WebApiMode.PASSIVE
    ) -> str:
        record = self._record_for(target)
        url = record.get("url") or f"https://{record['host']}/"
        return self._emit(
            "inspect_authentication",
            target,
            mode,
            record,
            {
                "observed_url": url,
                "schemes": [dict(s) for s in record.get("auth_schemes", [])],
            },
        )

    def parse_openapi(
        self, target: str, mode: WebApiMode = WebApiMode.PASSIVE
    ) -> str:
        record = self._record_for(target)
        url = record.get("url") or f"https://{record['host']}/"
        return self._emit(
            "parse_openapi",
            target,
            mode,
            record,
            {
                "observed_url": url,
                "document": (
                    json.loads(json.dumps(record["openapi"]))
                    if record.get("openapi") is not None
                    else None
                ),
            },
        )

    def discover_graphql(
        self, target: str, mode: WebApiMode = WebApiMode.PASSIVE
    ) -> str:
        record = self._record_for(target)
        url = record.get("url") or f"https://{record['host']}/"
        return self._emit(
            "discover_graphql",
            target,
            mode,
            record,
            {
                "observed_url": url,
                "graphql": (
                    dict(record["graphql"])
                    if record.get("graphql") is not None
                    else None
                ),
            },
        )

    def observe_request_response(
        self, target: str, mode: WebApiMode = WebApiMode.ACTIVE
    ) -> str:
        record = self._record_for(target)
        url = record.get("url") or f"https://{record['host']}/"
        responses = [
            {
                **r,
                "host": record["host"],
                "headers": redact_headers(r.get("headers", {})),
            }
            for r in record.get("request_responses", [])
        ]
        return self._emit(
            "observe_request_response",
            target,
            mode,
            record,
            {"observed_url": url, "responses": responses},
        )

    def _emit(
        self,
        tool: str,
        target: str,
        mode: WebApiMode,
        record: dict[str, Any],
        payload: dict[str, Any],
    ) -> str:
        document: dict[str, Any] = {
            "tool": tool,
            "mode": mode.value,
            "target": target,
            "host": record["host"],
        }
        if "error" in record:
            document["error"] = dict(record["error"])
            return json.dumps(document, sort_keys=True)
        document.update(payload)
        return json.dumps(document, sort_keys=True)
