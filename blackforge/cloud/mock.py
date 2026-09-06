from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Deterministic mock multi-provider cloud estate (all fixture data).
#
# The mock models three fictional AELIONIX test estates — AWS (an account),
# Azure (a subscription), and GCP (a project). Every value is synthetic: fake
# account ids, ``*-test`` regions, ``pay.example`` image names, and
# ``*.external.test`` endpoints. Nothing here requires a real cloud provider
# and nothing in here is ever queried or mutated at runtime.
#
# Credential-like fields below (``secret_value``, ``access_key_id``,
# ``private_key``, ``connection_string``) exist ONLY to prove the redaction
# boundary: they are stripped at the artifact boundary and never reach
# observations, evidence, or the world model.
# ---------------------------------------------------------------------------

CLOUD_ACCOUNTS: dict[str, dict[str, Any]] = {
    "aws": {"aelionix-aws-test": {"account_id": "111111111111"}},
    "azure": {
        "aelionix-azure-test": {
            "account_id": "22222222-2222-2222-2222-222222222222"
        }
    },
    "gcp": {"aelionix-gcp-test": {"account_id": "933333333333"}},
}

CLOUD_ESTATES: dict[str, dict[str, dict[str, Any]]] = {
    "aws": {
        "aelionix-aws-test": {
            "account": {
                "account": "aelionix-aws-test",
                "account_id": "111111111111",
                "regions": ["us-test-1", "eu-test-1"],
            },
            "projects": [
                {
                    "project": "aelionix-prod-ou",
                    "project_type": "organizational_unit",
                },
                {
                    "project": "aelionix-dev-ou",
                    "project_type": "organizational_unit",
                },
            ],
            "resources": {
                "compute": [
                    {
                        "name": "web-01",
                        "instance_type": "t3.test",
                        "state": "running",
                        "public_endpoint": "https://web-01.external.test",
                        "private_endpoints": ["10.0.0.10"],
                        "tags": {"owner": "platform", "tier": "web"},
                        "guarded_admin": {"private_key": "demo-private-key-0000"},
                    },
                    {
                        "name": "db-01",
                        "instance_type": "db.test",
                        "state": "running",
                        "region": "eu-test-1",
                        "private_endpoints": ["10.0.1.20"],
                        "tags": {"owner": "platform"},
                    },
                ],
                "storage": [
                    {
                        "name": "public-bucket",
                        "storage_type": "object",
                        "public_access": True,
                        "access_key": "demo-access-key-0000",
                    },
                    {
                        "name": "private-bucket",
                        "storage_type": "object",
                        "public_access": False,
                    },
                    {
                        "name": "backups-disk",
                        "storage_type": "block",
                        "public_access": False,
                    },
                ],
                "database": [
                    {
                        "name": "orders",
                        "engine": "postgres.test",
                        "public_access": False,
                        "connection_string": (
                            "postgres://svc:demo-db-password-0000@"
                            "orders.internal.example:5432/orders"
                        ),
                    }
                ],
                "network": [
                    {
                        "name": "vpc-main",
                        "network_type": "virtual_network",
                        "ingress_allowed": False,
                        "attached_cidrs": ["10.0.0.0/16"],
                    },
                    {
                        "name": "web-subnet",
                        "network_type": "subnet",
                        "ingress_allowed": False,
                        "attached_cidrs": ["10.0.0.0/24"],
                    },
                    {
                        "name": "web-sg",
                        "network_type": "security_group",
                        "ingress_allowed": True,
                        "attached_cidrs": ["0.0.0.0/0"],
                    },
                    {
                        "name": "dmz-fw",
                        "network_type": "firewall_rule",
                        "ingress_allowed": True,
                        "attached_cidrs": ["0.0.0.0/0"],
                    },
                    {
                        "name": "public-elb",
                        "network_type": "load_balancer",
                        "ingress_allowed": True,
                        "attached_cidrs": ["0.0.0.0/0"],
                    },
                ],
                "cluster": [
                    {
                        "name": "aelionix-cluster",
                        "version": "v1.test",
                        "node_count": 3,
                    }
                ],
                "container": [
                    {
                        "name": "web-01-pod",
                        "image": "pay.example/web:1.2.3",
                        "state": "running",
                        "exposed_ports": ["443"],
                        "cluster": "aelionix-cluster",
                    },
                    {
                        "name": "worker-01",
                        "image": "pay.example/worker:0.9.0",
                        "state": "running",
                        "exposed_ports": [],
                        "cluster": "aelionix-cluster",
                    },
                ],
            },
            "iam_identities": [
                {
                    "identity": "alice-cloud",
                    "principal_type": "user",
                    "enabled": True,
                    "mfa_enabled": True,
                    "privileges": ["deploy"],
                },
                {
                    "identity": "build-service-cloud",
                    "principal_type": "service_account",
                    "enabled": True,
                    "mfa_enabled": True,
                    "privileges": ["deploy", "read_secrets"],
                },
                {
                    "identity": "legacy-robot",
                    "principal_type": "robot",
                    "enabled": True,
                    "mfa_enabled": False,
                    "privileges": ["read"],
                    "access_key_id": "AKIA-TEST-0000",
                },
            ],
            "iam_roles": [
                {"role": "web-service-role", "description": "runtime credentials for web tier"},
                {"role": "backup-role", "description": "snapshot orchestration"},
                {"role": "admin-role", "description": "broad administrative rights"},
            ],
            "iam_permissions": [
                {
                    "permission": "s3:read",
                    "effect": "allow",
                    "action": "s3:GetObject",
                },
                {
                    "permission": "ec2:describe",
                    "effect": "allow",
                    "action": "ec2:DescribeInstances",
                },
                {
                    "permission": "rds:modify",
                    "effect": "allow",
                    "action": "rds:ModifyDBInstance",
                },
                {
                    "permission": "secretsmanager:getsecretvalue",
                    "effect": "allow",
                    "action": "secretsmanager:GetSecretValue",
                },
                {
                    "permission": "iam:createaccesskey",
                    "effect": "deny",
                    "action": "iam:CreateAccessKey",
                },
            ],
            "secret_references": [
                {
                    "name": "api-gateway-key",
                    "secret_kind": "api_key",
                    "reference": (
                        "arn:aws:secretsmanager:us-test-1:111111111111:"
                        "secret:api-gateway-key"
                    ),
                    "secret_value": "demo-aws-secret-0000",
                },
                {
                    "name": "db-master-credential",
                    "secret_kind": "password",
                    "reference": (
                        "arn:aws:secretsmanager:us-test-1:111111111111:"
                        "secret:db-master-credential"
                    ),
                    "secret_value": "demo-db-password-0000",
                },
                {
                    "name": "ec2-deploy-key",
                    "secret_kind": "ssh_key",
                    "reference": (
                        "arn:aws:secretsmanager:us-test-1:111111111111:"
                        "secret:ec2-deploy-key"
                    ),
                    "secret_value": "demo-ssh-key-0000",
                },
            ],
            "exposures": [
                {
                    "resource_type": "compute_instance",
                    "resource": "web-01",
                    "exposed": True,
                    "endpoint": "https://web-01.external.test",
                },
                {
                    "resource_type": "storage_bucket",
                    "resource": "public-bucket",
                    "exposed": True,
                    "endpoint": "https://public-bucket.external.test",
                },
                {
                    "resource_type": "storage_bucket",
                    "resource": "private-bucket",
                    "exposed": False,
                },
                {
                    "resource_type": "compute_instance",
                    "resource": "db-01",
                    "exposed": False,
                },
                {
                    "resource_type": "load_balancer",
                    "resource": "public-elb",
                    "exposed": True,
                    "endpoint": "https://public-elb.external.test",
                },
            ],
            "security_configuration": [
                {
                    "entity_type": "account",
                    "entity": "aelionix-aws-test",
                    "item": "cloudtrail_logging",
                    "value": "enabled",
                    "source": "provider",
                    "resolved": True,
                },
                {
                    "entity_type": "account",
                    "entity": "aelionix-aws-test",
                    "item": "cloudtrail_logging",
                    "value": "disabled",
                    "source": "tag_feed",
                    "resolved": True,
                },
                {
                    "entity_type": "compute",
                    "entity": "web-01",
                    "item": "instance_metadata_v2",
                    "value": "required",
                    "source": "provider",
                    "resolved": True,
                },
                {
                    "entity_type": "storage",
                    "entity": "public-bucket",
                    "item": "server_side_encryption",
                    "value": "enabled",
                    "source": "provider",
                    "resolved": True,
                },
                {
                    "entity_type": "storage",
                    "entity": "backups-disk",
                    "item": "server_side_encryption",
                    "value": "disabled",
                    "source": "provider",
                    "resolved": True,
                },
                {
                    "entity_type": "iam_identity",
                    "entity": "legacy-robot",
                    "item": "mfa_required",
                    "value": "false",
                    "source": "provider",
                    "resolved": True,
                },
                {
                    "entity_type": "iam_role",
                    "entity": "backup-role",
                    "item": "managed_by",
                    "value": "ghost-suite",
                    "source": "tag_feed",
                    "resolved": False,
                },
            ],
            "relationships": [
                {
                    "relationship_type": "uses",
                    "source_type": "compute_instance",
                    "source": "web-01",
                    "target_type": "storage_bucket",
                    "target": "public-bucket",
                },
                {
                    "relationship_type": "depends_on",
                    "source_type": "compute_instance",
                    "source": "web-01",
                    "target_type": "database",
                    "target": "orders",
                },
                {
                    "relationship_type": "connects_to",
                    "source_type": "compute_instance",
                    "source": "web-01",
                    "target_type": "subnet",
                    "target": "web-subnet",
                },
                {
                    "relationship_type": "applies_to",
                    "source_type": "security_group",
                    "source": "web-sg",
                    "target_type": "compute_instance",
                    "target": "web-01",
                },
                {
                    "relationship_type": "applies_to",
                    "source_type": "firewall_rule",
                    "source": "dmz-fw",
                    "target_type": "security_group",
                    "target": "web-sg",
                },
                {
                    "relationship_type": "contains",
                    "source_type": "cluster",
                    "source": "aelionix-cluster",
                    "target_type": "container",
                    "target": "web-01-pod",
                },
                {
                    "relationship_type": "contains",
                    "source_type": "cluster",
                    "source": "aelionix-cluster",
                    "target_type": "container",
                    "target": "worker-01",
                },
            ],
            "edges": [
                {
                    "edge": "cdn-edge-main",
                    "edge_kind": "cdn",
                    "domain": "app.aelionix.test",
                    "origin_endpoints": ["10.0.0.10"],
                    "protected_applications": ["web-01"],
                    "directly_reachable_origin": False,
                    "note": "app.aelionix.test terminates TLS at the CDN edge",
                },
                {
                    "edge": "fw-edge-dmz",
                    "edge_kind": "waf",
                    "domain": "admin.aelionix.test",
                    "origin_endpoints": ["10.0.0.10"],
                    "protected_applications": ["web-01"],
                    "directly_reachable_origin": False,
                },
            ],
            "origin_candidates": [
                {
                    "domain": "app.aelionix.test",
                    "candidate_address": "10.0.0.10",
                    "candidate_endpoint": "https://app.aelionix.test",
                    "source_category": "edge_config",
                    "evidence_ids": ["mock-ev-edge-cdn-main"],
                    "correlation_reasons": [
                        "cdn origin matches web-01 private endpoint",
                        "tls terminates only at the edge",
                    ],
                    "confidence_label": "high",
                    "evidence_status": "inferred",
                    "validation_status": "unvalidated",
                    "authorization_requirements": [
                        "authorized origin validation required before interaction"
                    ],
                },
                {
                    "domain": "app.aelionix.test",
                    "candidate_address": "203.0.113.10",
                    "candidate_endpoint": "http://203.0.113.10:8080",
                    "source_category": "external_exposure_feed",
                    "evidence_ids": ["mock-ev-exposure-feed-01"],
                    "correlation_reasons": [
                        "external feed claims a directly reachable public "
                        "origin for the app domain"
                    ],
                    "confidence_label": "low",
                    "evidence_status": "hypothesized",
                    "validation_status": "unvalidated",
                    "authorization_requirements": [
                        "authorized validation required; feed claim unconfirmed"
                    ],
                },
                {
                    "domain": "orders.internal.aelionix.test",
                    "candidate_address": "10.0.1.20",
                    "candidate_endpoint": "orders.internal.aelionix.test:5432",
                    "source_category": "internal_service",
                    "evidence_ids": ["mock-ev-internal-service-feed"],
                    "correlation_reasons": [
                        "internal service registry lists the orders endpoint"
                    ],
                    "confidence_label": "high",
                    "evidence_status": "observed",
                    "validation_status": "unvalidated",
                    "authorization_requirements": [
                        "internal service validation restricted to authorized missions"
                    ],
                },
                {
                    "domain": "api.aelionix.test",
                    "candidate_address": "10.0.1.20",
                    "candidate_endpoint": "https://api.aelionix.test",
                    "source_category": "edge_config",
                    "evidence_ids": ["mock-ev-edge-fw-api"],
                    "correlation_reasons": [
                        "waf-fronted api route maps to the internal api pool"
                    ],
                    "confidence_label": "medium",
                    "evidence_status": "inferred",
                    "validation_status": "unvalidated",
                    "authorization_requirements": [
                        "authorized origin validation required before interaction"
                    ],
                },
            ],
            "transport_security": [
                {
                    "endpoint": "app.aelionix.test",
                    "tls_enforced": True,
                    "tls_version": "TLS1.3",
                    "certificate_valid": True,
                    "source": "provider",
                },
                {
                    "endpoint": "app.aelionix.test",
                    "tls_enforced": False,
                    "tls_version": "TLS1.0",
                    "certificate_valid": False,
                    "source": "external_feed",
                },
                {
                    "endpoint": "api.aelionix.test",
                    "tls_enforced": True,
                    "tls_version": "TLS1.3",
                    "certificate_valid": True,
                    "source": "provider",
                },
                {
                    "endpoint": "web-01.external.test",
                    "tls_enforced": False,
                    "tls_version": "TLS1.0",
                    "certificate_valid": False,
                    "source": "external_feed",
                },
            ],
        }
    },
    "azure": {
        "aelionix-azure-test": {
            "account": {
                "account": "aelionix-azure-test",
                "account_id": "22222222-2222-2222-2222-222222222222",
                "regions": ["us-test-central", "eu-test-west"],
            },
            "projects": [
                {"project": "rg-platform", "project_type": "resource_group"},
                {"project": "rg-data", "project_type": "resource_group"},
            ],
            "resources": {
                "compute": [
                    {
                        "name": "vm-01",
                        "instance_type": "standard_d2s.test",
                        "state": "running",
                        "private_endpoints": ["10.1.0.10"],
                    },
                    {
                        "name": "vm-02",
                        "instance_type": "standard_b1s.test",
                        "state": "running",
                        "public_endpoint": "https://vm-02.external.test",
                        "private_endpoints": ["10.1.0.11"],
                    },
                ],
                "storage": [
                    {
                        "name": "blob-assets",
                        "storage_type": "object",
                        "public_access": False,
                    }
                ],
                "database": [
                    {
                        "name": "web-app-db",
                        "engine": "sqlserver.test",
                        "public_access": False,
                    }
                ],
                "network": [
                    {
                        "name": "vnet-main",
                        "network_type": "virtual_network",
                        "ingress_allowed": False,
                        "attached_cidrs": ["10.1.0.0/16"],
                    },
                    {
                        "name": "nsg-web",
                        "network_type": "security_group",
                        "ingress_allowed": True,
                        "attached_cidrs": ["0.0.0.0/0"],
                    },
                ],
                "cluster": [
                    {"name": "aks-test", "version": "1.30.test", "node_count": 2}
                ],
                "container": [
                    {
                        "name": "pod-api",
                        "image": "pay.example/api:2.1.0",
                        "state": "running",
                        "exposed_ports": ["443"],
                        "cluster": "aks-test",
                    }
                ],
            },
            "iam_identities": [
                {
                    "identity": "sp-deploy",
                    "principal_type": "service_account",
                    "enabled": True,
                    "mfa_enabled": True,
                    "privileges": ["deploy"],
                },
                {
                    "identity": "user-portal-admin",
                    "principal_type": "user",
                    "enabled": True,
                    "mfa_enabled": True,
                    "privileges": ["portal_admin"],
                },
            ],
            "iam_roles": [
                {"role": "contributor-role", "description": "subscription contributor"},
                {"role": "reader-role", "description": "subscription reader"},
            ],
            "iam_permissions": [
                {
                    "permission": "storage:read",
                    "effect": "allow",
                    "action": "Microsoft.Storage/storageAccounts/read",
                },
                {
                    "permission": "keyvault:get",
                    "effect": "allow",
                    "action": "Microsoft.KeyVault/vaults/secrets/read",
                },
            ],
            "secret_references": [
                {
                    "name": "kv-api-secret",
                    "secret_kind": "api_key",
                    "reference": (
                        "https://aelionix-vault-test.vault.example/"
                        "secrets/api-secret"
                    ),
                    "secret_value": "demo-azure-secret-0000",
                }
            ],
            "exposures": [
                {
                    "resource_type": "compute_instance",
                    "resource": "vm-02",
                    "exposed": True,
                    "endpoint": "https://vm-02.external.test",
                },
                {
                    "resource_type": "storage_bucket",
                    "resource": "blob-assets",
                    "exposed": False,
                },
            ],
            "security_configuration": [
                {
                    "entity_type": "account",
                    "entity": "aelionix-azure-test",
                    "item": "audit_logging",
                    "value": "enabled",
                    "source": "provider",
                    "resolved": True,
                },
                {
                    "entity_type": "storage",
                    "entity": "blob-assets",
                    "item": "server_side_encryption",
                    "value": "enabled",
                    "source": "provider",
                    "resolved": True,
                },
            ],
            "relationships": [
                {
                    "relationship_type": "uses",
                    "source_type": "compute_instance",
                    "source": "vm-01",
                    "target_type": "storage_bucket",
                    "target": "blob-assets",
                },
                {
                    "relationship_type": "contains",
                    "source_type": "cluster",
                    "source": "aks-test",
                    "target_type": "container",
                    "target": "pod-api",
                },
            ],
            "edges": [
                {
                    "edge": "afd-edge-api",
                    "edge_kind": "cdn",
                    "domain": "api.aelionix.test",
                    "origin_endpoints": ["10.1.0.10"],
                    "protected_applications": ["vm-01"],
                    "directly_reachable_origin": False,
                },
            ],
            "origin_candidates": [
                {
                    "domain": "vm-02.aelionix.test",
                    "candidate_address": "198.51.100.21",
                    "candidate_endpoint": "https://vm-02.external.test",
                    "source_category": "provider_public_endpoint",
                    "evidence_ids": ["mock-ev-vm02-public"],
                    "correlation_reasons": [
                        "vm-02 has a provider-reported public endpoint "
                        "with no edge/ proxy in front"
                    ],
                    "confidence_label": "high",
                    "evidence_status": "observed",
                    "validation_status": "unvalidated",
                    "authorization_requirements": [
                        "requires authorized validation before any interaction"
                    ],
                },
                {
                    "domain": "blob-assets.aelionix.test",
                    "candidate_address": "10.1.0.10",
                    "candidate_endpoint": "blob-assets.aelionix.test:443",
                    "source_category": "internal_service",
                    "evidence_ids": ["mock-ev-azure-internal"],
                    "correlation_reasons": [
                        "internal service registry lists the blob storage endpoint"
                    ],
                    "confidence_label": "medium",
                    "evidence_status": "observed",
                    "validation_status": "unvalidated",
                    "authorization_requirements": [
                        "internal validation restricted to authorized missions"
                    ],
                },
            ],
            "transport_security": [
                {
                    "endpoint": "api.aelionix.test",
                    "tls_enforced": True,
                    "tls_version": "TLS1.3",
                    "certificate_valid": True,
                    "source": "provider",
                },
                {
                    "endpoint": "vm-02.external.test",
                    "tls_enforced": False,
                    "tls_version": "TLS1.2",
                    "certificate_valid": True,
                    "source": "external_feed",
                },
            ],
        }
    },
    "gcp": {
        "aelionix-gcp-test": {
            "account": {
                "account": "aelionix-gcp-test",
                "account_id": "933333333333",
                "regions": ["us-test-central1", "eu-test-west1"],
            },
            "projects": [
                {"project": "aelionix-gcp-test", "project_type": "project"},
            ],
            "resources": {
                "compute": [
                    {
                        "name": "gce-web-01",
                        "instance_type": "e2.test",
                        "state": "running",
                        "public_endpoint": "https://gce-web-01.external.test",
                        "private_endpoints": ["10.2.0.10"],
                    },
                    {
                        "name": "gce-batch-01",
                        "instance_type": "e2.test",
                        "state": "running",
                        "private_endpoints": ["10.2.0.11"],
                    },
                ],
                "storage": [
                    {
                        "name": "gcs-assets",
                        "storage_type": "object",
                        "public_access": True,
                    }
                ],
                "database": [
                    {
                        "name": "cloud-sql-orders",
                        "engine": "mysql.test",
                        "public_access": False,
                    }
                ],
                "network": [
                    {
                        "name": "vpc-test",
                        "network_type": "virtual_network",
                        "ingress_allowed": False,
                        "attached_cidrs": ["10.2.0.0/16"],
                    }
                ],
                "cluster": [
                    {"name": "gke-test", "version": "1.29.test", "node_count": 2}
                ],
                "container": [
                    {
                        "name": "gke-pod-api",
                        "image": "pay.example/api:1.0.0",
                        "state": "running",
                        "exposed_ports": ["443"],
                        "cluster": "gke-test",
                    }
                ],
            },
            "iam_identities": [
                {
                    "identity": "sa-gce",
                    "principal_type": "service_account",
                    "enabled": True,
                    "mfa_enabled": True,
                    "privileges": ["gce_admin"],
                },
                {
                    "identity": "user-analyst",
                    "principal_type": "user",
                    "enabled": True,
                    "mfa_enabled": False,
                    "privileges": ["bq_query"],
                },
            ],
            "iam_roles": [
                {"role": "roles-viewer", "description": "read-only project viewer"},
                {"role": "roles-bigquery", "description": "bigquery job user"},
            ],
            "iam_permissions": [
                {
                    "permission": "gcs:read",
                    "effect": "allow",
                    "action": "storage.objects.get",
                },
                {
                    "permission": "bq:query",
                    "effect": "allow",
                    "action": "bigquery.jobs.create",
                },
            ],
            "secret_references": [
                {
                    "name": "sm-api-key",
                    "secret_kind": "api_key",
                    "reference": "projects/933333333333/secret-manager/sm-api-key",
                    "secret_value": "demo-gcp-secret-0000",
                }
            ],
            "exposures": [
                {
                    "resource_type": "storage_bucket",
                    "resource": "gcs-assets",
                    "exposed": True,
                    "endpoint": "https://storage.external.test/gcs-assets",
                },
                {
                    "resource_type": "compute_instance",
                    "resource": "gce-batch-01",
                    "exposed": False,
                },
            ],
            "security_configuration": [
                {
                    "entity_type": "project",
                    "entity": "aelionix-gcp-test",
                    "item": "os_login",
                    "value": "enabled",
                    "source": "provider",
                    "resolved": True,
                },
                {
                    "entity_type": "compute",
                    "entity": "gce-web-01",
                    "item": "block_project_keys",
                    "value": "disabled",
                    "source": "provider",
                    "resolved": True,
                },
            ],
            "relationships": [
                {
                    "relationship_type": "uses",
                    "source_type": "compute_instance",
                    "source": "gce-web-01",
                    "target_type": "storage_bucket",
                    "target": "gcs-assets",
                },
                {
                    "relationship_type": "contains",
                    "source_type": "cluster",
                    "source": "gke-test",
                    "target_type": "container",
                    "target": "gke-pod-api",
                },
            ],
            "edges": [
                {
                    "edge": "lc-edge-web",
                    "edge_kind": "load_balancer",
                    "domain": "gce-web.aelionix.test",
                    "origin_endpoints": ["10.2.0.10"],
                    "protected_applications": ["gce-web-01"],
                    "directly_reachable_origin": False,
                },
            ],
            "origin_candidates": [
                {
                    "domain": "gce-web.aelionix.test",
                    "candidate_address": "10.2.0.10",
                    "candidate_endpoint": "https://gce-web.aelionix.test",
                    "source_category": "edge_config",
                    "evidence_ids": ["mock-ev-gcp-edge"],
                    "correlation_reasons": [
                        "load balancer backend matches gce-web-01 private endpoint"
                    ],
                    "confidence_label": "high",
                    "evidence_status": "inferred",
                    "validation_status": "unvalidated",
                    "authorization_requirements": [
                        "authorized origin validation required before interaction"
                    ],
                },
                {
                    "domain": "gcs-assets.external.test",
                    "candidate_address": "198.51.100.80",
                    "candidate_endpoint": "https://storage.external.test/gcs-assets",
                    "source_category": "public_reachability_feed",
                    "evidence_ids": ["mock-ev-gcp-gcs"],
                    "correlation_reasons": [
                        "public storage endpoint reported in reachability feed"
                    ],
                    "confidence_label": "medium",
                    "evidence_status": "observed",
                    "validation_status": "unvalidated",
                    "authorization_requirements": [
                        "requires authorized validation before any interaction"
                    ],
                },
            ],
            "transport_security": [
                {
                    "endpoint": "gce-web.aelionix.test",
                    "tls_enforced": True,
                    "tls_version": "TLS1.3",
                    "certificate_valid": True,
                    "source": "provider",
                },
                {
                    "endpoint": "storage.external.test",
                    "tls_enforced": True,
                    "tls_version": "TLS1.3",
                    "certificate_valid": False,
                    "source": "external_feed",
                },
            ],
        }
    },
}

_ERROR_TABLE: dict[str, dict[str, str]] = {
    "aws/snail-account": {
        "kind": "timeout",
        "message": "cloud estate observation timed out",
    },
    "aws/bursty-account": {
        "kind": "rate_limited",
        "message": "cloud estate observation rate limit exceeded",
    },
    "aws/locked-account": {
        "kind": "unauthorized",
        "message": "cloud estate observation not authorized",
    },
    "aws/garbled-account": {
        "kind": "malformed",
        "message": "cloud estate returned a malformed response",
    },
}


def modeled_estate_container_names(provider_value: str) -> list[str]:
    """Deterministic container (account/subscription/project) names."""
    return [name for name in CLOUD_ESTATES.get(provider_value, {})]


__all__ = [
    "CLOUD_ACCOUNTS",
    "CLOUD_ESTATES",
    "_ERROR_TABLE",
    "modeled_estate_container_names",
]
