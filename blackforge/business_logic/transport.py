from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from blackforge.business_logic.models import (
    BusinessLogicMode,
    ReplaySafetyClass,
    ReplaySimulator,
    WorkflowModel,
    WorkflowTransition,
)

_DEMO_ORDER_WORKFLOW: dict[str, Any] = {
    "url": "https://shop.example.com/",
    "ip": "192.0.2.30",
    "workflow": "order_workflow",
    "application": "shop.example.com",
    "description": "Order fulfillment lifecycle: created -> paid -> shipped -> delivered.",
    "initial_state": "created",
    "terminal_states": ["delivered", "cancelled"],
    "states": ["created", "paid", "shipped", "delivered", "cancelled"],
    "actions": [
        "submit_order",
        "process_payment",
        "ship_order",
        "confirm_delivery",
        "cancel_order",
    ],
    "transitions": [
        {
            "action": "submit_order",
            "source_state": "created",
            "target_state": "created",
            "prerequisites": ["created"],
            "note": "order created and remains in the created state",
        },
        {
            "action": "process_payment",
            "source_state": "created",
            "target_state": "paid",
            "prerequisites": ["created"],
            "note": "payment recorded for the created order",
        },
        {
            "action": "ship_order",
            "source_state": "paid",
            "target_state": "shipped",
            "prerequisites": ["paid"],
            "note": "only paid orders ship",
        },
        {
            "action": "confirm_delivery",
            "source_state": "shipped",
            "target_state": "delivered",
            "prerequisites": ["shipped"],
            "note": "delivery confirmed for the shipped order",
        },
        {
            "action": "cancel_order",
            "source_state": "created",
            "target_state": "cancelled",
            "prerequisites": ["created"],
            "note": "only pre-shipment orders cancel",
        },
    ],
    "action_safety": {
        "submit_order": ReplaySafetyClass.PASSIVE.value,
        "process_payment": ReplaySafetyClass.BOUNDED.value,
        "ship_order": ReplaySafetyClass.BOUNDED.value,
        "confirm_delivery": ReplaySafetyClass.PASSIVE.value,
        "cancel_order": ReplaySafetyClass.BOUNDED.value,
    },
    "state_meta": {
        "created": {
            "initial": True,
            "terminal": False,
            "allowed_roles": ["customer", "admin", "warehouse"],
        },
        "paid": {
            "initial": False,
            "terminal": False,
            "allowed_roles": ["customer", "admin", "warehouse"],
        },
        "shipped": {
            "initial": False,
            "terminal": False,
            "allowed_roles": ["admin", "warehouse"],
        },
        "delivered": {
            "initial": False,
            "terminal": True,
            "allowed_roles": ["admin", "warehouse"],
        },
        "cancelled": {
            "initial": False,
            "terminal": True,
            "allowed_roles": ["customer", "admin"],
        },
    },
    "state_transitions": [
        {
            "action": "submit_order",
            "source_state": "created",
            "target_state": "created",
            "direct": True,
            "prerequisite": "created",
            "resource": "orders",
            "anomalous": False,
            "note": "order creation observed",
        },
        {
            "action": "process_payment",
            "source_state": "created",
            "target_state": "paid",
            "direct": True,
            "prerequisite": "created",
            "resource": "orders",
            "anomalous": False,
            "note": "created -> paid observed (order-1001)",
        },
        {
            "action": "ship_order",
            "source_state": "paid",
            "target_state": "shipped",
            "direct": True,
            "prerequisite": "paid",
            "resource": "orders",
            "anomalous": False,
            "note": "paid -> shipped observed (order-1002)",
        },
        {
            "action": "ship_order",
            "source_state": "created",
            "target_state": "shipped",
            "direct": False,
            "prerequisite": "paid",
            "resource": "orders",
            "anomalous": True,
            "note": "created -> shipped observed for order-2001 without payment",
        },
        {
            "action": "confirm_delivery",
            "source_state": "shipped",
            "target_state": "delivered",
            "direct": True,
            "prerequisite": "shipped",
            "resource": "orders",
            "anomalous": False,
            "note": "shipped -> delivered observed (order-1001)",
        },
        {
            "action": "cancel_order",
            "source_state": "created",
            "target_state": "cancelled",
            "direct": True,
            "prerequisite": "created",
            "resource": "orders",
            "anomalous": False,
            "note": "created -> cancelled observed (order-1003)",
        },
    ],
    "business_rules": [
        {
            "rule": "only_paid_orders_ship",
            "description": "A shipment requires a completed payment for the order",
            "enforcement": "broken",
            "observed": True,
            "detail": "order-2001 transitioned created -> shipped without payment",
        },
        {
            "rule": "no_post_shipment_cancel",
            "description": "Cancellation is allowed only before an order ships",
            "enforcement": "enforced",
            "observed": True,
            "detail": "cancel_order denied for shipped order-1001",
        },
        {
            "rule": "payment_requires_created",
            "description": "Payment is accepted only for orders in the created state",
            "enforcement": "enforced",
            "observed": True,
            "detail": "no payment deviation observed across the demo orders",
        },
    ],
    "ownership": [
        {
            "resource": "order-1001",
            "owner": "alice",
            "owner_type": "identity",
            "controlled": True,
        },
        {
            "resource": "order-1002",
            "owner": "bob",
            "owner_type": "identity",
            "controlled": True,
        },
        {
            "resource": "order-2001",
            "owner": "alice",
            "owner_type": "identity",
            "controlled": True,
        },
    ],
    "role_boundaries": [
        {
            "role": "customer",
            "action": "submit_order",
            "resource": "orders",
            "allowed": True,
            "expected": True,
            "consistent": True,
        },
        {
            "role": "customer",
            "action": "process_payment",
            "resource": "orders",
            "allowed": True,
            "expected": True,
            "consistent": True,
        },
        {
            "role": "customer",
            "action": "cancel_order",
            "resource": "orders",
            "allowed": True,
            "expected": True,
            "consistent": True,
        },
        {
            "role": "customer",
            "action": "ship_order",
            "resource": "orders",
            "allowed": False,
            "expected": False,
            "consistent": True,
        },
        {
            "role": "customer",
            "action": "confirm_delivery",
            "resource": "orders",
            "allowed": False,
            "expected": False,
            "consistent": True,
        },
        {
            "role": "admin",
            "action": "ship_order",
            "resource": "orders",
            "allowed": True,
            "expected": True,
            "consistent": True,
        },
        {
            "role": "warehouse",
            "action": "ship_order",
            "resource": "orders",
            "allowed": True,
            "expected": True,
            "consistent": True,
        },
    ],
    "invariants": [
        {
            "invariant": "only_paid_orders_ship",
            "status": "violated",
            "detail": "ship_order observed from created for order-2001",
        },
        {
            "invariant": "no_post_shipment_cancel",
            "status": "consistent",
            "detail": "cancel_order denied after shipping (order-1001)",
        },
        {
            "invariant": "payment_requires_created",
            "status": "consistent",
            "detail": "no payment-before-created deviation observed",
        },
    ],
    "hypotheses": [
        {
            "hypothesis": "cancel_after_payment",
            "outcome": "supported",
            "detail": "cancel_order on order-1002 (paid, pre-shipment) returned allowed",
        },
        {
            "hypothesis": "cancel_after_shipping",
            "outcome": "refuted",
            "detail": "cancel_order on order-1001 (shipped) returned denied by the server",
        },
        {
            "hypothesis": "cancel_ambiguous_order",
            "outcome": "inconclusive",
            "detail": "cancel_order on order-3001 returned an indeterminate 5xx",
        },
    ],
    "validations": [
        {
            "hypothesis": "cancel_after_payment",
            "result": "validated",
            "evidence_reference": (
                "replay [process_payment, cancel_order] on order-1002 "
                "-> [success, success]"
            ),
            "replay_observations": 2,
        },
        {
            "hypothesis": "cancel_after_shipping",
            "result": "invalidated",
            "evidence_reference": (
                "replay [process_payment, ship_order, cancel_order] on order-1001 "
                "-> [success, success, missing_prerequisite]"
            ),
            "replay_observations": 3,
        },
        {
            "hypothesis": "cancel_ambiguous_order",
            "result": "unverifiable",
            "evidence_reference": "order-3001 cancelled out; no deterministic outcome",
            "replay_observations": 0,
        },
    ],
}


def _demo_records() -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {
        "shop.example.com": dict(_DEMO_ORDER_WORKFLOW),
        "throttled.example.com": {
            "ip": "203.0.113.51",
            "error": {"kind": "rate_limited", "message": "rate limited"},
        },
        "unreachable.example.com": {
            "ip": "203.0.113.52",
            "error": {"kind": "connection_refused", "message": "connection refused"},
        },
        "slow.example.com": {
            "ip": "203.0.113.53",
            "error": {"kind": "timeout", "message": "timed out"},
        },
        "malformed.example.com": {
            "ip": "203.0.113.54",
            "error": {"kind": "malformed", "message": "malformed response"},
        },
    }
    return records


def _error_record_for_none(target: str) -> dict[str, Any]:
    return {
        "error": {
            "kind": "connection_refused",
            "message": "no business workflow model recorded for this target",
        },
    }


class MockBusinessLogicTransport:
    """Deterministic, mock-only business logic observation source.

    Never touches the network and never executes real state machines: all
    iteration happens against a fixed paper model of the demo ``order_workflow``
    hosted at ``shop.example.com``. Observed anomalies (scenario B) are fixed
    fixture data. Replay runs the in-process
    :class:`~blackforge.business_logic.models.ReplaySimulator` under the
    modeled action-safety envelope; anything outside it is rejected
    fail-closed. Known error hosts surface structured negative outcomes; any
    other host yields a stable ``connection_refused`` error document.
    """

    def __init__(self) -> None:
        self._records = _demo_records()

    @staticmethod
    def _host_for(target: str) -> str:
        text = target.strip()
        if "://" in text:
            return urlparse(text).netloc.rsplit(":", 1)[0]
        return text

    def _record_for(self, target: str) -> tuple[str, dict[str, Any]]:
        host = self._host_for(target)
        via_ip = None
        for name, record in self._records.items():
            if record.get("ip") == host:
                via_ip = name
                break
        if via_ip is not None:
            return via_ip, dict(self._records[via_ip])
        record = self._records.get(host)
        if record is not None:
            return host, dict(record)
        return host, _error_record_for_none(host)

    def _document(
        self,
        tool: str,
        target: str,
        mode: BusinessLogicMode,
        host: str,
        record: dict[str, Any],
    ) -> dict[str, Any]:
        return {"tool": tool, "mode": mode.value, "target": target, "host": host}

    def _error_output(self, tool: str, target: str, host: str, record: dict[str, Any]) -> str:
        doc = {
            "tool": tool,
            "mode": "active",
            "target": target,
            "host": host,
        }
        doc["error"] = dict(record.get("error", {}))
        return json.dumps(doc, sort_keys=True)

    def _url_for(self, record: dict[str, Any], host: str) -> str:
        return record.get("url") or f"https://{host}/"

    def _base(
        self,
        tool: str,
        target: str,
        mode: BusinessLogicMode,
        record: dict[str, Any],
        host: str,
    ) -> dict[str, Any] | None:
        if "error" in record:
            return None
        doc = self._document(tool, target, mode, host, record)
        doc["observed_url"] = self._url_for(record, host)
        return doc

    def _emit(self, doc: dict[str, Any]) -> str:
        return json.dumps(doc, sort_keys=True)

    # ------------------------------------------------------------------
    # Typed observation tools
    # ------------------------------------------------------------------
    def discover_workflows(
        self, target: str, mode: BusinessLogicMode = BusinessLogicMode.ACTIVE
    ) -> str:
        host, record = self._record_for(target)
        base = self._base("discover_workflows", target, mode, record, host)
        if base is None:
            return self._error_output("discover_workflows", target, host, record)
        base["workflow"] = record["workflow"]
        base["application"] = record.get("application")
        base["description"] = record.get("description")
        base["state_names"] = list(record.get("states", []))
        base["action_names"] = list(record.get("actions", []))
        return self._emit(base)

    def model_workflow(
        self, target: str, mode: BusinessLogicMode = BusinessLogicMode.ACTIVE
    ) -> str:
        host, record = self._record_for(target)
        base = self._base("model_workflow", target, mode, record, host)
        if base is None:
            return self._error_output("model_workflow", target, host, record)
        base["workflow"] = record["workflow"]
        base["initial_state"] = record.get("initial_state")
        base["terminal_states"] = list(record.get("terminal_states", []))
        base["states"] = [
            {"state": name, **dict(meta)}
            for name, meta in record.get("state_meta", {}).items()
        ]
        base["state_names"] = record.get("states", [])
        return self._emit(base)

    def analyze_state_transitions(
        self, target: str, mode: BusinessLogicMode = BusinessLogicMode.ACTIVE
    ) -> str:
        host, record = self._record_for(target)
        base = self._base("analyze_state_transitions", target, mode, record, host)
        if base is None:
            return self._error_output("analyze_state_transitions", target, host, record)
        base["workflow"] = record["workflow"]
        base["state_transitions"] = [
            dict(c) for c in record.get("state_transitions", [])
        ]
        if not base["state_transitions"]:
            base["note"] = "no state transitions observed"
        return self._emit(base)

    def analyze_business_rules(
        self, target: str, mode: BusinessLogicMode = BusinessLogicMode.ACTIVE
    ) -> str:
        host, record = self._record_for(target)
        base = self._base("analyze_business_rules", target, mode, record, host)
        if base is None:
            return self._error_output("analyze_business_rules", target, host, record)
        base["workflow"] = record["workflow"]
        base["business_rules"] = [dict(c) for c in record.get("business_rules", [])]
        if not base["business_rules"]:
            base["note"] = "no business rules observed"
        return self._emit(base)

    def analyze_ownership(
        self,
        target: str,
        mode: BusinessLogicMode = BusinessLogicMode.ACTIVE,
        test_identities: list[str] | None = None,
    ) -> str:
        host, record = self._record_for(target)
        base = self._base("analyze_ownership", target, mode, record, host)
        if base is None:
            return self._error_output("analyze_ownership", target, host, record)
        base["workflow"] = record["workflow"]
        entries = [dict(c) for c in record.get("ownership", [])]
        if test_identities:
            controlled = {str(i) for i in test_identities}
            entries = [
                e for e in entries if str(e.get("owner")) in controlled
            ]
            base["test_identities"] = [str(i) for i in test_identities]
            if not entries:
                base["note"] = "no ownership entries for the controlled identities"
        else:
            base["test_identities"] = []
        base["ownership"] = entries
        return self._emit(base)

    def analyze_role_boundaries(
        self,
        target: str,
        mode: BusinessLogicMode = BusinessLogicMode.ACTIVE,
        test_identities: list[str] | None = None,
    ) -> str:
        host, record = self._record_for(target)
        base = self._base("analyze_role_boundaries", target, mode, record, host)
        if base is None:
            return self._error_output("analyze_role_boundaries", target, host, record)
        base["workflow"] = record["workflow"]
        entries = [dict(c) for c in record.get("role_boundaries", [])]
        if test_identities:
            controlled = {str(i) for i in test_identities}
            entries = [
                e for e in entries if str(e.get("role")) in controlled
            ]
            base["test_identities"] = [str(i) for i in test_identities]
            if not entries:
                base["note"] = "no role-boundary entries for the controlled identities"
        else:
            base["test_identities"] = []
        base["role_boundaries"] = entries
        return self._emit(base)

    def check_workflow_consistency(
        self, target: str, mode: BusinessLogicMode = BusinessLogicMode.ACTIVE
    ) -> str:
        host, record = self._record_for(target)
        base = self._base("check_workflow_consistency", target, mode, record, host)
        if base is None:
            return self._error_output(
                "check_workflow_consistency", target, host, record
            )
        base["workflow"] = record["workflow"]
        base["invariants"] = [dict(c) for c in record.get("invariants", [])]
        if not base["invariants"]:
            base["note"] = "no invariants to check"
        return self._emit(base)

    # ------------------------------------------------------------------
    # Replay (in-process, safety-gated, deterministic)
    # ------------------------------------------------------------------
    def _workflow_model_for(self, host: str, record: dict[str, Any]) -> WorkflowModel:
        transitions: dict[str, list[WorkflowTransition]] = {}
        for entry in record.get("transitions", []):
            transitions.setdefault(entry["action"], []).append(
                WorkflowTransition(
                    action=entry["action"],
                    source_state=entry["source_state"],
                    target_state=entry["target_state"],
                    prerequisites=list(entry.get("prerequisites", [])),
                    note=entry.get("note"),
                )
            )
        safety = {
            action: ReplaySafetyClass(value)
            for action, value in record.get("action_safety", {}).items()
        }
        return WorkflowModel(
            workflow=record["workflow"],
            host=host,
            initial_state=record.get("initial_state", ""),
            states=list(record.get("states", [])),
            terminal_states=list(record.get("terminal_states", [])),
            actions=list(record.get("actions", [])),
            transitions=transitions,
            action_safety=safety,
        )

    def safety_class_for(self, target: str, action: str) -> ReplaySafetyClass:
        """Fail-closed safety class for an action on a host."""
        host, record = self._record_for(target)
        if "error" in record or "action_safety" not in record:
            return ReplaySafetyClass.PROHIBITED
        value = record.get("action_safety", {}).get(action)
        try:
            return ReplaySafetyClass(value) if value else ReplaySafetyClass.PROHIBITED
        except ValueError:
            return ReplaySafetyClass.PROHIBITED

    def replay_workflow(
        self,
        target: str,
        mode: BusinessLogicMode = BusinessLogicMode.ACTIVE,
        actions: list[str] | None = None,
        start_state: str | None = None,
        max_sequence_length: int = 8,
    ) -> str:
        host, record = self._record_for(target)
        base = self._base("replay_workflow", target, mode, record, host)
        if base is None:
            return self._error_output("replay_workflow", target, host, record)
        base["workflow"] = record["workflow"]
        sequence = [str(a) for a in (actions or [])][:max_sequence_length]
        model = self._workflow_model_for(host, record)
        simulator = ReplaySimulator(model)
        start = start_state or model.initial_state
        try:
            evaluations = simulator.replay(
                sequence,
                start,
                observed_targets=None,
                max_sequence_length=max_sequence_length,
            )
        except ValueError as exc:
            base["error"] = {"kind": "replay_rejected", "message": str(exc)}
            base["note"] = str(exc)
            base["replay"] = []
            return self._emit(base)
        base["start_state"] = start
        base["requested_actions"] = list(sequence)
        base["replay"] = [
            {
                "action": eval_.action,
                "source_state": eval_.source_state,
                "target_state": eval_.target_state,
                "result": eval_.result.value,
                "safety_class": eval_.safety_class.value,
                "sequence_length": eval_.sequence_length,
                "note": eval_.note,
            }
            for eval_ in evaluations
        ]
        return self._emit(base)

    # ------------------------------------------------------------------
    # Hypothesis + validation
    # ------------------------------------------------------------------
    def hypothesize_business_logic(
        self, target: str, mode: BusinessLogicMode = BusinessLogicMode.ACTIVE
    ) -> str:
        host, record = self._record_for(target)
        base = self._base("hypothesize_business_logic", target, mode, record, host)
        if base is None:
            return self._error_output(
                "hypothesize_business_logic", target, host, record
            )
        base["workflow"] = record["workflow"]
        base["hypotheses"] = [dict(c) for c in record.get("hypotheses", [])]
        if not base["hypotheses"]:
            base["note"] = "no hypotheses to evaluate"
        return self._emit(base)

    def validate_business_logic(
        self, target: str, mode: BusinessLogicMode = BusinessLogicMode.ACTIVE
    ) -> str:
        host, record = self._record_for(target)
        base = self._base("validate_business_logic", target, mode, record, host)
        if base is None:
            return self._error_output("validate_business_logic", target, host, record)
        base["workflow"] = record["workflow"]
        base["validations"] = [dict(c) for c in record.get("validations", [])]
        if not base["validations"]:
            base["note"] = "no validations recorded"
        return self._emit(base)

    def collect_workflow_evidence(
        self, target: str, mode: BusinessLogicMode = BusinessLogicMode.ACTIVE
    ) -> str:
        host, record = self._record_for(target)
        base = self._base("collect_workflow_evidence", target, mode, record, host)
        if base is None:
            return self._error_output(
                "collect_workflow_evidence", target, host, record
            )
        base["workflow"] = record["workflow"]
        base["application"] = record.get("application")
        base["description"] = record.get("description")
        base["state_names"] = list(record.get("states", []))
        base["action_names"] = list(record.get("actions", []))
        base["evidence_counts"] = {
            "states": len(record.get("states", [])),
            "actions": len(record.get("actions", [])),
            "transitions": len(record.get("state_transitions", [])),
            "rules": len(record.get("business_rules", [])),
        }
        base["note"] = (
            "workflow evidence harvested deterministically from the mock "
            "order_workflow dataset"
        )
        return self._emit(base)


__all__ = ["MockBusinessLogicTransport"]
