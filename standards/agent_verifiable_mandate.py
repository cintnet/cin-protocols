#!/usr/bin/env python3
"""Fail-closed validator for AgentVerifiableMandate v0.1.0.

Implements cross-domain verifiable mandate checking under IETF WIMSE draft-hulea-wimse-agent-mandate-01,
enforcing strict separation between delegator authority statements and agent mandate grants,
monotonic scope attenuation, integer-only resource accounting, and token status list revocation pointers.
Standard library only.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple


def parse_iso8601(dt_str: str) -> datetime:
    """Parse ISO 8601 string, strictly requiring timezone offset (UTC 'Z' or +/-HH:MM)."""
    if not isinstance(dt_str, str):
        raise ValueError("timestamp_must_be_string")
    if not (dt_str.endswith("Z") or re.search(r"[+-]\d{2}:\d{2}$", dt_str)):
        raise ValueError("timestamp_must_have_timezone_offset")
    if dt_str.endswith("Z"):
        dt = datetime.fromisoformat(dt_str[:-1] + "+00:00")
    else:
        dt = datetime.fromisoformat(dt_str)
    if dt.tzinfo is None:
        raise ValueError("timestamp_must_have_timezone_offset")
    return dt


class AgentVerifiableMandateValidator:
    """Fail-closed schema and semantic validator for AgentVerifiableMandate documents."""

    def __init__(self, schema_dict: Optional[Dict[str, Any]] = None):
        if schema_dict is None:
            schema_path = Path(__file__).resolve().parent / "agent-verifiable-mandate-v0.1.json"
            with open(schema_path, "r", encoding="utf-8") as f:
                self.schema = json.load(f)
        else:
            self.schema = schema_dict

    def _validate_node(self, doc: Any, node: Dict[str, Any], path: str) -> Tuple[bool, Optional[str]]:
        expected_type = node.get("type")
        if expected_type == "object":
            if not isinstance(doc, dict):
                return False, f"{path}:must_be_object"
            for req in node.get("required", []):
                if req not in doc:
                    return False, f"{path}:missing_required_property:{req}"
            props = node.get("properties", {})
            if not node.get("additionalProperties", True):
                extra = set(doc.keys()) - set(props.keys())
                if extra:
                    return False, f"{path}:extra_properties:{','.join(sorted(extra))}"
            for k, v in doc.items():
                if k in props:
                    sub_path = f"{path}.{k}" if path else k
                    ok, err = self._validate_node(v, props[k], sub_path)
                    if not ok:
                        return False, err
            return True, None

        elif expected_type == "string":
            if not isinstance(doc, str):
                return False, f"{path}:must_be_string"
            if "const" in node and doc != node["const"]:
                return False, f"{path}:const_mismatch:{doc}!= {node['const']}"
            if "minLength" in node and len(doc) < node["minLength"]:
                return False, f"{path}:minLength_violation"
            if "maxLength" in node and len(doc) > node["maxLength"]:
                return False, f"{path}:maxLength_violation"
            if "pattern" in node and not re.match(node["pattern"], doc):
                return False, f"{path}:pattern_mismatch"
            if "enum" in node and doc not in node["enum"]:
                return False, f"{path}:enum_violation:{doc}"
            if node.get("format") == "date-time":
                try:
                    parse_iso8601(doc)
                except ValueError as ex:
                    return False, f"{path}:invalid_iso8601:{ex}"
            return True, None

        elif expected_type == "integer":
            if isinstance(doc, bool) or not isinstance(doc, int):
                return False, f"{path}:must_be_integer"
            if "minimum" in node and doc < node["minimum"]:
                return False, f"{path}:below_minimum:{doc}<{node['minimum']}"
            if "maximum" in node and doc > node["maximum"]:
                return False, f"{path}:above_maximum:{doc}>{node['maximum']}"
            return True, None

        elif expected_type == "array":
            if not isinstance(doc, list):
                return False, f"{path}:must_be_array"
            if "minItems" in node and len(doc) < node["minItems"]:
                return False, f"{path}:minItems_violation"
            items_schema = node.get("items", {})
            for idx, item in enumerate(doc):
                sub_path = f"{path}[{idx}]"
                ok, err = self._validate_node(item, items_schema, sub_path)
                if not ok:
                    return False, err
            return True, None

        return True, None

    def validate_schema(self, doc: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate document against the JSON schema structure fail-closed."""
        return self._validate_node(doc, self.schema, "")

    def validate_mandate(
        self,
        doc: Dict[str, Any],
        as_of: Optional[datetime] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Validate structural syntax and semantic authority-mandate invariants fail-closed."""
        # 1. Structural schema validation
        ok, err = self.validate_schema(doc)
        if not ok:
            return False, err

        # 2. Timestamp and lifespan verification
        try:
            auth_issued = parse_iso8601(doc["authority_statement"]["issued_at"])
            auth_expires = parse_iso8601(doc["authority_statement"]["expires_at"])
            mandate_issued = parse_iso8601(doc["mandate_grant"]["issued_at"])
            mandate_expires = parse_iso8601(doc["mandate_grant"]["expires_at"])
        except ValueError as ex:
            return False, f"timestamp_parse_error:{ex}"

        if auth_expires <= auth_issued:
            return False, "authority_statement:zero_or_negative_lifespan"

        if mandate_expires <= mandate_issued:
            return False, "mandate_grant:zero_or_negative_lifespan"

        # Mandate validity must be contained within delegator authority validity window
        if mandate_issued < auth_issued:
            return False, "mandate_issued_before_authority_window"
        if mandate_expires > auth_expires:
            return False, "mandate_expires_after_authority_window"

        # Check against reference evaluation clock
        eval_time = as_of or datetime.now(timezone.utc)
        if eval_time < mandate_issued:
            return False, "mandate_not_yet_valid"
        if eval_time >= mandate_expires:
            return False, "mandate_expired"

        # 3. Monotonic scope attenuation (authority separation)
        auth_stmt = doc["authority_statement"]
        mandate = doc["mandate_grant"]

        allowed_actions = set(auth_stmt["allowed_delegable_actions"])
        conferred_actions = set(mandate["conferred_actions"])

        if not conferred_actions:
            return False, "mandate_conferred_actions_empty"

        escalated_actions = conferred_actions - allowed_actions
        if escalated_actions:
            return False, f"privilege_escalation:unauthorized_actions:{','.join(sorted(escalated_actions))}"

        allowed_domains = set(auth_stmt["allowed_target_domains"])
        target_domain = mandate["target_domain"]
        if target_domain not in allowed_domains:
            return False, f"privilege_escalation:target_domain_not_allowed:{target_domain}"

        # 4. Resource and financial limits (LS-a25669)
        auth_budget = auth_stmt["max_delegable_budget_cents"]
        limits = mandate["limits"]
        mandate_budget = limits["max_budget_cents"]
        per_tx_cents = limits["max_spend_per_transaction_cents"]

        if mandate_budget > auth_budget:
            return False, f"budget_escalation:mandate_cents_{mandate_budget}_exceeds_authority_{auth_budget}"

        if per_tx_cents > mandate_budget:
            return False, f"spend_limit_inconsistency:per_tx_{per_tx_cents}_exceeds_total_{mandate_budget}"

        # 5. Token status list revocation check
        status_list = mandate["token_status_list"]
        if status_list["expected_status"] != "valid":
            return False, f"mandate_revocation_status_not_valid:{status_list['expected_status']}"

        return True, None
