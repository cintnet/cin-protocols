#!/usr/bin/env python3
"""Fail-closed validator and conformance tests for AgentDelegationToken v0.1.0."""
import copy, json, math, re, sys
from datetime import datetime
from pathlib import Path

def parse_iso8601(s: str) -> datetime:
    if not isinstance(s, str): raise TypeError("timestamp must be string")
    dt = datetime.fromisoformat(s[:-1] + "+00:00" if s.endswith("Z") else s)
    if dt.tzinfo is None: raise ValueError("timezone_required")
    return dt

class SchemaValidator:
    """Fail-closed validator enforcing schema types, bounds, enums, and no extra properties."""
    def __init__(self, schema_dict: dict): self.schema = schema_dict

    def _validate_obj(self, doc: dict, node: dict, path: str) -> tuple[bool, str | None]:
        if not isinstance(doc, dict): return False, f"{path}:must_be_object"
        for req in node.get("required", []):
            if req not in doc: return False, f"{path}:missing_required_property:{req}"
        props = node.get("properties", {})
        if not node.get("additionalProperties", True):
            extra = set(doc.keys()) - set(props.keys())
            if extra: return False, f"{path}:extra_properties:{','.join(sorted(extra))}"
        for key, val in doc.items():
            if key not in props: continue
            p_schema, sp = props[key], (f"{path}.{key}" if path else key)
            pt = p_schema.get("type")
            if isinstance(pt, list):
                if not any((t == "string" and isinstance(val, str)) or (t == "null" and val is None) for t in pt):
                    return False, f"{sp}:union_type_violation"
            elif pt == "string" and not isinstance(val, str): return False, f"{sp}:must_be_string"
            elif pt == "integer" and (not isinstance(val, int) or isinstance(val, bool)): return False, f"{sp}:must_be_integer"
            elif pt == "boolean" and not isinstance(val, bool): return False, f"{sp}:must_be_boolean"
            elif pt == "array" and not isinstance(val, list): return False, f"{sp}:must_be_array"
            elif pt == "object":
                valid, err = self._validate_obj(val, p_schema, sp)
                if not valid: return False, err
            if pt == "integer" and "minimum" in p_schema and val < p_schema["minimum"]: return False, f"{sp}:minimum_violation"
            if "const" in p_schema and val != p_schema["const"]: return False, f"{sp}:const_mismatch:{val}!={p_schema['const']}"
            if "enum" in p_schema and val not in p_schema["enum"]: return False, f"{sp}:enum_violation:{val}"
            if "pattern" in p_schema and isinstance(val, str) and not re.match(p_schema["pattern"], val): return False, f"{sp}:pattern_mismatch"
            if pt == "array" and "items" in p_schema:
                if len(val) < p_schema.get("minItems", 0): return False, f"{sp}:min_items_violation"
                for i, item in enumerate(val):
                    ip = f"{sp}[{i}]"
                    if p_schema["items"].get("type") == "object":
                        valid, err = self._validate_obj(item, p_schema["items"], ip)
                        if not valid: return False, err
                    elif p_schema["items"].get("type") == "string" and not isinstance(item, str): return False, f"{ip}:must_be_string"
        return True, None

    def validate(self, doc: dict) -> tuple[bool, str | None]:
        valid, err = self._validate_obj(doc, self.schema, "root")
        if not valid: return False, err
        try:
            it, xt = parse_iso8601(doc["issued_at"]), parse_iso8601(doc["expires_at"])
            if xt <= it: return False, "inverted_lifecycle:expires_at_must_be_after_issued_at"
        except Exception as e: return False, f"invalid_date_format:{e}"
        rev_at = doc.get("revocation", {}).get("revoked_at")
        if rev_at is not None:
            try: parse_iso8601(rev_at)
            except Exception as e: return False, f"invalid_date_format:revoked_at:{e}"
        chain = doc.get("principal_chain", [])
        if not chain or not isinstance(chain[0], str) or not chain[0].startswith("person:"):
            return False, "principal_chain_root_must_be_human"
        return True, None

def _is_str_list(lst) -> bool:
    return isinstance(lst, list) and len(lst) > 0 and all(isinstance(x, str) and len(x) > 0 for x in lst)

def _is_pos_int(val) -> bool:
    return isinstance(val, int) and not isinstance(val, bool) and val > 0

def verify_scope_attenuation(parent_scope: dict, delegated_token: dict) -> tuple[bool, str | None]:
    """Verify that delegated scope is monotonically attenuated relative to delegator scope."""
    if not isinstance(parent_scope, dict) or not isinstance(delegated_token, dict): return False, "invalid_input_type"
    del_scope = delegated_token.get("scope")
    if not isinstance(del_scope, dict): return False, "invalid_scope"
    pa, da = parent_scope.get("allowed_actions"), del_scope.get("allowed_actions")
    if not _is_str_list(pa) or not _is_str_list(da): return False, "empty_or_invalid_allowlist:actions"
    if not set(da).issubset(set(pa)): return False, f"privilege_escalation:actions:{','.join(sorted(set(da) - set(pa)))}"
    pc, dc = parent_scope.get("data_categories"), del_scope.get("data_categories")
    if not _is_str_list(pc) or not _is_str_list(dc): return False, "empty_or_invalid_allowlist:categories"
    if not set(dc).issubset(set(pc)): return False, f"privilege_escalation:categories:{','.join(sorted(set(dc) - set(pc)))}"
    pb, db = parent_scope.get("max_budget_units"), del_scope.get("max_budget_units")
    if not _is_pos_int(pb) or not _is_pos_int(db): return False, "invalid_budget_units"
    if db > pb: return False, f"budget_escalation:{db}>{pb}"
    return True, None

def evaluate_lifecycle(token: dict, req: dict) -> tuple[bool, str | None]:
    """Evaluate token lifecycle against a concrete execution request."""
    if not isinstance(token, dict) or not isinstance(req, dict): return False, "invalid_format"
    rev, delg, scp = token.get("revocation"), token.get("delegatee"), token.get("scope")
    if not isinstance(rev, dict) or not isinstance(delg, dict) or not isinstance(scp, dict): return False, "invalid_token_format"
    try:
        et, it, xt = parse_iso8601(req.get("evaluated_at", "")), parse_iso8601(token.get("issued_at", "")), parse_iso8601(token.get("expires_at", ""))
        if et >= xt: return False, "token_expired"
        if et < it: return False, "token_not_yet_valid"
    except Exception as e: return False, f"invalid_timestamp:{e}"
    if rev.get("is_revoked"): return False, "token_revoked"
    if req.get("delegatee_agent_id") != delg.get("agent_id"): return False, "delegatee_drift"
    if req.get("action") not in scp.get("allowed_actions", []): return False, "action_not_permitted"
    units, max_b = req.get("requested_units", 1), scp.get("max_budget_units")
    if not _is_pos_int(units) or not _is_pos_int(max_b): return False, "invalid_units_or_budget"
    if units > max_b: return False, "budget_exceeded"
    return True, None

def run_tests() -> int:
    base = Path(__file__).resolve().parent.parent
    schema = json.loads((base / "agent-delegation-token-v0.1.json").read_text(encoding="utf-8"))
    example = json.loads((base / "examples" / "delegated-sensor-query-token.json").read_text(encoding="utf-8"))
    validator = SchemaValidator(schema)
    assert validator.validate(example) == (True, None)
    req = {"evaluated_at": "2026-10-10T12:30:00Z", "delegatee_agent_id": "agent:diagnostic-subagent", "action": "query_reading", "requested_units": 2}
    assert evaluate_lifecycle(example, req) == (True, None)
    ps = {"allowed_actions": ["query_reading", "compute_digest", "export"], "data_categories": ["health_sensors", "dev"], "max_budget_units": 50}
    assert verify_scope_attenuation(ps, example) == (True, None)

    # Structural rejections (15 checks)
    for mod in [lambda d: d.update({"extra": 1}), lambda d: d["delegator"].update({"extra": 1}),
                lambda d: d["delegatee"].update({"extra": 1}), lambda d: d["scope"].update({"extra": 1}),
                lambda d: d["revocation"].update({"extra": 1}), lambda d: d["signatures"][0].update({"extra": 1}),
                lambda d: d.update({"principal_chain": []}), lambda d: d.update({"principal_chain": ["person:alice"]}),
                lambda d: d.update({"principal_chain": ["agent:bot1", "agent:bot2"]}),
                lambda d: d.update({"issued_at": "2026-10-10T12:00:00"}), # naive dt
                lambda d: d.update({"expires_at": "2026-10-10T12:00:00Z"}), # inverted / equal
                lambda d: d["delegator"].update({"max_delegation_depth": -1}), lambda d: d["revocation"].update({"revocable": False}),
                lambda d: d["scope"].update({"max_budget_units": 0}), lambda d: d["signatures"][0].update({"signature_hex": "abc"})]:
        bad = copy.deepcopy(example); mod(bad)
        assert not validator.validate(bad)[0]

    # Attenuation rejections (7 checks)
    assert verify_scope_attenuation(None, example) == (False, "invalid_input_type")
    assert verify_scope_attenuation(ps, None) == (False, "invalid_input_type")
    assert verify_scope_attenuation({"allowed_actions": [], "data_categories": ["h"], "max_budget_units": 10}, example) == (False, "empty_or_invalid_allowlist:actions")
    assert verify_scope_attenuation({"allowed_actions": "query_reading", "data_categories": ["h"], "max_budget_units": 10}, example) == (False, "empty_or_invalid_allowlist:actions")
    assert verify_scope_attenuation({"allowed_actions": ["compute_digest"], "data_categories": ["health_sensors"], "max_budget_units": 50}, example)[0] is False
    assert verify_scope_attenuation({"allowed_actions": ["query_reading", "compute_digest"], "data_categories": ["other"], "max_budget_units": 50}, example)[0] is False
    assert verify_scope_attenuation({**ps, "max_budget_units": 5}, example) == (False, "budget_escalation:10>5")
    assert verify_scope_attenuation({**ps, "max_budget_units": float("nan")}, example) == (False, "invalid_budget_units")

    # Lifecycle rejections (8 checks)
    assert evaluate_lifecycle(None, req) == (False, "invalid_format")
    assert evaluate_lifecycle({"revocation": None}, req) == (False, "invalid_token_format")
    assert evaluate_lifecycle(example, {**req, "evaluated_at": "2026-10-10T13:00:00Z"}) == (False, "token_expired")
    assert evaluate_lifecycle(example, {**req, "evaluated_at": "2026-10-10T11:59:59Z"}) == (False, "token_not_yet_valid")
    assert evaluate_lifecycle(example, {**req, "evaluated_at": "2026-10-10T12:30:00"})[0] is False # naive timestamp
    rev = copy.deepcopy(example); rev["revocation"]["is_revoked"] = True
    assert evaluate_lifecycle(rev, req) == (False, "token_revoked")
    assert evaluate_lifecycle(example, {**req, "delegatee_agent_id": "agent:other"}) == (False, "delegatee_drift")
    assert evaluate_lifecycle(example, {**req, "action": "forbidden"}) == (False, "action_not_permitted")
    assert evaluate_lifecycle(example, {**req, "requested_units": 100}) == (False, "budget_exceeded")
    assert evaluate_lifecycle(example, {**req, "requested_units": 0}) == (False, "invalid_units_or_budget")

    print("PASS: 33 adversarial and conformance checks succeeded.")
    return 0

import unittest

class TestDelegationTokenSchema(unittest.TestCase):
    def test_delegation_token_conformance_and_adversarial(self):
        self.assertEqual(run_tests(), 0)

if __name__ == "__main__":
    unittest.main()
