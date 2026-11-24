#!/usr/bin/env python3
"""Fail-closed validator and conformance tests for AgentConsentGrant v0.1.0."""
import copy, json, re, sys
from datetime import datetime
from pathlib import Path

def parse_iso8601(dt_str: str) -> datetime:
    return datetime.fromisoformat(dt_str[:-1] + "+00:00" if dt_str.endswith("Z") else dt_str)

class SchemaValidator:
    """Fail-closed validator enforcing schema types, bounds, enums, and no extra properties."""
    def __init__(self, schema_dict: dict):
        self.schema = schema_dict

    def _validate_obj(self, doc: dict, schema_node: dict, path: str) -> tuple[bool, str | None]:
        if not isinstance(doc, dict):
            return False, f"{path}:must_be_object"
        for req in schema_node.get("required", []):
            if req not in doc:
                return False, f"{path}:missing_required_property:{req}"
        props = schema_node.get("properties", {})
        if not schema_node.get("additionalProperties", True):
            extra = set(doc.keys()) - set(props.keys())
            if extra:
                return False, f"{path}:extra_properties:{','.join(sorted(extra))}"
        for key, val in doc.items():
            if key not in props:
                continue
            p_schema, sub_path = props[key], (f"{path}.{key}" if path else key)
            p_type = p_schema.get("type")
            if isinstance(p_type, list):
                matched = any((t == "string" and isinstance(val, str)) or
                              (t == "null" and val is None) or
                              (t == "integer" and isinstance(val, int) and not isinstance(val, bool)) or
                              (t == "boolean" and isinstance(val, bool)) for t in p_type)
                if not matched:
                    return False, f"{sub_path}:union_type_violation"
            elif p_type == "string" and not isinstance(val, str):
                return False, f"{sub_path}:must_be_string"
            elif p_type == "integer" and (not isinstance(val, int) or isinstance(val, bool)):
                return False, f"{sub_path}:must_be_integer"
            elif p_type == "boolean" and not isinstance(val, bool):
                return False, f"{sub_path}:must_be_boolean"
            elif p_type == "array" and not isinstance(val, list):
                return False, f"{sub_path}:must_be_array"
            elif p_type == "object":
                valid, err = self._validate_obj(val, p_schema, sub_path)
                if not valid: return False, err
            if p_type == "integer" and "minimum" in p_schema and val < p_schema["minimum"]:
                return False, f"{sub_path}:minimum_violation"
            if "const" in p_schema and val != p_schema["const"]:
                return False, f"{sub_path}:const_mismatch:{val}!= {p_schema['const']}"
            if "enum" in p_schema and val not in p_schema["enum"]:
                return False, f"{sub_path}:enum_violation:{val}"
            if "pattern" in p_schema and isinstance(val, str) and not re.match(p_schema["pattern"], val):
                return False, f"{sub_path}:pattern_mismatch"
            if p_type == "array" and "items" in p_schema:
                if len(val) < p_schema.get("minItems", 0):
                    return False, f"{sub_path}:min_items_violation"
                for i, item in enumerate(val):
                    i_path = f"{sub_path}[{i}]"
                    if p_schema["items"].get("type") == "object":
                        valid, err = self._validate_obj(item, p_schema["items"], i_path)
                        if not valid: return False, err
                    elif p_schema["items"].get("type") == "string" and not isinstance(item, str):
                        return False, f"{i_path}:must_be_string"
        return True, None

    def validate(self, doc: dict) -> tuple[bool, str | None]:
        valid, err = self._validate_obj(doc, self.schema, "root")
        if not valid: return False, err
        for dt_f in ("issued_at", "expires_at"):
            try: parse_iso8601(doc[dt_f])
            except Exception as e: return False, f"invalid_date_format:{dt_f}:{e}"
        rev_at = doc.get("revocation", {}).get("revoked_at")
        if rev_at is not None:
            try: parse_iso8601(rev_at)
            except Exception as e: return False, f"invalid_date_format:revoked_at:{e}"
        return True, None

def evaluate_lifecycle(grant: dict, request: dict) -> tuple[bool, str | None]:
    """Fail-closed lifecycle evaluation of request execution."""
    if not isinstance(request, dict): return False, "invalid_request_format"
    try:
        eval_t, iss_t, exp_t = parse_iso8601(request["evaluated_at"]), parse_iso8601(grant["issued_at"]), parse_iso8601(grant["expires_at"])
        if eval_t.tzinfo is None or iss_t.tzinfo is None or exp_t.tzinfo is None:
            return False, "invalid_timestamp_format:timezone_required"
        if eval_t >= exp_t: return False, "grant_expired"
        if eval_t < iss_t: return False, "grant_not_yet_valid"
    except Exception as e: return False, f"invalid_timestamp_format:{e}"
    if grant.get("revocation", {}).get("is_revoked"): return False, "grant_revoked"
    if request.get("grantee_agent_id") != grant.get("grantee", {}).get("agent_id"): return False, "recipient_drift"
    if request.get("purpose_code") != grant.get("purpose", {}).get("code"): return False, "purpose_drift"
    inv_count = request.get("invocations_count")
    if not isinstance(inv_count, int) or isinstance(inv_count, bool) or inv_count < 0:
        return False, "invalid_invocations_count"
    if inv_count >= grant.get("data_scope", {}).get("max_invocations", 1): return False, "invocation_limit_exceeded"
    req_fields = request.get("requested_fields")
    if not isinstance(req_fields, list) or not all(isinstance(f, str) for f in req_fields):
        return False, "invalid_requested_fields"
    permitted = set(grant.get("data_scope", {}).get("fields_permitted", []))
    req_fields_set = set(req_fields)
    if not req_fields_set or not permitted or not req_fields_set.issubset(permitted): return False, "unauthorized_fields_requested"
    return True, None

def run_tests() -> bool:
    base_dir = Path(__file__).resolve().parent.parent
    with open(base_dir / "agent-consent-grant-v0.1.json", "r", encoding="utf-8") as f: schema = json.load(f)
    validator = SchemaValidator(schema)
    with open(base_dir / "examples" / "dentist-visit-consent-grant.json", "r", encoding="utf-8") as f: base_doc = json.load(f)

    v, err = validator.validate(base_doc)
    assert v and err is None, f"Positive test 1 failed: {err}"
    valid_req = {
        "evaluated_at": "2026-10-09T14:15:00Z",
        "grantee_agent_id": "agent-dr-smith-clinic",
        "purpose_code": "oral-health-consultation",
        "invocations_count": 0,
        "requested_fields": ["streptococcus_mutans_relative_abundance"],
    }
    v, err = evaluate_lifecycle(base_doc, valid_req)
    assert v, f"Positive test 2 failed: {err}"

    adversarial_count = 0
    tcs = [
        ("exact_expiry", base_doc, {**valid_req, "evaluated_at": "2026-10-09T15:00:00Z"}, "grant_expired"),
        ("before_validity", base_doc, {**valid_req, "evaluated_at": "2026-10-09T13:59:59Z"}, "grant_not_yet_valid"),
        ("recipient_drift", base_doc, {**valid_req, "grantee_agent_id": "agent-third-party"}, "recipient_drift"),
        ("purpose_drift", base_doc, {**valid_req, "purpose_code": "ad-targeting"}, "purpose_drift"),
        ("invocation_limit", base_doc, {**valid_req, "invocations_count": 1}, "invocation_limit_exceeded"),
        ("unauthorized_field", base_doc, {**valid_req, "requested_fields": ["genomic_dna"]}, "unauthorized_fields_requested"),
        ("fields_string_shape", base_doc, {**valid_req, "requested_fields": "streptococcus_mutans_relative_abundance"}, "invalid_requested_fields"),
        ("fields_none_shape", base_doc, {**valid_req, "requested_fields": None}, "invalid_requested_fields"),
        ("fields_non_string_item", base_doc, {**valid_req, "requested_fields": [123]}, "invalid_requested_fields"),
        ("invocations_non_int", base_doc, {**valid_req, "invocations_count": "0"}, "invalid_invocations_count"),
        ("invocations_none", base_doc, {**valid_req, "invocations_count": None}, "invalid_invocations_count"),
        ("invocations_negative", base_doc, {**valid_req, "invocations_count": -1}, "invalid_invocations_count"),
    ]
    for name, grant, req, exp_err in tcs:
        ok, res_err = evaluate_lifecycle(grant, req)
        assert not ok and res_err == exp_err, f"Test {name} expected {exp_err}, got {res_err}"
        adversarial_count += 1

    mods = [
        ("revocation.is_revoked", True, lambda d: evaluate_lifecycle(d, valid_req), "grant_revoked"),
        ("grantor.extra_injected", "malicious", lambda d: validator.validate(d), "extra_properties"),
        ("revocation.revocable", False, lambda d: validator.validate(d), "const_mismatch"),
        ("signatures.0.algorithm", "mock-sha256", lambda d: validator.validate(d), "enum_violation"),
        ("data_scope.fields_permitted", [], lambda d: validator.validate(d), "min_items_violation"),
        ("revocation.revoked_at", {"injected": "dict"}, lambda d: validator.validate(d), "union_type_violation"),
        ("data_scope.max_invocations", 0, lambda d: validator.validate(d), "minimum_violation"),
        ("revocation.revoked_at", "not-a-date", lambda d: validator.validate(d), "invalid_date_format:revoked_at"),
        ("signatures.0.signature_hex", "short", lambda d: validator.validate(d), "pattern_mismatch"),
    ]
    for path, val, check_fn, exp_err in mods:
        doc = copy.deepcopy(base_doc)
        cur = doc
        parts = path.split(".")
        for p in parts[:-1]: cur = cur[int(p)] if p.isdigit() else cur[p]
        cur[parts[-1]] = val
        ok, res_err = check_fn(doc)
        assert not ok and exp_err in str(res_err), f"Mod {path} expected {exp_err}, got {res_err}"
        adversarial_count += 1

    assert adversarial_count == 21, f"Expected 21 adversarial tests, got {adversarial_count}"
    print(f"PASS: 2 positive checks and {adversarial_count} adversarial conformance tests succeeded.")
    return True

import unittest

class TestConsentGrantSchema(unittest.TestCase):
    def test_consent_grant_conformance_and_adversarial(self):
        self.assertTrue(run_tests())

if __name__ == "__main__":
    unittest.main()
