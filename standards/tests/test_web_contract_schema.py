#!/usr/bin/env python3
"""Fail-closed validator and conformance tests for AgentWebContract v0.1.0.

Draft/offline boundaries and scope limits:
- Schema validation performs structural and parameter-bound verification offline.
- Offline schema shape checks do not replace runtime egress enforcement or verified authorization.
- HTTP method restrictions (e.g. limiting verbs to GET, HEAD, POST) bound declared verbs,
  but do not prove or guarantee read-only or side-effect-free execution (GET requests can
  trigger remote tracking or webhook side-effects; POST requests can submit arbitrary payloads).
- Dynamic egress gating and credential isolation must be enforced by the runtime host.
"""
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
import unittest


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


class SchemaValidator:
    """Fail-closed validator enforcing types, bounds, enums, formats, and additionalProperties: false."""

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

            if p_type == "string":
                if not isinstance(val, str):
                    return False, f"{sub_path}:must_be_string"
                if "minLength" in p_schema and len(val) < p_schema["minLength"]:
                    return False, f"{sub_path}:min_length_violation"
                if "pattern" in p_schema and not re.match(p_schema["pattern"], val):
                    return False, f"{sub_path}:pattern_mismatch"
                if "const" in p_schema and val != p_schema["const"]:
                    return False, f"{sub_path}:const_mismatch"
                if "enum" in p_schema and val not in p_schema["enum"]:
                    return False, f"{sub_path}:invalid_enum:{val}"
                if p_schema.get("format") == "date-time":
                    try:
                        parse_iso8601(val)
                    except Exception as e:
                        return False, f"{sub_path}:invalid_datetime:{e}"

            elif p_type == "integer":
                if not isinstance(val, int) or isinstance(val, bool):
                    return False, f"{sub_path}:must_be_integer"
                if "minimum" in p_schema and val < p_schema["minimum"]:
                    return False, f"{sub_path}:below_minimum"
                if "maximum" in p_schema and val > p_schema["maximum"]:
                    return False, f"{sub_path}:above_maximum"

            elif p_type == "boolean":
                if not isinstance(val, bool):
                    return False, f"{sub_path}:must_be_boolean"
                if "const" in p_schema and val != p_schema["const"]:
                    return False, f"{sub_path}:const_mismatch"

            elif p_type == "array":
                if not isinstance(val, list):
                    return False, f"{sub_path}:must_be_array"
                if "minItems" in p_schema and len(val) < p_schema["minItems"]:
                    return False, f"{sub_path}:below_min_items"
                items_schema = p_schema.get("items", {})
                for idx, item in enumerate(val):
                    elem_path = f"{sub_path}[{idx}]"
                    item_type = items_schema.get("type")
                    if item_type == "object":
                        ok, err = self._validate_obj(item, items_schema, elem_path)
                        if not ok:
                            return False, err
                    elif item_type == "string":
                        if not isinstance(item, str):
                            return False, f"{elem_path}:must_be_string"
                        if "minLength" in items_schema and len(item) < items_schema["minLength"]:
                            return False, f"{elem_path}:min_length_violation"
                        if "pattern" in items_schema and not re.match(items_schema["pattern"], item):
                            return False, f"{elem_path}:pattern_mismatch"
                        if "enum" in items_schema and item not in items_schema["enum"]:
                            return False, f"{elem_path}:invalid_enum:{item}"

            elif p_type == "object":
                ok, err = self._validate_obj(val, p_schema, sub_path)
                if not ok:
                    return False, err

        return True, None

    def validate(self, doc: dict) -> tuple[bool, str | None]:
        ok, err = self._validate_obj(doc, self.schema, "")
        if not ok:
            return False, err
        # Cross-field logical invariant checks
        try:
            issued = parse_iso8601(doc["issued_at"])
            expires = parse_iso8601(doc["expires_at"])
            if expires <= issued:
                return False, "invariants:expires_at_must_be_after_issued_at"
        except Exception as e:
            return False, f"invariants:timestamp_error:{e}"
        return True, None


class TestWebContractSchema(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        standards_dir = Path(__file__).resolve().parent.parent
        schema_file = standards_dir / "agent-web-contract-v0.1.json"
        example_file = standards_dir / "examples" / "web-research-contract.json"

        with open(schema_file, "r", encoding="utf-8") as f:
            cls.schema_data = json.load(f)
        cls.validator = SchemaValidator(cls.schema_data)

        with open(example_file, "r", encoding="utf-8") as f:
            cls.example_data = json.load(f)

    def test_schema_itself_is_valid_structure(self):
        self.assertEqual(self.schema_data.get("$schema"), "http://json-schema.org/draft-07/schema#")
        self.assertEqual(self.schema_data.get("title"), "AgentWebContract")
        self.assertEqual(self.schema_data.get("type"), "object")
        self.assertFalse(self.schema_data.get("additionalProperties", True))

    def test_example_payload_passes_validation(self):
        ok, err = self.validator.validate(self.example_data)
        self.assertTrue(ok, f"Expected example to pass, but got error: {err}")

    def test_reject_missing_required_properties(self):
        for req in [
            "contract_id",
            "domain_scope",
            "interaction_bounds",
            "data_protection",
            "evidence_requirements",
            "signatures",
        ]:
            bad = copy.deepcopy(self.example_data)
            del bad[req]
            ok, err = self.validator.validate(bad)
            self.assertFalse(ok, f"Should reject document missing {req}")
            self.assertIn(f"missing_required_property:{req}", err)

    def test_reject_extra_properties_fail_closed(self):
        bad = copy.deepcopy(self.example_data)
        bad["unauthorized_side_channel"] = "bypass"
        ok, err = self.validator.validate(bad)
        self.assertFalse(ok, "Must reject document with undeclared root properties")
        self.assertIn("extra_properties:unauthorized_side_channel", err)

        bad_nested = copy.deepcopy(self.example_data)
        bad_nested["domain_scope"]["allow_wildcard_subdomains"] = True
        ok, err = self.validator.validate(bad_nested)
        self.assertFalse(ok, "Must reject document with undeclared nested properties")
        self.assertIn("extra_properties:allow_wildcard_subdomains", err)

    def test_reject_malformed_and_insecure_endpoints(self):
        # Wildcard domain
        bad_wildcard = copy.deepcopy(self.example_data)
        bad_wildcard["domain_scope"]["allowed_endpoints"] = ["https://*.example.com"]
        ok, err = self.validator.validate(bad_wildcard)
        self.assertFalse(ok, "Must reject wildcard subdomains")

        # Direct IP address
        bad_ip = copy.deepcopy(self.example_data)
        bad_ip["domain_scope"]["allowed_endpoints"] = ["https://192.168.1.1/api"]
        ok, err = self.validator.validate(bad_ip)
        self.assertFalse(ok, "Must reject direct IP address endpoints")

        # Non-HTTPS endpoint
        bad_http = copy.deepcopy(self.example_data)
        bad_http["domain_scope"]["allowed_endpoints"] = ["http://arxiv.org/abs"]
        ok, err = self.validator.validate(bad_http)
        self.assertFalse(ok, "Must reject non-HTTPS endpoints")

        # Consecutive dots in hostname (empty DNS label) and out-of-range port
        bad_consecutive = copy.deepcopy(self.example_data)
        bad_consecutive["domain_scope"]["allowed_endpoints"] = ["https://a..com:99999/"]
        ok, err = self.validator.validate(bad_consecutive)
        self.assertFalse(ok, "Must reject consecutive dots and port > 65535")

        bad_dots = copy.deepcopy(self.example_data)
        bad_dots["domain_scope"]["allowed_endpoints"] = ["https://a..com/"]
        ok, err = self.validator.validate(bad_dots)
        self.assertFalse(ok, "Must reject empty DNS labels")

        # Port out of bounds (99999, 65536, 0)
        bad_port = copy.deepcopy(self.example_data)
        bad_port["domain_scope"]["allowed_endpoints"] = ["https://example.com:99999/"]
        ok, err = self.validator.validate(bad_port)
        self.assertFalse(ok, "Must reject port 99999")

        bad_port_zero = copy.deepcopy(self.example_data)
        bad_port_zero["domain_scope"]["allowed_endpoints"] = ["https://example.com:0/"]
        ok, err = self.validator.validate(bad_port_zero)
        self.assertFalse(ok, "Must reject port 0")

        bad_port_high = copy.deepcopy(self.example_data)
        bad_port_high["domain_scope"]["allowed_endpoints"] = ["https://example.com:65536/"]
        ok, err = self.validator.validate(bad_port_high)
        self.assertFalse(ok, "Must reject port 65536")

        # Whitespace and control characters
        bad_space = copy.deepcopy(self.example_data)
        bad_space["domain_scope"]["allowed_endpoints"] = ["https://example.com /path"]
        ok, err = self.validator.validate(bad_space)
        self.assertFalse(ok, "Must reject whitespace in endpoint")

        bad_ctrl = copy.deepcopy(self.example_data)
        bad_ctrl["domain_scope"]["allowed_endpoints"] = ["https://example\t.com/"]
        ok, err = self.validator.validate(bad_ctrl)
        self.assertFalse(ok, "Must reject control characters in endpoint")

    def test_reject_empty_endpoints_list(self):
        bad = copy.deepcopy(self.example_data)
        bad["domain_scope"]["allowed_endpoints"] = []
        ok, err = self.validator.validate(bad)
        self.assertFalse(ok, "Must reject empty allowed_endpoints list")
        self.assertIn("below_min_items", err)

    def test_reject_disallowed_http_methods(self):
        bad = copy.deepcopy(self.example_data)
        bad["domain_scope"]["allowed_methods"] = ["DELETE"]
        ok, err = self.validator.validate(bad)
        self.assertFalse(ok, "Must reject disallowed HTTP method DELETE")

        bad_put = copy.deepcopy(self.example_data)
        bad_put["domain_scope"]["allowed_methods"] = ["PUT"]
        ok, err = self.validator.validate(bad_put)
        self.assertFalse(ok, "Must reject disallowed HTTP method PUT")

    def test_reject_float_and_negative_bounds(self):
        # Float request budget
        bad_float = copy.deepcopy(self.example_data)
        bad_float["interaction_bounds"]["max_requests_per_session"] = 12.5
        ok, err = self.validator.validate(bad_float)
        self.assertFalse(ok, "Must reject float request budget")

        # Negative payload bytes
        bad_neg = copy.deepcopy(self.example_data)
        bad_neg["interaction_bounds"]["max_payload_bytes"] = -1
        ok, err = self.validator.validate(bad_neg)
        self.assertFalse(ok, "Must reject negative payload bytes")

        # Zero timeout
        bad_zero = copy.deepcopy(self.example_data)
        bad_zero["interaction_bounds"]["request_timeout_seconds"] = 0
        ok, err = self.validator.validate(bad_zero)
        self.assertFalse(ok, "Must reject zero timeout seconds")

    def test_reject_insecure_data_protection_flags(self):
        # Persistent cookies
        bad_cookie = copy.deepcopy(self.example_data)
        bad_cookie["data_protection"]["cookie_policy"] = "persistent"
        ok, err = self.validator.validate(bad_cookie)
        self.assertFalse(ok, "Must reject persistent cookie policy")

        # Credential retention permitted
        bad_cred = copy.deepcopy(self.example_data)
        bad_cred["data_protection"]["credential_retention_permitted"] = True
        ok, err = self.validator.validate(bad_cred)
        self.assertFalse(ok, "Must reject credential retention")

        # Disabling personal identifier stripping
        bad_strip = copy.deepcopy(self.example_data)
        bad_strip["data_protection"]["strip_personal_identifiers"] = False
        ok, err = self.validator.validate(bad_strip)
        self.assertFalse(ok, "Must reject disabling personal identifier stripping")

    def test_reject_missing_addressable_object_schema_invariants(self):
        bad = copy.deepcopy(self.example_data)
        bad["evidence_requirements"]["addressable_object_schema"]["require_address"] = False
        ok, err = self.validator.validate(bad)
        self.assertFalse(ok, "Must require addressable object address guarantee")

        bad_val = copy.deepcopy(self.example_data)
        bad_val["evidence_requirements"]["addressable_object_schema"]["require_value"] = False
        ok, err = self.validator.validate(bad_val)
        self.assertFalse(ok, "Must require addressable object value guarantee")

    def test_reject_expired_or_inverted_lifespan(self):
        bad = copy.deepcopy(self.example_data)
        bad["issued_at"] = "2026-10-12T08:00:00Z"
        bad["expires_at"] = "2026-10-12T04:00:00Z"
        ok, err = self.validator.validate(bad)
        self.assertFalse(ok, "Must reject inverted lifespan window")
        self.assertIn("expires_at_must_be_after_issued_at", err)

        bad_equal = copy.deepcopy(self.example_data)
        bad_equal["issued_at"] = "2026-10-12T04:00:00Z"
        bad_equal["expires_at"] = "2026-10-12T04:00:00Z"
        ok, err = self.validator.validate(bad_equal)
        self.assertFalse(ok, "Must reject zero-length lifespan window")
        self.assertIn("expires_at_must_be_after_issued_at", err)

    def test_reject_malformed_signature_format(self):
        bad = copy.deepcopy(self.example_data)
        bad["signatures"][0]["signature"] = "rsa:invalidformat123456"
        ok, err = self.validator.validate(bad)
        self.assertFalse(ok, "Must reject non-ed25519 signature format")


if __name__ == "__main__":
    unittest.main()
