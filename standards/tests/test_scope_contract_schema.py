#!/usr/bin/env python3
"""Fail-closed validator and conformance tests for AgentScopeContract v0.1.0."""
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

            elif p_type == "object":
                ok, err = self._validate_obj(val, p_schema, sub_path)
                if not ok:
                    return False, err

        return True, None

    def validate(self, doc: dict) -> tuple[bool, str | None]:
        if not isinstance(doc, dict):
            return False, "root:must_be_object"
        ok, err = self._validate_obj(doc, self.schema, "")
        if not ok:
            return False, err

        # Domain boundary rule 1: Non-zero valid lifecycle window
        try:
            t_issued = parse_iso8601(doc["issued_at"])
            t_expires = parse_iso8601(doc["expires_at"])
            if t_expires <= t_issued:
                return False, "contract:expires_at_must_be_greater_than_issued_at"
        except Exception as e:
            return False, f"contract:timestamp_validation_failed:{e}"

        # Domain boundary rule 2: Principal type and ID alignment
        princ = doc.get("principal", {})
        p_type = princ.get("principal_type")
        p_id = princ.get("principal_id")
        if p_type and p_id and not p_id.startswith(f"{p_type}:"):
            return False, f"principal:id_prefix_mismatch_with_type:{p_type}"

        # Domain boundary rule 3: Filesystem path traversal barriers
        fs_policy = doc.get("execution_bounds", {}).get("filesystem_policy", {})
        for root_key in ("allowed_read_roots", "allowed_write_roots"):
            for idx, path_val in enumerate(fs_policy.get(root_key, [])):
                if not isinstance(path_val, str) or not path_val.strip():
                    return False, f"filesystem_policy:{root_key}[{idx}]:empty_path"
                if not path_val.startswith("/"):
                    return False, f"filesystem_policy:{root_key}[{idx}]:must_be_absolute_posix_path"
                if ".." in path_val or "./" in path_val:
                    return False, f"filesystem_policy:{root_key}[{idx}]:path_traversal_prohibited"
                if "\\" in path_val or ":" in path_val:
                    return False, f"filesystem_policy:{root_key}[{idx}]:invalid_path_separators"
                if path_val.endswith(".") or path_val.endswith(" "):
                    return False, f"filesystem_policy:{root_key}[{idx}]:trailing_dot_or_space_prohibited"

        # Domain boundary rule 4: Egress allowlist, mode, and IP controls
        egress = doc.get("egress_controls", {})
        mode = egress.get("mode")
        endpoints = egress.get("allowed_endpoints", [])
        if mode == "offline" and endpoints:
            return False, "egress_controls:offline_mode_requires_empty_endpoints"
        if mode == "allowlist_only" and not endpoints:
            return False, "egress_controls:allowlist_only_requires_non_empty_endpoints"

        if egress.get("prohibit_direct_ip"):
            for idx, ep in enumerate(endpoints):
                m = re.match(r"^https://([^:/]+)", ep)
                if m:
                    host = m.group(1)
                    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host) or ":" in host:
                        return False, f"egress_controls:direct_ip_endpoint_prohibited:{host}"

        return True, None


class TestAgentScopeContractSchema(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        standards_dir = Path(__file__).resolve().parent.parent
        cls.schema_path = standards_dir / "agent-scope-contract-v0.1.json"
        cls.example_path = standards_dir / "examples" / "research-agent-scope-contract.json"

        with open(cls.schema_path, "r", encoding="utf-8") as f:
            cls.schema_dict = json.load(f)
        cls.validator = SchemaValidator(cls.schema_dict)

        with open(cls.example_path, "r", encoding="utf-8") as f:
            cls.example_doc = json.load(f)

    def test_schema_metadata(self):
        self.assertEqual(self.schema_dict.get("$schema"), "http://json-schema.org/draft-07/schema#")
        self.assertEqual(self.schema_dict.get("version"), "0.1.0")
        self.assertEqual(self.schema_dict.get("title"), "AgentScopeContract")
        self.assertFalse(self.schema_dict.get("additionalProperties"))

    def test_example_document_validates(self):
        ok, err = self.validator.validate(self.example_doc)
        self.assertTrue(ok, f"Valid example failed validation: {err}")

    def test_fail_closed_on_missing_required_fields(self):
        required_fields = self.schema_dict["required"]
        for field in required_fields:
            with self.subTest(missing_field=field):
                doc = copy.deepcopy(self.example_doc)
                del doc[field]
                ok, err = self.validator.validate(doc)
                self.assertFalse(ok, f"Validation should fail when {field} is missing")
                self.assertIn(f"missing_required_property:{field}", err or "")

    def test_fail_closed_on_root_extra_properties(self):
        doc = copy.deepcopy(self.example_doc)
        doc["unauthorized_escalation"] = True
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("extra_properties:unauthorized_escalation", err or "")

    def test_fail_closed_on_nested_extra_properties(self):
        doc = copy.deepcopy(self.example_doc)
        doc["resource_quotas"]["unmetered_gpu"] = 1
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("extra_properties:unmetered_gpu", err or "")

    def test_integer_only_resource_quotas(self):
        # Float quotas must be rejected
        doc = copy.deepcopy(self.example_doc)
        doc["resource_quotas"]["max_wall_time_seconds"] = 14400.5
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("must_be_integer", err or "")

        # Boolean quotas must be rejected
        doc = copy.deepcopy(self.example_doc)
        doc["resource_quotas"]["max_wall_time_seconds"] = True
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("must_be_integer", err or "")

        # Below minimum quotas must be rejected
        doc = copy.deepcopy(self.example_doc)
        doc["resource_quotas"]["max_wall_time_seconds"] = 0
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("below_minimum", err or "")

    def test_mandatory_auto_halt_on_violation(self):
        doc = copy.deepcopy(self.example_doc)
        doc["termination_conditions"]["auto_halt_on_boundary_violation"] = False
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("const_mismatch", err or "")

    def test_prohibited_cross_run_persistence(self):
        doc = copy.deepcopy(self.example_doc)
        doc["termination_conditions"]["cross_run_persistence_permitted"] = True
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("const_mismatch", err or "")

    def test_expiry_strictly_after_issuance(self):
        # Expired before issuance
        doc = copy.deepcopy(self.example_doc)
        doc["expires_at"] = "2026-10-11T10:00:00Z"
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("expires_at_must_be_greater_than_issued_at", err or "")

        # Equal timestamp
        doc = copy.deepcopy(self.example_doc)
        doc["expires_at"] = doc["issued_at"]
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("expires_at_must_be_greater_than_issued_at", err or "")

    def test_timezone_offset_required(self):
        doc = copy.deepcopy(self.example_doc)
        doc["issued_at"] = "2026-10-11T12:00:00"  # Missing 'Z' or offset
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("invalid_datetime", err or "")

    def test_egress_allowlist_requires_endpoints(self):
        doc = copy.deepcopy(self.example_doc)
        doc["egress_controls"]["mode"] = "allowlist_only"
        doc["egress_controls"]["allowed_endpoints"] = []
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("allowlist_only_requires_non_empty_endpoints", err or "")

    def test_permitted_tools_cannot_be_empty(self):
        doc = copy.deepcopy(self.example_doc)
        doc["execution_bounds"]["permitted_tools"] = []
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("below_min_items", err or "")

    def test_signatures_cannot_be_empty(self):
        doc = copy.deepcopy(self.example_doc)
        doc["signatures"] = []
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("below_min_items", err or "")

    def test_fail_closed_on_path_traversal(self):
        traversal_cases = [
            "../../etc/shadow",
            "../..",
            "./relative/path",
            r"..\..\Windows",
            r"/workspace/..\etc",
        ]
        for bad_path in traversal_cases:
            with self.subTest(bad_path=bad_path):
                doc = copy.deepcopy(self.example_doc)
                doc["execution_bounds"]["filesystem_policy"]["allowed_read_roots"] = [bad_path]
                ok, err = self.validator.validate(doc)
                self.assertFalse(ok, f"Path traversal '{bad_path}' should be rejected")

                doc2 = copy.deepcopy(self.example_doc)
                doc2["execution_bounds"]["filesystem_policy"]["allowed_write_roots"] = [bad_path]
                ok2, err2 = self.validator.validate(doc2)
                self.assertFalse(ok2, f"Write root traversal '{bad_path}' should be rejected")

    def test_fail_closed_on_trailing_dots_and_spaces(self):
        dot_cases = [
            "/workspace/dir.",
            "/workspace/dir ",
            "/workspace/dir..",
        ]
        for bad_path in dot_cases:
            with self.subTest(bad_path=bad_path):
                doc = copy.deepcopy(self.example_doc)
                doc["execution_bounds"]["filesystem_policy"]["allowed_read_roots"] = [bad_path]
                ok, err = self.validator.validate(doc)
                self.assertFalse(ok, f"Trailing dot/space path '{bad_path}' should be rejected")

    def test_fail_closed_on_empty_string_roots_and_capabilities(self):
        # Empty string read root
        doc = copy.deepcopy(self.example_doc)
        doc["execution_bounds"]["filesystem_policy"]["allowed_read_roots"] = [""]
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)

        # Empty string forbidden capabilities
        doc = copy.deepcopy(self.example_doc)
        doc["execution_bounds"]["forbidden_capabilities"] = [""]
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)

        # Empty string forbidden patterns
        doc = copy.deepcopy(self.example_doc)
        doc["execution_bounds"]["filesystem_policy"]["forbidden_patterns"] = [""]
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)

    def test_fail_closed_on_direct_ip_egress(self):
        ip_endpoints = [
            "https://192.168.1.1/admin",
            "https://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1:8080/metrics",
        ]
        for ep in ip_endpoints:
            with self.subTest(endpoint=ep):
                doc = copy.deepcopy(self.example_doc)
                doc["egress_controls"]["allowed_endpoints"] = [ep]
                ok, err = self.validator.validate(doc)
                self.assertFalse(ok, f"Direct IP endpoint '{ep}' should be rejected")

    def test_fail_closed_on_offline_mode_with_active_endpoints(self):
        doc = copy.deepcopy(self.example_doc)
        doc["egress_controls"]["mode"] = "offline"
        doc["egress_controls"]["allowed_endpoints"] = ["https://export.arxiv.org/api/query"]
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("offline_mode_requires_empty_endpoints", err or "")

        # When offline and empty, it must validate successfully
        doc["egress_controls"]["allowed_endpoints"] = []
        ok2, err2 = self.validator.validate(doc)
        self.assertTrue(ok2, f"Offline mode with empty endpoints should pass: {err2}")

    def test_fail_closed_on_principal_type_and_id_mismatch(self):
        doc = copy.deepcopy(self.example_doc)
        doc["principal"]["principal_type"] = "person"
        doc["principal"]["principal_id"] = "cooperative:group1"
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("id_prefix_mismatch_with_type", err or "")


if __name__ == "__main__":
    unittest.main()
