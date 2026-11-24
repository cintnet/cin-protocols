#!/usr/bin/env python3
"""Fail-closed validator and conformance tests for AgentMortalContract v0.1.0."""
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
    # Must have timezone indicator
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
    """Fail-closed validator enforcing types, bounds, enums, formats, and no extra properties."""

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
                    return False, f"{sub_path}:enum_violation:{val}"
                if p_schema.get("format") == "date-time":
                    try:
                        parse_iso8601(val)
                    except Exception as e:
                        return False, f"{sub_path}:invalid_datetime_format:{str(e)}"
            elif p_type == "integer":
                if not isinstance(val, int) or isinstance(val, bool):
                    return False, f"{sub_path}:must_be_integer"
                if "minimum" in p_schema and val < p_schema["minimum"]:
                    return False, f"{sub_path}:minimum_violation:{val}<{p_schema['minimum']}"
            elif p_type == "boolean":
                if not isinstance(val, bool):
                    return False, f"{sub_path}:must_be_boolean"
            elif p_type == "array":
                if not isinstance(val, list):
                    return False, f"{sub_path}:must_be_array"
                if "minItems" in p_schema and len(val) < p_schema["minItems"]:
                    return False, f"{sub_path}:min_items_violation"
                items_schema = p_schema.get("items", {})
                for idx, item in enumerate(val):
                    item_path = f"{sub_path}[{idx}]"
                    if items_schema.get("type") == "object":
                        ok, err = self._validate_obj(item, items_schema, item_path)
                        if not ok:
                            return False, err
                    elif items_schema.get("type") == "string":
                        if not isinstance(item, str):
                            return False, f"{item_path}:must_be_string"
                        if "minLength" in items_schema and len(item) < items_schema["minLength"]:
                            return False, f"{item_path}:min_length_violation"
            elif p_type == "object":
                ok, err = self._validate_obj(val, p_schema, sub_path)
                if not ok:
                    return False, err

        return True, None

    def validate(self, doc: dict) -> tuple[bool, str | None]:
        ok, err = self._validate_obj(doc, self.schema, "")
        if not ok:
            return False, err

        # Semantic lifecycle checks
        try:
            issued = parse_iso8601(doc["issued_at"])
            expires = parse_iso8601(doc["expires_at"])
        except Exception as e:
            return False, f"lifecycle:datetime_parse_error:{str(e)}"

        if expires <= issued:
            return False, "lifecycle:expires_at_must_be_after_issued_at"

        # Fail-closed allowlist check (Lesson 31 & Checklist 2)
        remote = doc.get("remote_models", {})
        if remote.get("permitted") is True:
            allowed = remote.get("allowed_providers", [])
            if not allowed:
                return False, "remote_models:empty_allowlist_when_permitted"

        return True, None


def is_active(contract: dict, evaluation_time_str: str | None = None) -> bool:
    """Evaluate whether contract is currently active at evaluation time (defaults to UTC now)."""
    try:
        if evaluation_time_str is None:
            eval_dt = datetime.now(timezone.utc)
        else:
            eval_dt = parse_iso8601(evaluation_time_str)
        issued_dt = parse_iso8601(contract["issued_at"])
        expires_dt = parse_iso8601(contract["expires_at"])
        return issued_dt <= eval_dt < expires_dt
    except Exception:
        return False


class TestAgentMortalContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base_dir = Path(__file__).resolve().parent.parent
        schema_path = base_dir / "agent-mortal-contract-v0.1.json"
        example_path = base_dir / "examples" / "personal-twin-mortal-contract.json"
        cls.schema = json.loads(schema_path.read_text(encoding="utf-8"))
        cls.example = json.loads(example_path.read_text(encoding="utf-8"))
        cls.validator = SchemaValidator(cls.schema)

    def test_example_validates(self):
        ok, err = self.validator.validate(self.example)
        self.assertTrue(ok, f"Example failed validation: {err}")

    def test_missing_required_property(self):
        doc = copy.deepcopy(self.example)
        del doc["budgets"]
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("missing_required_property:budgets", err)

    def test_extra_property_root_rejected(self):
        doc = copy.deepcopy(self.example)
        doc["unauthorized_field"] = "exploit"
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("extra_properties", err)

    def test_extra_property_nested_rejected(self):
        doc = copy.deepcopy(self.example)
        doc["budgets"]["unmetered_gpus"] = 8
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("budgets:extra_properties", err)

    def test_naive_timestamp_rejected(self):
        doc = copy.deepcopy(self.example)
        doc["issued_at"] = "2026-10-11T00:00:00"  # Missing timezone offset
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("invalid_datetime_format", err)

    def test_inverted_lifespan_rejected(self):
        doc = copy.deepcopy(self.example)
        doc["issued_at"] = "2026-11-10T00:00:00Z"
        doc["expires_at"] = "2026-10-11T00:00:00Z"
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("expires_at_must_be_after_issued_at", err)

    def test_equal_issued_and_expires_rejected(self):
        doc = copy.deepcopy(self.example)
        doc["expires_at"] = doc["issued_at"]
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("expires_at_must_be_after_issued_at", err)

    def test_negative_budget_rejected(self):
        doc = copy.deepcopy(self.example)
        doc["budgets"]["inference_units_per_day"] = -100
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("minimum_violation", err)

    def test_zero_memory_mb_rejected(self):
        doc = copy.deepcopy(self.example)
        doc["budgets"]["memory_mb"] = 0
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("minimum_violation", err)

    def test_float_budget_rejected(self):
        doc = copy.deepcopy(self.example)
        doc["budgets"]["inference_units_per_day"] = 500000.5
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("must_be_integer", err)

    def test_boolean_as_integer_budget_rejected(self):
        doc = copy.deepcopy(self.example)
        doc["budgets"]["inference_units_per_day"] = True
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("must_be_integer", err)

    def test_empty_approvers_rejected(self):
        doc = copy.deepcopy(self.example)
        doc["approvers"] = []
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("min_items_violation", err)

    def test_empty_signatures_rejected(self):
        doc = copy.deepcopy(self.example)
        doc["signatures"] = []
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("min_items_violation", err)

    def test_malformed_signature_hex_rejected(self):
        doc = copy.deepcopy(self.example)
        doc["signatures"][0]["signature_hex"] = "not_hex_chars_12345"
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("pattern_mismatch", err)

    def test_empty_allowlist_when_remote_permitted_rejected(self):
        doc = copy.deepcopy(self.example)
        doc["remote_models"]["permitted"] = True
        doc["remote_models"]["allowed_providers"] = []
        doc["remote_models"]["max_data_sensitivity"] = "pseudonymous"
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("empty_allowlist_when_permitted", err)

    def test_valid_remote_models_configuration_passes(self):
        doc = copy.deepcopy(self.example)
        doc["remote_models"]["permitted"] = True
        doc["remote_models"]["allowed_providers"] = ["local_coop_host", "audit_peer"]
        doc["remote_models"]["max_data_sensitivity"] = "pseudonymous"
        ok, err = self.validator.validate(doc)
        self.assertTrue(ok, f"Expected valid remote config to pass, got: {err}")

    def test_invalid_capability_tier_rejected(self):
        doc = copy.deepcopy(self.example)
        doc["capability_tier"] = "unbounded_superintelligence"
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("enum_violation", err)

    def test_active_evaluation_lifecycle(self):
        # Active assertions
        self.assertTrue(is_active(self.example, "2026-10-11T00:00:00Z"))
        self.assertTrue(is_active(self.example, "2026-10-15T12:00:00Z"))
        # Inactive boundary assertions
        self.assertFalse(is_active(self.example, "2026-10-10T23:59:59Z"))
        self.assertFalse(is_active(self.example, "2026-11-10T00:00:00Z"))
        self.assertFalse(is_active(self.example, "2026-11-15T00:00:00Z"))
        # Lesson 57: Test future issuance and omitted clock argument
        future_doc = copy.deepcopy(self.example)
        future_doc["issued_at"] = "2027-01-01T00:00:00Z"
        future_doc["expires_at"] = "2027-02-01T00:00:00Z"
        self.assertFalse(is_active(future_doc))  # Clock omitted, evaluated against UTC now (2026)
        # Malformed / naive string fail-closed
        self.assertFalse(is_active(self.example, "invalid_timestamp"))
        self.assertFalse(is_active(self.example, "2026-10-15T12:00:00"))  # Naive


if __name__ == "__main__":
    unittest.main()
