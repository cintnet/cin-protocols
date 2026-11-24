#!/usr/bin/env python3
"""Fail-closed validator and conformance tests for AgentEvidenceReceipt v0.1.0."""
import copy
import json
import re
import unittest
from datetime import datetime
from pathlib import Path


def parse_iso8601(dt_str: str) -> datetime:
    if not isinstance(dt_str, str) or not dt_str.strip():
        raise ValueError("timestamp must be non-empty string")
    if not (dt_str.endswith("Z") or re.search(r"[+-]\d{2}:\d{2}$", dt_str)):
        raise ValueError("timestamp must include explicit timezone offset (Z or +/-HH:MM)")
    iso_norm = dt_str[:-1] + "+00:00" if dt_str.endswith("Z") else dt_str
    dt = datetime.fromisoformat(iso_norm)
    if dt.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return dt


class SchemaValidator:
    """Fail-closed validator enforcing schema types, bounds, enums, date-time, and no extra properties."""

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
            p_schema = props[key]
            sub_path = f"{path}.{key}" if path else key
            p_type = p_schema.get("type")
            if p_type == "string":
                if not isinstance(val, str):
                    return False, f"{sub_path}:must_be_string"
                if "const" in p_schema and val != p_schema["const"]:
                    return False, f"{sub_path}:const_mismatch:{val}"
                if "enum" in p_schema and val not in p_schema["enum"]:
                    return False, f"{sub_path}:invalid_enum:{val}"
                if "pattern" in p_schema and not re.search(p_schema["pattern"], val):
                    return False, f"{sub_path}:pattern_mismatch:{val}"
                if p_schema.get("format") == "date-time":
                    try:
                        parse_iso8601(val)
                    except Exception as e:
                        return False, f"{sub_path}:invalid_date_time:{e}"
            elif p_type == "integer":
                if not isinstance(val, int) or isinstance(val, bool):
                    return False, f"{sub_path}:must_be_integer"
                if "minimum" in p_schema and val < p_schema["minimum"]:
                    return False, f"{sub_path}:below_minimum:{val}"
            elif p_type == "boolean":
                if not isinstance(val, bool):
                    return False, f"{sub_path}:must_be_boolean"
            elif p_type == "object":
                ok, err = self._validate_obj(val, p_schema, sub_path)
                if not ok:
                    return False, err
            elif p_type == "array":
                if not isinstance(val, list):
                    return False, f"{sub_path}:must_be_array"
                if "minItems" in p_schema and len(val) < p_schema["minItems"]:
                    return False, f"{sub_path}:below_minItems:{len(val)}"
                item_schema = p_schema.get("items", {})
                for idx, item in enumerate(val):
                    elem_path = f"{sub_path}[{idx}]"
                    item_type = item_schema.get("type")
                    if item_type == "string":
                        if not isinstance(item, str):
                            return False, f"{elem_path}:must_be_string"
                        if "pattern" in item_schema and not re.search(item_schema["pattern"], item):
                            return False, f"{elem_path}:pattern_mismatch:{item}"
                    elif item_type == "object":
                        ok, err = self._validate_obj(item, item_schema, elem_path)
                        if not ok:
                            return False, err
        return True, None

    def validate(self, doc: dict) -> tuple[bool, str | None]:
        return self._validate_obj(doc, self.schema, "")


class TestEvidenceReceiptSchema(unittest.TestCase):
    def setUp(self):
        repo_root = Path(__file__).resolve().parent.parent
        self.schema_path = repo_root / "agent-evidence-receipt-v0.1.json"
        self.example_path = repo_root / "examples" / "dentist-sensor-evidence-receipt.json"

        with open(self.schema_path, "r", encoding="utf-8") as f:
            self.schema = json.load(f)
        self.validator = SchemaValidator(self.schema)

        with open(self.example_path, "r", encoding="utf-8") as f:
            self.valid_doc = json.load(f)

    def test_valid_example_document(self):
        ok, err = self.validator.validate(self.valid_doc)
        self.assertTrue(ok, f"Valid example failed validation: {err}")

    def test_missing_required_property(self):
        doc = copy.deepcopy(self.valid_doc)
        del doc["manifest_hash"]
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("missing_required_property:manifest_hash", str(err))

    def test_extra_property_rejected(self):
        doc = copy.deepcopy(self.valid_doc)
        doc["unauthorized_telemetry"] = "leak"
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("extra_properties:unauthorized_telemetry", str(err))

    def test_extra_property_in_nested_check_rejected(self):
        doc = copy.deepcopy(self.valid_doc)
        doc["sufficiency_check"]["unknown_field"] = 123
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("extra_properties:unknown_field", str(err))

    def test_invalid_hash_pattern(self):
        doc = copy.deepcopy(self.valid_doc)
        doc["manifest_hash"] = "not-a-64-char-hex-hash"
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("pattern_mismatch", str(err))

    def test_invalid_evidence_hash_pattern(self):
        doc = copy.deepcopy(self.valid_doc)
        doc["sufficiency_check"]["evidence_hashes"][0] = "short_hash"
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("pattern_mismatch", str(err))

    def test_empty_evidence_hashes_rejected(self):
        doc = copy.deepcopy(self.valid_doc)
        doc["sufficiency_check"]["evidence_hashes"] = []
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("below_minItems", str(err))

    def test_invalid_verdict_enum(self):
        doc = copy.deepcopy(self.valid_doc)
        doc["verdict"] = "MAYBE"
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("invalid_enum:MAYBE", str(err))

    def test_invalid_claim_scope_enum(self):
        doc = copy.deepcopy(self.valid_doc)
        doc["claim_scope"] = "unbounded_action"
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("invalid_enum:unbounded_action", str(err))

    def test_integer_type_rejects_floats(self):
        doc = copy.deepcopy(self.valid_doc)
        doc["coverage_check"]["committed_action_count"] = 3.5
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("must_be_integer", str(err))

    def test_integer_type_rejects_booleans(self):
        doc = copy.deepcopy(self.valid_doc)
        doc["coverage_check"]["committed_action_count"] = True
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("must_be_integer", str(err))

    def test_negative_action_count_rejected(self):
        doc = copy.deepcopy(self.valid_doc)
        doc["coverage_check"]["committed_action_count"] = -1
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("below_minimum", str(err))

    def test_invalid_signature_hex_length(self):
        doc = copy.deepcopy(self.valid_doc)
        doc["signatures"][0]["signature_hex"] = "abcdef"
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("pattern_mismatch", str(err))

    def test_empty_signatures_rejected(self):
        doc = copy.deepcopy(self.valid_doc)
        doc["signatures"] = []
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("below_minItems", str(err))

    def test_missing_timezone_offset_rejected(self):
        doc = copy.deepcopy(self.valid_doc)
        doc["issued_at"] = "2026-10-11T13:45:00"  # No Z or offset
        ok, err = self.validator.validate(doc)
        self.assertFalse(ok)
        self.assertIn("invalid_date_time", str(err))


if __name__ == "__main__":
    unittest.main()
