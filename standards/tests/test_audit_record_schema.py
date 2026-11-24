#!/usr/bin/env python3
"""Fail-closed validator and conformance tests for AgentAuditRecord v0.1.0."""
import copy, hashlib, json, re, sys
from datetime import datetime
from pathlib import Path


def parse_iso8601(dt_str: str) -> datetime:
    if not isinstance(dt_str, str) or not dt_str.strip():
        raise ValueError("timestamp must be non-empty string")
    # Require explicit timezone offset (Z or +/-HH:MM)
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
            if isinstance(p_type, list):
                matched = any(
                    (t == "string" and isinstance(val, str)) or
                    (t == "null" and val is None) or
                    (t == "integer" and isinstance(val, int) and not isinstance(val, bool)) or
                    (t == "boolean" and isinstance(val, bool))
                    for t in p_type
                )
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
                if not valid:
                    return False, err
            if p_schema.get("format") == "date-time":
                if not isinstance(val, str):
                    return False, f"{sub_path}:date_time_must_be_string"
                try:
                    parse_iso8601(val)
                except Exception as e:
                    return False, f"{sub_path}:invalid_date_time:{e}"
            if p_type == "integer" and "minimum" in p_schema and val < p_schema["minimum"]:
                return False, f"{sub_path}:minimum_violation"
            if "const" in p_schema and val != p_schema["const"]:
                return False, f"{sub_path}:const_mismatch:{val}!={p_schema['const']}"
            if "enum" in p_schema and val not in p_schema["enum"]:
                return False, f"{sub_path}:enum_violation:{val}"
            if "pattern" in p_schema and isinstance(val, str) and not re.match(p_schema["pattern"], val):
                return False, f"{sub_path}:pattern_mismatch"
            if p_type == "array" and "items" in p_schema:
                if len(val) < p_schema.get("minItems", 0):
                    return False, f"{sub_path}:min_items_violation"
                for i, item in enumerate(val):
                    item_schema = p_schema["items"]
                    if item_schema.get("type") == "object":
                        valid, err = self._validate_obj(item, item_schema, f"{sub_path}[{i}]")
                        if not valid:
                            return False, err
        return True, None

    def validate(self, doc: dict) -> tuple[bool, str | None]:
        return self._validate_obj(doc, self.schema, "")


def compute_record_digest(record: dict) -> str:
    """Deterministic canonical digest over canonical JSON representation."""
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_audit_chain(prev_record: dict, current_record: dict, validator: SchemaValidator) -> tuple[bool, str | None]:
    """Verify cryptographic hash chaining continuity and temporal order between consecutive records."""
    ok1, err1 = validator.validate(prev_record)
    if not ok1:
        return False, f"prev_record_invalid:{err1}"
    ok2, err2 = validator.validate(current_record)
    if not ok2:
        return False, f"current_record_invalid:{err2}"

    expected_hash = compute_record_digest(prev_record)
    actual_prev_hash = current_record.get("prev_record_hash")
    if actual_prev_hash != expected_hash:
        return False, f"broken_hash_chain:expected {expected_hash} but found {actual_prev_hash}"

    t_prev = parse_iso8601(prev_record["timestamp"])
    t_curr = parse_iso8601(current_record["timestamp"])
    if t_curr < t_prev:
        return False, f"temporal_inversion:current timestamp {t_curr} precedes prev {t_prev}"

    return True, None


def run_tests() -> int:
    base = Path(__file__).resolve().parent.parent
    schema_file = base / "agent-audit-record-v0.1.json"
    example_file = base / "examples" / "runtime-gate-audit-record.json"

    with open(schema_file, encoding="utf-8") as f:
        schema = json.load(f)
    validator = SchemaValidator(schema)

    with open(example_file, encoding="utf-8") as f:
        example = json.load(f)

    # Positive check 1: Example document
    ok, err = validator.validate(example)
    assert ok, f"Example failed schema validation: {err}"

    # Positive check 2: Timestamp parse
    ts = parse_iso8601(example["timestamp"])
    assert ts.year == 2026, "Expected year 2026"

    # Positive check 3: Chaining verification helper between consecutive valid records
    rec1 = copy.deepcopy(example)
    digest1 = compute_record_digest(rec1)
    rec2 = copy.deepcopy(example)
    rec2["record_id"] = "audit-20261010-002"
    rec2["prev_record_hash"] = digest1
    rec2["timestamp"] = "2026-10-10T14:05:00Z"
    chain_ok, chain_err = verify_audit_chain(rec1, rec2, validator)
    assert chain_ok, f"Audit chain verification failed: {chain_err}"

    # Fail-closed adversarial checks
    # 1. Non-date string timestamp fails closed
    bad = copy.deepcopy(example); bad["timestamp"] = "not_a_timestamp"
    assert not validator.validate(bad)[0], "Accepted non-date string timestamp"

    # 2. Naive timestamp without timezone fails closed
    bad = copy.deepcopy(example); bad["timestamp"] = "2026-10-10T14:00:00"
    assert not validator.validate(bad)[0], "Accepted naive timestamp without timezone"

    # 3. Out-of-bounds date fails closed
    bad = copy.deepcopy(example); bad["timestamp"] = "2026-99-99T99:99:99Z"
    assert not validator.validate(bad)[0], "Accepted out-of-bounds timestamp"

    # 4. Broken hash chain detected and rejected
    bad_rec2 = copy.deepcopy(rec2)
    bad_rec2["prev_record_hash"] = "0" * 64
    chain_ok, err = verify_audit_chain(rec1, bad_rec2, validator)
    assert not chain_ok and "broken_hash_chain" in err, "Accepted broken hash chain"

    # 5. Temporal inversion in chain detected and rejected
    inverted_rec2 = copy.deepcopy(rec2)
    inverted_rec2["prev_record_hash"] = digest1
    inverted_rec2["timestamp"] = "2026-10-10T13:50:00Z"  # 10 minutes prior to rec1
    chain_ok, err = verify_audit_chain(rec1, inverted_rec2, validator)
    assert not chain_ok and "temporal_inversion" in err, "Accepted temporal inversion in chain"

    # 6. Extra top-level property rejected
    bad = copy.deepcopy(example); bad["leak_field"] = "bad"
    assert not validator.validate(bad)[0], "Accepted extra top-level field"

    # 7. Extra property inside adjudication rejected
    bad = copy.deepcopy(example); bad["adjudication"]["unauthorized_override"] = True
    assert not validator.validate(bad)[0], "Accepted extra adjudication field"

    # 8. Extra property inside evidence (raw payload leak) rejected
    bad = copy.deepcopy(example); bad["evidence"]["raw_payload"] = "plaintext"
    assert not validator.validate(bad)[0], "Accepted raw payload in evidence"

    # 9. Unknown action plane rejected
    bad = copy.deepcopy(example); bad["action_plane"] = "arbitrary_plane"
    assert not validator.validate(bad)[0], "Accepted unknown action plane"

    # 10. Unknown adjudication decision rejected
    bad = copy.deepcopy(example); bad["adjudication"]["decision"] = "ignore_policy"
    assert not validator.validate(bad)[0], "Accepted unknown adjudication decision"

    # 11. Malformed record_id rejected
    bad = copy.deepcopy(example); bad["record_id"] = "bad-id!"
    assert not validator.validate(bad)[0], "Accepted malformed record_id"

    # 12. Short / non-hex prev_record_hash rejected
    bad = copy.deepcopy(example); bad["prev_record_hash"] = "short_hash"
    assert not validator.validate(bad)[0], "Accepted non-hex prev_record_hash"

    # 13. Negative tokens used rejected
    bad = copy.deepcopy(example); bad["evidence"]["tokens_used"] = -1
    assert not validator.validate(bad)[0], "Accepted negative tokens_used"

    # 14. Non-integer tokens used rejected
    bad = copy.deepcopy(example); bad["evidence"]["tokens_used"] = 12.5
    assert not validator.validate(bad)[0], "Accepted float tokens_used"

    # 15. Boolean tokens used rejected
    bad = copy.deepcopy(example); bad["evidence"]["tokens_used"] = True
    assert not validator.validate(bad)[0], "Accepted bool tokens_used"

    # 16. Unknown sensitivity tier rejected
    bad = copy.deepcopy(example); bad["evidence"]["sensitivity"] = "confidential_top_secret"
    assert not validator.validate(bad)[0], "Accepted non-enumerated sensitivity tier"

    # 17. Empty signatures list rejected
    bad = copy.deepcopy(example); bad["signatures"] = []
    assert not validator.validate(bad)[0], "Accepted empty signatures"

    # 18. Invalid signature role rejected
    bad = copy.deepcopy(example); bad["signatures"][0]["signer_role"] = "untrusted_party"
    assert not validator.validate(bad)[0], "Accepted untrusted signer role"

    # 19. Invalid signature algorithm rejected
    bad = copy.deepcopy(example); bad["signatures"][0]["algorithm"] = "md5"
    assert not validator.validate(bad)[0], "Accepted weak signature algorithm"

    # 20. Invalid signature length (not 128 hex chars) rejected
    bad = copy.deepcopy(example); bad["signatures"][0]["signature_hex"] = "112233"
    assert not validator.validate(bad)[0], "Accepted short signature hex"

    print("PASS: 3 positive checks and 20 adversarial fail-closed conformance checks passed.")
    return 0


import unittest

class TestAuditRecordSchema(unittest.TestCase):
    def test_audit_record_conformance_and_adversarial(self):
        self.assertEqual(run_tests(), 0)

if __name__ == "__main__":
    unittest.main()
