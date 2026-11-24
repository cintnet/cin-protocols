"""Unit and conformance tests for Agent Control Incident Response specification.

Validates schema constraints, fail-closed type checking, lifecycle state machine
rules, and tamper-resistant cryptographic digest calculation.
"""

from __future__ import annotations

import json
from pathlib import Path
import unittest

from research.standards.agent_control_incident_response import (
    AgentControlIncidentRecord,
    IncidentValidationError,
    validate_incident_dict,
)


class TestAgentControlIncidentResponse(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.standards_dir = Path(__file__).resolve().parent.parent
        cls.schema_path = cls.standards_dir / "agent-control-incident-response-v0.1.json"
        cls.example_path = cls.standards_dir / "examples" / "agent-control-incident-record-example.json"

        with open(cls.schema_path, "r", encoding="utf-8") as f:
            cls.schema_data = json.load(f)

        with open(cls.example_path, "r", encoding="utf-8") as f:
            cls.example_data = json.load(f)

    def test_schema_json_structure(self):
        """Schema declares draft-07, object type, and mandatory fields."""
        self.assertEqual(self.schema_data.get("$schema"), "http://json-schema.org/draft-07/schema#")
        self.assertEqual(self.schema_data.get("title"), "AgentControlIncidentRecord")
        self.assertEqual(self.schema_data.get("type"), "object")
        self.assertFalse(self.schema_data.get("additionalProperties"))
        self.assertIn("lifecycle_stage", self.schema_data.get("required", []))

    def test_valid_example_record_passes(self):
        """Example record conforms to schema and produces an immutable record object."""
        rec = validate_incident_dict(self.example_data)
        self.assertIsInstance(rec, AgentControlIncidentRecord)
        self.assertEqual(rec.incident_id, "inc-20261030-001a4f9b")
        self.assertEqual(rec.lifecycle_stage, "recover")
        self.assertTrue(rec.response_containment.execution_halted)
        self.assertTrue(rec.recovery_verification.containment_verified)

    def test_deterministic_digest_stability(self):
        """Digest is a deterministic 64-character SHA-256 string."""
        rec = validate_incident_dict(self.example_data)
        digest1 = rec.compute_digest()
        digest2 = rec.compute_digest()
        self.assertEqual(digest1, digest2)
        self.assertEqual(len(digest1), 64)

    def test_unknown_top_field_fails_closed(self):
        """Rejects unknown properties at the top level."""
        bad_data = dict(self.example_data)
        bad_data["unrecognized_injection"] = "arbitrary_payload"
        with self.assertRaises(IncidentValidationError):
            validate_incident_dict(bad_data)

    def test_missing_required_field_fails_closed(self):
        """Rejects record when mandatory field is missing."""
        bad_data = dict(self.example_data)
        del bad_data["detection_telemetry"]
        with self.assertRaises(IncidentValidationError):
            validate_incident_dict(bad_data)

    def test_invalid_timestamp_fails_closed(self):
        """Rejects non-ISO-8601 timestamp formats."""
        bad_data = dict(self.example_data)
        bad_data["timestamp_detected"] = "2026/10/30 03:14:02"  # non-ISO format
        with self.assertRaises(IncidentValidationError):
            validate_incident_dict(bad_data)

    def test_boolean_anomaly_score_fails_closed(self):
        """Rejects bool passed as anomaly score."""
        bad_data = json.loads(json.dumps(self.example_data))
        bad_data["detection_telemetry"]["anomaly_score"] = True
        with self.assertRaises(IncidentValidationError):
            validate_incident_dict(bad_data)

    def test_out_of_bounds_anomaly_score_fails_closed(self):
        """Rejects anomaly score > 1.0 or < 0.0 or non-finite."""
        bad_data = json.loads(json.dumps(self.example_data))
        bad_data["detection_telemetry"]["anomaly_score"] = 1.05
        with self.assertRaises(IncidentValidationError):
            validate_incident_dict(bad_data)

    def test_recovery_without_verified_containment_fails_closed(self):
        """In recover stage, containment_verified must be True."""
        bad_data = json.loads(json.dumps(self.example_data))
        bad_data["recovery_verification"]["containment_verified"] = False
        with self.assertRaises(IncidentValidationError):
            validate_incident_dict(bad_data)

    def test_recovery_without_execution_halt_fails_closed(self):
        """In recover stage, execution_halted must be True."""
        bad_data = json.loads(json.dumps(self.example_data))
        bad_data["response_containment"]["execution_halted"] = False
        with self.assertRaises(IncidentValidationError):
            validate_incident_dict(bad_data)

    def test_recovery_without_trusted_baseline_fails_closed(self):
        """In recover stage, rebuilt_from_trusted_baseline must be True."""
        bad_data = json.loads(json.dumps(self.example_data))
        bad_data["recovery_verification"]["rebuilt_from_trusted_baseline"] = False
        with self.assertRaises(IncidentValidationError):
            validate_incident_dict(bad_data)

    def test_invalid_hex_digest_fails_closed(self):
        """Rejects malformed digest that is not 64 hex characters."""
        bad_data = json.loads(json.dumps(self.example_data))
        bad_data["response_containment"]["forensic_log_digest"] = "invalid_short_hash"
        with self.assertRaises(IncidentValidationError):
            validate_incident_dict(bad_data)

    def test_fail_closed_on_nested_extra_properties(self):
        """Unrecognized fields within nested objects must raise IncidentValidationError."""
        nested_sections = (
            "preparation_baseline",
            "detection_telemetry",
            "response_containment",
            "recovery_verification",
            "reporting_status",
        )
        for section in nested_sections:
            bad_data = json.loads(json.dumps(self.example_data))
            bad_data[section]["unrecognized_extra_property"] = "rogue_payload"
            with self.assertRaises(
                IncidentValidationError,
                msg=f"Expected IncidentValidationError when {section} contains extra property",
            ):
                validate_incident_dict(bad_data)


if __name__ == "__main__":
    unittest.main()
