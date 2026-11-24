"""Unit tests for the Agent PTV Hardware Attestation Protocol Validator.

Validates fail-closed schema conformance, unknown field rejection, replay defenses,
hardware enclave trust filters, and temporal expiration invariants.
Standard library only.
"""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

STANDARDS_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = STANDARDS_DIR.parent.parent
for p in (str(STANDARDS_DIR), str(REPO_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from agent_ptv_attestation import (
    PTVAttestationError,
    PTVAttestationRecord,
    validate_ptv_attestation_dict,
    verify_ptv_attestation_exercise,
)


class TestAgentPTVAttestation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.standards_dir = Path(__file__).resolve().parent.parent
        cls.example_path = cls.standards_dir / "examples" / "agent-ptv-attestation-example.json"
        with open(cls.example_path, "r", encoding="utf-8") as f:
            cls.valid_payload = json.load(f)

    def test_valid_example_payload_passes(self):
        validated = validate_ptv_attestation_dict(self.valid_payload)
        self.assertEqual(validated["attestation_id"], self.valid_payload["attestation_id"])
        record = PTVAttestationRecord.from_dict(self.valid_payload)
        self.assertEqual(record.enclave_type, "sev-snp")
        self.assertEqual(record.phase, "VERIFY")

    def test_exercise_verification_success(self):
        res = verify_ptv_attestation_exercise(
            self.valid_payload,
            expected_nonce="nonce_20261103_exercise_challenge_99a8b7c6",
            current_time_iso="2026-11-03T15:15:00Z",
            trusted_enclave_types=["sev-snp", "nitro-enclaves"],
            trusted_key_fingerprints=["8f3b2c1d0e9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c"],
        )
        self.assertTrue(res)

    def test_unknown_root_property_rejected_fail_closed(self):
        payload = copy.deepcopy(self.valid_payload)
        payload["unauthorized_side_channel"] = "leak"
        with self.assertRaises(PTVAttestationError) as ctx:
            validate_ptv_attestation_dict(payload)
        self.assertIn("Unknown root properties forbidden", str(ctx.exception))

    def test_missing_mandatory_field_rejected(self):
        payload = copy.deepcopy(self.valid_payload)
        del payload["hardware_anchor"]
        with self.assertRaises(PTVAttestationError) as ctx:
            validate_ptv_attestation_dict(payload)
        self.assertIn("Missing mandatory root properties", str(ctx.exception))

    def test_invalid_enclave_type_rejected(self):
        payload = copy.deepcopy(self.valid_payload)
        payload["hardware_anchor"]["enclave_type"] = "untrusted-hypervisor"
        with self.assertRaises(PTVAttestationError) as ctx:
            validate_ptv_attestation_dict(payload)
        self.assertIn("Unknown enclave_type", str(ctx.exception))

    def test_invalid_attestation_key_fingerprint_length_rejected(self):
        payload = copy.deepcopy(self.valid_payload)
        payload["hardware_anchor"]["attestation_key_fingerprint"] = "short_hex"
        with self.assertRaises(PTVAttestationError) as ctx:
            validate_ptv_attestation_dict(payload)
        self.assertIn("attestation_key_fingerprint must be a 64-character lowercase hex string", str(ctx.exception))

    def test_inverted_timestamps_rejected(self):
        payload = copy.deepcopy(self.valid_payload)
        payload["issued_at"] = "2026-11-03T16:00:00Z"
        payload["expires_at"] = "2026-11-03T15:00:00Z"
        with self.assertRaises(PTVAttestationError) as ctx:
            validate_ptv_attestation_dict(payload)
        self.assertIn("expires_at", str(ctx.exception))

    def test_nonce_mismatch_fails_closed(self):
        with self.assertRaises(PTVAttestationError) as ctx:
            verify_ptv_attestation_exercise(
                self.valid_payload,
                expected_nonce="nonce_wrong_counterparty_nonce_123456",
                current_time_iso="2026-11-03T15:15:00Z",
            )
        self.assertIn("Challenge nonce mismatch", str(ctx.exception))

    def test_expired_attestation_at_exercise_time_rejected(self):
        with self.assertRaises(PTVAttestationError) as ctx:
            verify_ptv_attestation_exercise(
                self.valid_payload,
                expected_nonce="nonce_20261103_exercise_challenge_99a8b7c6",
                current_time_iso="2026-11-03T15:35:00Z",
            )
        self.assertIn("Attestation has expired", str(ctx.exception))

    def test_not_yet_valid_future_attestation_rejected(self):
        with self.assertRaises(PTVAttestationError) as ctx:
            verify_ptv_attestation_exercise(
                self.valid_payload,
                expected_nonce="nonce_20261103_exercise_challenge_99a8b7c6",
                current_time_iso="2026-11-03T14:50:00Z",
            )
        self.assertIn("Attestation not yet valid", str(ctx.exception))

    def test_untrusted_key_fingerprint_rejected(self):
        with self.assertRaises(PTVAttestationError) as ctx:
            verify_ptv_attestation_exercise(
                self.valid_payload,
                expected_nonce="nonce_20261103_exercise_challenge_99a8b7c6",
                current_time_iso="2026-11-03T15:15:00Z",
                trusted_key_fingerprints=["0000000000000000000000000000000000000000000000000000000000000000"],
            )
        self.assertIn("Attestation key fingerprint", str(ctx.exception))

    def test_non_verify_phase_rejected_at_exercise(self):
        payload = copy.deepcopy(self.valid_payload)
        payload["ptv_lifecycle"]["phase"] = "PROVE"
        with self.assertRaises(PTVAttestationError) as ctx:
            verify_ptv_attestation_exercise(
                payload,
                expected_nonce="nonce_20261103_exercise_challenge_99a8b7c6",
                current_time_iso="2026-11-03T15:15:00Z",
            )
        self.assertIn("Exercise-time verification requires phase 'VERIFY'", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
