"""Unit tests for Federated Code Forge Attestation and Rate-Limiting Gate."""

import copy
import json
from pathlib import Path
import sys
import unittest

STANDARDS_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = STANDARDS_DIR.parent.parent
for p in (str(STANDARDS_DIR), str(REPO_ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)

from federated_code_forge_attestation import (
    AttestorIdentity,
    ForgeAttestation,
    ResourceQuota,
    SlidingWindowAttestationRateLimiter,
    TestSuiteRun,
    parse_forge_attestation,
    verify_forge_attestation,
)


class TestFederatedCodeForgeAttestation(unittest.TestCase):
    def setUp(self) -> None:
        example_path = STANDARDS_DIR / "examples" / "federated-code-forge-attestation.example.json"
        with open(example_path, "r", encoding="utf-8") as f:
            self.valid_payload = json.load(f)
        self.secret = "test-shared-enclave-secret-key-32b"

    def test_valid_example_payload_passes_schema_and_verification(self) -> None:
        att = parse_forge_attestation(self.valid_payload)
        self.assertEqual(att.schema_version, "0.1.0")
        self.assertEqual(att.test_suite_run.total_tests, 42)
        self.assertEqual(att.test_suite_run.passed_tests, 42)
        self.assertTrue(att.resource_quota.network_egress_blocked)

        # End-to-end verification within lifespan
        valid, reason, parsed = verify_forge_attestation(
            self.valid_payload,
            current_time_iso="2026-10-31T10:30:00Z",
        )
        self.assertTrue(valid, reason)
        self.assertIsNotNone(parsed)

    def test_canonical_signature_roundtrip_and_verification(self) -> None:
        att = parse_forge_attestation(self.valid_payload)
        sig = att.compute_hmac_signature(self.secret)
        self.assertTrue(len(sig) == 64)

        payload_with_sig = copy.deepcopy(self.valid_payload)
        payload_with_sig["signature"] = sig

        valid, reason, _ = verify_forge_attestation(
            payload_with_sig,
            secret_key=self.secret,
            current_time_iso="2026-10-31T10:30:00Z",
        )
        self.assertTrue(valid, reason)

    def test_signature_mismatch_fails_closed(self) -> None:
        payload_with_sig = copy.deepcopy(self.valid_payload)
        payload_with_sig["signature"] = "a" * 64

        valid, reason, _ = verify_forge_attestation(
            payload_with_sig,
            secret_key=self.secret,
            current_time_iso="2026-10-31T10:30:00Z",
        )
        self.assertFalse(valid)
        self.assertIn("signature mismatch", reason)

    def test_reject_tampered_commit_sha(self) -> None:
        bad = copy.deepcopy(self.valid_payload)
        bad["commit_sha"] = "not-a-valid-sha"
        with self.assertRaises(ValueError):
            parse_forge_attestation(bad)

    def test_reject_tampered_tree_hash(self) -> None:
        bad = copy.deepcopy(self.valid_payload)
        bad["tree_hash"] = "short_hash"
        with self.assertRaises(ValueError):
            parse_forge_attestation(bad)

    def test_reject_test_tally_mismatch(self) -> None:
        bad = copy.deepcopy(self.valid_payload)
        bad["test_suite_run"]["passed_tests"] = 40  # 40 passed + 0 failed + 0 skipped != 42 total
        with self.assertRaises(ValueError) as ctx:
            parse_forge_attestation(bad)
        self.assertIn("Test tally mismatch", str(ctx.exception))

    def test_reject_failed_tests_when_zero_failures_required(self) -> None:
        bad = copy.deepcopy(self.valid_payload)
        bad["test_suite_run"]["passed_tests"] = 40
        bad["test_suite_run"]["failed_tests"] = 2
        valid, reason, _ = verify_forge_attestation(
            bad,
            current_time_iso="2026-10-31T10:30:00Z",
            require_zero_failures=True,
        )
        self.assertFalse(valid)
        self.assertIn("failure", reason)

    def test_reject_inverted_lifecycle(self) -> None:
        bad = copy.deepcopy(self.valid_payload)
        bad["issued_at"] = "2026-10-31T11:00:00Z"
        bad["expires_at"] = "2026-10-31T10:00:00Z"
        with self.assertRaises(ValueError) as ctx:
            parse_forge_attestation(bad)
        self.assertIn("must be strictly after issued_at", str(ctx.exception))

    def test_reject_expired_attestation(self) -> None:
        valid, reason, _ = verify_forge_attestation(
            self.valid_payload,
            current_time_iso="2026-10-31T11:00:01Z",
        )
        self.assertFalse(valid)
        self.assertIn("Expired attestation", reason)

    def test_reject_premature_attestation(self) -> None:
        valid, reason, _ = verify_forge_attestation(
            self.valid_payload,
            current_time_iso="2026-10-31T09:59:00Z",
        )
        self.assertFalse(valid)
        self.assertIn("Premature attestation", reason)

    def test_reject_unblocked_egress_when_required(self) -> None:
        bad = copy.deepcopy(self.valid_payload)
        bad["resource_quota"]["network_egress_blocked"] = False
        valid, reason, _ = verify_forge_attestation(
            bad,
            current_time_iso="2026-10-31T10:30:00Z",
            require_egress_blocked=True,
        )
        self.assertFalse(valid)
        self.assertIn("Network egress was not blocked", reason)

    def test_reject_unknown_field_fail_closed(self) -> None:
        bad = copy.deepcopy(self.valid_payload)
        bad["malicious_extra_field"] = "escalate_privilege"
        with self.assertRaises(ValueError) as ctx:
            parse_forge_attestation(bad)
        self.assertIn("Undeclared properties", str(ctx.exception))

    def test_reject_missing_required_field(self) -> None:
        bad = copy.deepcopy(self.valid_payload)
        del bad["nonce"]
        with self.assertRaises(ValueError) as ctx:
            parse_forge_attestation(bad)
        self.assertIn("Missing required properties", str(ctx.exception))

    def test_reject_boolean_for_integer(self) -> None:
        bad = copy.deepcopy(self.valid_payload)
        bad["test_suite_run"]["total_tests"] = True
        with self.assertRaises(ValueError):
            parse_forge_attestation(bad)

    def test_reject_float_for_integer(self) -> None:
        bad = copy.deepcopy(self.valid_payload)
        bad["resource_quota"]["memory_mb"] = 512.5
        with self.assertRaises(ValueError):
            parse_forge_attestation(bad)

    def test_reject_invalid_enclave_type(self) -> None:
        bad = copy.deepcopy(self.valid_payload)
        bad["attestor"]["enclave_type"] = "unverified-untrusted-box"
        with self.assertRaises(ValueError) as ctx:
            parse_forge_attestation(bad)
        self.assertIn("Invalid enclave_type", str(ctx.exception))

    def test_sliding_window_rate_limiter_admissions_and_burst_blocking(self) -> None:
        limiter = SlidingWindowAttestationRateLimiter(window_seconds=600, max_requests_per_window=3)
        did = "did:cin:agent:node-alpha-772"
        repo = "https://forge.collective.local/cin/core-ledger"

        # 3 requests allowed
        for i in range(3):
            nonce = f"0123456789abcdef{i:04x}"
            ok, msg = limiter.check_and_record(did, repo, nonce, current_time=1000.0 + i * 10)
            self.assertTrue(ok, msg)

        # 4th request within window rejected
        nonce4 = "0123456789abcdef0004"
        ok, msg = limiter.check_and_record(did, repo, nonce4, current_time=1050.0)
        self.assertFalse(ok)
        self.assertIn("Rate limit exceeded", msg)

        # After window slides past 600s, new request accepted
        nonce5 = "0123456789abcdef0005"
        ok, msg = limiter.check_and_record(did, repo, nonce5, current_time=1650.0)
        self.assertTrue(ok, msg)

    def test_sliding_window_rate_limiter_rejects_replay_nonce(self) -> None:
        limiter = SlidingWindowAttestationRateLimiter(window_seconds=600, max_requests_per_window=10)
        did = "did:cin:agent:node-alpha-772"
        repo = "https://forge.collective.local/cin/core-ledger"
        nonce = "0123456789abcdefc0ffee"

        ok1, msg1 = limiter.check_and_record(did, repo, nonce, current_time=1000.0)
        self.assertTrue(ok1, msg1)

        # Same nonce within window fails
        ok2, msg2 = limiter.check_and_record(did, repo, nonce, current_time=1020.0)
        self.assertFalse(ok2)
        self.assertIn("Replay attack detected", msg2)

    def test_sliding_window_rate_limiter_non_positive_bounds_fail_closed(self) -> None:
        """Non-positive window_seconds or max_requests_per_window fail closed with ValueError (LS-a25669)."""
        with self.assertRaises(ValueError):
            SlidingWindowAttestationRateLimiter(window_seconds=0)

        with self.assertRaises(ValueError):
            SlidingWindowAttestationRateLimiter(window_seconds=-10)

        with self.assertRaises(ValueError):
            SlidingWindowAttestationRateLimiter(max_requests_per_window=0)

        with self.assertRaises(ValueError):
            SlidingWindowAttestationRateLimiter(max_requests_per_window=-5)

        with self.assertRaises(ValueError):
            SlidingWindowAttestationRateLimiter(window_seconds=True)

        with self.assertRaises(ValueError):
            SlidingWindowAttestationRateLimiter(max_requests_per_window=True)


if __name__ == "__main__":
    unittest.main()
