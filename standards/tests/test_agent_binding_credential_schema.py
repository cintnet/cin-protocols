#!/usr/bin/env python3
"""Conformance and security tests for AgentBindingCredential v0.1.0 and checker.

Enforces fail-closed validation, holder binding verification, lease expiration checks,
proof-to-issuer key bindings, and lifecycle integrity under articles/the-second-internet.md and D-0385.
"""

import copy
import json
import unittest
from unittest.mock import patch
from datetime import datetime, timezone
from pathlib import Path

from research.standards.agent_binding_credential import AgentBindingCredentialChecker, parse_iso8601


class TestAgentBindingCredentialConformance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.standards_dir = Path(__file__).resolve().parent.parent
        cls.example_path = cls.standards_dir / "examples" / "agent-binding-credential-example.json"
        with open(cls.example_path, "r", encoding="utf-8") as f:
            cls.canonical_example = json.load(f)
        cls.checker = AgentBindingCredentialChecker()

    def setUp(self):
        self.doc = copy.deepcopy(self.canonical_example)
        # Default active evaluation time during the valid example window (issued 2026-10-13T12:00:00Z)
        self.eval_time = parse_iso8601("2026-10-13T15:00:00Z")

    def test_canonical_example_passes_with_clock(self):
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertTrue(valid, f"Canonical example must pass: {err}")
        self.assertIsNone(err)

    def test_canonical_example_passes_default_clock(self):
        # Freeze the default host clock inside the synthetic lease window.
        # The example lease expires; the wall calendar must not determine this test.
        with patch("research.standards.agent_binding_credential.datetime", wraps=datetime) as clock:
            clock.now.return_value = self.eval_time
            valid, err = self.checker.check(self.doc)
            clock.now.assert_called_once_with(timezone.utc)
        self.assertTrue(valid, f"Canonical example must pass with default clock: {err}")

    def test_rejects_expired_credential_with_omitted_clock(self):
        # Set credential into the distant past (2020)
        self.doc["issued_at"] = "2020-01-01T00:00:00Z"
        self.doc["expires_at"] = "2020-01-08T00:00:00Z"
        self.doc["permissions"][0]["granted_at"] = "2020-01-01T00:00:00Z"
        self.doc["permissions"][0]["expires_at"] = "2020-01-02T00:00:00Z"
        self.doc["permissions"][1]["granted_at"] = "2020-01-01T00:00:00Z"
        self.doc["permissions"][1]["expires_at"] = "2020-01-03T00:00:00Z"
        # Clock omitted -> evaluates against now (2026) -> must reject
        valid, err = self.checker.check(self.doc)
        self.assertFalse(valid)
        self.assertIn("credential_expired", err)

    def test_rejects_future_issuance(self):
        # Issued in 2030, evaluated at 2026
        self.doc["issued_at"] = "2030-01-01T00:00:00Z"
        self.doc["expires_at"] = "2030-01-10T00:00:00Z"
        self.doc["permissions"][0]["granted_at"] = "2030-01-01T00:00:00Z"
        self.doc["permissions"][0]["expires_at"] = "2030-01-02T00:00:00Z"
        self.doc["permissions"][1]["granted_at"] = "2030-01-01T00:00:00Z"
        self.doc["permissions"][1]["expires_at"] = "2030-01-03T00:00:00Z"
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("credential_not_yet_valid", err)

    def test_rejects_lease_predating_credential_issuance(self):
        # Lease granted before credential issued
        self.doc["permissions"][0]["granted_at"] = "2026-10-12T00:00:00Z"
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("lease_cannot_predate_credential_issuance", err)

    def test_rejects_premature_permission_lease(self):
        # Lease granted in future relative to evaluation time
        self.doc["permissions"][0]["granted_at"] = "2026-10-14T00:00:00Z"
        self.doc["permissions"][0]["expires_at"] = "2026-10-15T00:00:00Z"
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("lease_not_yet_valid", err)

    def test_rejects_exact_boundary_expiry(self):
        # ref_time == expires_at fails closed
        exact_expiry = parse_iso8601(self.doc["expires_at"])
        valid, err = self.checker.check(self.doc, as_of=exact_expiry)
        self.assertFalse(valid)
        self.assertIn("credential_expired", err)

    def test_rejects_exact_boundary_lease_expiry(self):
        # ref_time == lease.expires_at fails closed
        lease_expiry = parse_iso8601(self.doc["permissions"][0]["expires_at"])
        valid, err = self.checker.check(self.doc, as_of=lease_expiry)
        self.assertFalse(valid)
        self.assertIn("lease_expired", err)

    def test_rejects_mismatched_proof_verification_method(self):
        self.doc["proof"]["verification_method"] = "did:cin:attacker-unauthorized#keys-9"
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("proof_verification_method_mismatch", err)

    def test_rejects_malformed_revocation_uri(self):
        self.doc["revocation"]["revocation_list_url"] = "not a valid uri with spaces"
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("invalid_uri_format", err)

    def test_rejects_malformed_iso_datetime(self):
        self.doc["issued_at"] = "2026-10-13 12:00:00"  # missing T and timezone
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("invalid", err)

    def test_rejects_unknown_root_field(self):
        self.doc["extra_field_unauthorized"] = "exploit"
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("extra_properties", err)

    def test_rejects_unknown_nested_field_in_compute_budget(self):
        self.doc["compute_budget"]["unbounded_compute"] = True
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("extra_properties", err)

    def test_rejects_unknown_nested_field_in_lease(self):
        self.doc["permissions"][0]["bypass_gate"] = True
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("extra_properties", err)

    def test_rejects_missing_required_field_root(self):
        del self.doc["compute_budget"]
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("missing_required_property:compute_budget", err)

    def test_rejects_missing_required_field_holder(self):
        del self.doc["holder"]["binding_commitment"]
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("missing_required_property:binding_commitment", err)

    def test_rejects_mismatched_holder_id(self):
        valid, err = self.checker.check(self.doc, as_of=self.eval_time, expected_holder_id="did:cin:wrong-holder-id")
        self.assertFalse(valid)
        self.assertIn("holder_mismatch", err)

    def test_matches_correct_holder_id(self):
        valid, err = self.checker.check(self.doc, as_of=self.eval_time, expected_holder_id="did:cin:holder-person-zk7721")
        self.assertTrue(valid, f"Expected matching holder to pass: {err}")

    def test_rejects_person_binding_without_personhood_ref(self):
        self.doc["holder"]["personhood_credential_ref"] = None
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("person_binding_requires_personhood_credential_ref", err)

    def test_rejects_person_binding_with_organisation_ref(self):
        self.doc["holder"]["organisation_ref"] = "urn:cin:org:illegal-cross-binding"
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("person_binding_must_not_include_organisation_ref", err)

    def test_valid_organisation_binding(self):
        self.doc["holder"]["binding_kind"] = "organisation"
        self.doc["holder"]["personhood_credential_ref"] = None
        self.doc["holder"]["organisation_ref"] = "urn:cin:org:coop-tech-guild-01"
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertTrue(valid, f"Valid organisation binding must pass: {err}")

    def test_rejects_organisation_binding_without_organisation_ref(self):
        self.doc["holder"]["binding_kind"] = "organisation"
        self.doc["holder"]["personhood_credential_ref"] = None
        self.doc["holder"]["organisation_ref"] = None
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("organisation_binding_requires_organisation_ref", err)

    def test_rejects_organisation_binding_with_personhood_ref(self):
        self.doc["holder"]["binding_kind"] = "organisation"
        self.doc["holder"]["organisation_ref"] = "urn:cin:org:coop-tech-guild-01"
        self.doc["holder"]["personhood_credential_ref"] = "urn:cin:personhood:zk-adler2024-99120"
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("organisation_binding_must_not_include_personhood_credential_ref", err)

    def test_rejects_inverted_lifecycle(self):
        self.doc["issued_at"] = "2026-10-20T12:00:00Z"
        self.doc["expires_at"] = "2026-10-13T12:00:00Z"
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("expires_at_must_be_after_issued_at", err)

    def test_rejects_expired_credential(self):
        eval_time = parse_iso8601("2026-10-25T00:00:00Z")
        valid, err = self.checker.check(self.doc, as_of=eval_time)
        self.assertFalse(valid)
        self.assertIn("credential_expired", err)

    def test_rejects_revoked_credential(self):
        self.doc["revocation"]["is_revoked"] = True
        self.doc["revocation"]["revoked_at"] = "2026-10-13T13:00:00Z"
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("credential_revoked", err)

    def test_rejects_expired_permission_lease(self):
        # Evaluation time after lease 1 expiry (which expires 2026-10-14T12:00:00Z)
        eval_time = parse_iso8601("2026-10-14T18:00:00Z")
        valid, err = self.checker.check(self.doc, as_of=eval_time)
        self.assertFalse(valid)
        self.assertIn("lease_expired:lease-browse-local-01", err)

    def test_rejects_lease_outliving_parent_credential(self):
        self.doc["permissions"][0]["expires_at"] = "2026-10-30T12:00:00Z"
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("lease_cannot_outlive_credential_expiry", err)

    def test_rejects_inverted_lease_lifecycle(self):
        self.doc["permissions"][0]["granted_at"] = "2026-10-14T12:00:00Z"
        self.doc["permissions"][0]["expires_at"] = "2026-10-13T12:00:00Z"
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("expires_at_must_be_after_granted_at", err)

    def test_rejects_revoked_lease(self):
        self.doc["permissions"][0]["is_revoked"] = True
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("lease_revoked", err)

    def test_rejects_empty_permissions_list(self):
        self.doc["permissions"] = []
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("min_items_violation", err)

    def test_rejects_invalid_compute_budget_type_or_bounds(self):
        self.doc["compute_budget"]["max_tokens_per_hour"] = 500  # min is 1000
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("minimum_violation", err)

        self.doc["compute_budget"]["max_tokens_per_hour"] = "infinite"
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("must_be_integer", err)

    def test_rejects_unknown_model_family(self):
        self.doc["agent_subject"]["model_family"] = "unaligned-rogue-v1"
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("enum_violation", err)

    def test_rejects_malformed_runtime_hash(self):
        self.doc["agent_subject"]["runtime_hash"] = "md5:12345"
        valid, err = self.checker.check(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("pattern_mismatch", err)


if __name__ == "__main__":
    unittest.main()
