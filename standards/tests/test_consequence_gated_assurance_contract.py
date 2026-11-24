"""Unit tests for consequence-gated identity assurance contract (arXiv:2610.00287).

Verifies fail-closed behavior, consequence-proportional claim bounding (F2),
temporal validity windows, cross-border jurisdictional constraints, and immutability.
"""

import unittest
from research.standards.consequence_gated_assurance_contract import (
    AssertionScope,
    AssuranceVerdict,
    ConsequenceGatedAssuranceContract,
    ConsequenceTier,
    EntityType,
    PointInTimeAssertion,
)


class TestConsequenceGatedAssuranceContract(unittest.TestCase):
    def setUp(self):
        self.valid_assertion = PointInTimeAssertion(
            assertion_id="asst-20261013-001",
            entity_type=EntityType.MACHINE_AGENT,
            scope=AssertionScope.MINIMAL_CLAIM,
            issuer_did="did:cin:issuer:coop-alpha",
            subject_did="did:cin:agent:twin-042",
            jurisdiction="CA-ON",
            valid_from="2026-10-13T00:00:00Z",
            valid_until="2026-10-13T04:00:00Z",
            claims={"proof_of_age_over_18": "true", "purpose": "inquiry"},
            signature="sig_ed25519_mock_valid_hash_492048",
        )

    def test_read_only_access_passes_anonymously_without_assertion(self):
        verdict = ConsequenceGatedAssuranceContract.evaluate_capability_request(
            consequence_tier=ConsequenceTier.READ_ONLY,
            assertion=None,
            target_jurisdiction="CA-ON",
            current_time_iso="2026-10-13T01:00:00Z",
        )
        self.assertTrue(verdict.advisory_pass)
        self.assertEqual(verdict.admitted_scope, AssertionScope.ANONYMOUS)
        self.assertFalse(verdict.over_collection_detected)

    def test_read_only_rejects_over_collection_when_identity_supplied(self):
        # Floor Right F2: Services receive answers, not data. Read-only forbids over-collection.
        verdict = ConsequenceGatedAssuranceContract.evaluate_capability_request(
            consequence_tier=ConsequenceTier.READ_ONLY,
            assertion=self.valid_assertion,
            target_jurisdiction="CA-ON",
            current_time_iso="2026-10-13T01:00:00Z",
        )
        self.assertFalse(verdict.advisory_pass)
        self.assertTrue(verdict.over_collection_detected)
        self.assertIn("over-collection", verdict.reason)

    def test_low_impact_transaction_passes_with_minimal_claim(self):
        verdict = ConsequenceGatedAssuranceContract.evaluate_capability_request(
            consequence_tier=ConsequenceTier.LOW_IMPACT_TRANSACTION,
            assertion=self.valid_assertion,
            target_jurisdiction="CA-ON",
            current_time_iso="2026-10-13T01:00:00Z",
        )
        self.assertTrue(verdict.advisory_pass)
        self.assertEqual(verdict.admitted_scope, AssertionScope.MINIMAL_CLAIM)
        self.assertFalse(verdict.over_collection_detected)

    def test_low_impact_transaction_rejects_direct_identifier_over_collection(self):
        direct_id_assertion = PointInTimeAssertion(
            assertion_id="asst-20261013-002",
            entity_type=EntityType.NATURAL_PERSON,
            scope=AssertionScope.DIRECT_IDENTIFIER,
            issuer_did="did:cin:issuer:coop-alpha",
            subject_did="did:cin:person:alice-sin",
            jurisdiction="CA-ON",
            valid_from="2026-10-13T00:00:00Z",
            valid_until="2026-10-13T04:00:00Z",
            claims={"sin": "000-000-000", "legal_name": "Alice Doe"},
            signature="sig_ed25519_direct_id_001",
        )
        verdict = ConsequenceGatedAssuranceContract.evaluate_capability_request(
            consequence_tier=ConsequenceTier.LOW_IMPACT_TRANSACTION,
            assertion=direct_id_assertion,
            target_jurisdiction="CA-ON",
            current_time_iso="2026-10-13T01:00:00Z",
        )
        self.assertFalse(verdict.advisory_pass)
        self.assertTrue(verdict.over_collection_detected)
        self.assertIn("permits at most minimal_claim", verdict.reason)

    def test_bounded_delegation_rejects_insufficient_minimal_claim(self):
        verdict = ConsequenceGatedAssuranceContract.evaluate_capability_request(
            consequence_tier=ConsequenceTier.BOUNDED_DELEGATION,
            assertion=self.valid_assertion,
            target_jurisdiction="CA-ON",
            current_time_iso="2026-10-13T01:00:00Z",
        )
        self.assertFalse(verdict.advisory_pass)
        self.assertFalse(verdict.over_collection_detected)
        self.assertIn("requires at least pseudonymous_attribute", verdict.reason)

    def test_bounded_delegation_passes_with_pseudonymous_attribute(self):
        delegation_assertion = PointInTimeAssertion(
            assertion_id="asst-20261013-003",
            entity_type=EntityType.MACHINE_AGENT,
            scope=AssertionScope.PSEUDONYMOUS_ATTRIBUTE,
            issuer_did="did:cin:issuer:coop-alpha",
            subject_did="did:cin:agent:broker-09",
            jurisdiction="CA-ON",
            valid_from="2026-10-13T00:00:00Z",
            valid_until="2026-10-13T04:00:00Z",
            claims={"delegation_limit_cad_cents": "5000", "role": "procurement"},
            signature="sig_delegation_valid_99",
        )
        verdict = ConsequenceGatedAssuranceContract.evaluate_capability_request(
            consequence_tier=ConsequenceTier.BOUNDED_DELEGATION,
            assertion=delegation_assertion,
            target_jurisdiction="CA-ON",
            current_time_iso="2026-10-13T01:00:00Z",
        )
        self.assertTrue(verdict.advisory_pass)
        self.assertEqual(verdict.admitted_scope, AssertionScope.PSEUDONYMOUS_ATTRIBUTE)

    def test_missing_assertion_on_non_read_only_tier_fails_closed(self):
        verdict = ConsequenceGatedAssuranceContract.evaluate_capability_request(
            consequence_tier=ConsequenceTier.LOW_IMPACT_TRANSACTION,
            assertion=None,
            target_jurisdiction="CA-ON",
        )
        self.assertFalse(verdict.advisory_pass)
        self.assertIn("requires assertion metadata", verdict.reason)

    def test_temporal_expired_assertion_fails_closed(self):
        verdict = ConsequenceGatedAssuranceContract.evaluate_capability_request(
            consequence_tier=ConsequenceTier.LOW_IMPACT_TRANSACTION,
            assertion=self.valid_assertion,
            target_jurisdiction="CA-ON",
            current_time_iso="2026-10-13T05:00:00Z",
        )
        self.assertFalse(verdict.advisory_pass)
        self.assertIn("expired", verdict.reason)

    def test_temporal_premature_assertion_fails_closed(self):
        verdict = ConsequenceGatedAssuranceContract.evaluate_capability_request(
            consequence_tier=ConsequenceTier.LOW_IMPACT_TRANSACTION,
            assertion=self.valid_assertion,
            target_jurisdiction="CA-ON",
            current_time_iso="2026-10-12T23:59:00Z",
        )
        self.assertFalse(verdict.advisory_pass)
        self.assertIn("premature", verdict.reason)

    def test_inverted_temporal_window_fails_closed(self):
        inverted = PointInTimeAssertion(
            assertion_id="asst-inverted",
            entity_type=EntityType.MACHINE_AGENT,
            scope=AssertionScope.MINIMAL_CLAIM,
            issuer_did="did:cin:issuer:coop-alpha",
            subject_did="did:cin:agent:twin-042",
            jurisdiction="CA-ON",
            valid_from="2026-10-13T05:00:00Z",
            valid_until="2026-10-13T01:00:00Z",
            signature="sig_test",
        )
        verdict = ConsequenceGatedAssuranceContract.evaluate_capability_request(
            consequence_tier=ConsequenceTier.LOW_IMPACT_TRANSACTION,
            assertion=inverted,
            target_jurisdiction="CA-ON",
            current_time_iso="2026-10-13T02:00:00Z",
        )
        self.assertFalse(verdict.advisory_pass)
        self.assertIn("inverted validity window", verdict.reason)

    def test_unrecognized_jurisdiction_fails_closed(self):
        unrecognized = PointInTimeAssertion(
            assertion_id="asst-unrecog",
            entity_type=EntityType.MACHINE_AGENT,
            scope=AssertionScope.MINIMAL_CLAIM,
            issuer_did="did:cin:issuer:coop-alpha",
            subject_did="did:cin:agent:twin-042",
            jurisdiction="UNKNOWN-TERRITORY",
            valid_from="2026-10-13T00:00:00Z",
            valid_until="2026-10-13T04:00:00Z",
            signature="sig_test",
        )
        verdict = ConsequenceGatedAssuranceContract.evaluate_capability_request(
            consequence_tier=ConsequenceTier.LOW_IMPACT_TRANSACTION,
            assertion=unrecognized,
            target_jurisdiction="CA-ON",
            current_time_iso="2026-10-13T01:00:00Z",
        )
        self.assertFalse(verdict.advisory_pass)
        self.assertIn("unrecognized assertion jurisdiction", verdict.reason)

    def test_quebec_law_25_cross_border_restriction_enforced(self):
        qc_assertion = PointInTimeAssertion(
            assertion_id="asst-qc-01",
            entity_type=EntityType.NATURAL_PERSON,
            scope=AssertionScope.MINIMAL_CLAIM,
            issuer_did="did:cin:issuer:coop-quebec",
            subject_did="did:cin:person:montreal-user",
            jurisdiction="CA-QC",
            valid_from="2026-10-13T00:00:00Z",
            valid_until="2026-10-13T04:00:00Z",
            signature="sig_qc_001",
        )
        verdict_unassessed = ConsequenceGatedAssuranceContract.evaluate_capability_request(
            consequence_tier=ConsequenceTier.LOW_IMPACT_TRANSACTION,
            assertion=qc_assertion,
            target_jurisdiction="US",
            current_time_iso="2026-10-13T01:00:00Z",
        )
        self.assertFalse(verdict_unassessed.advisory_pass)
        self.assertIn("Quebec Law 25", verdict_unassessed.reason)

        verdict_fed = ConsequenceGatedAssuranceContract.evaluate_capability_request(
            consequence_tier=ConsequenceTier.LOW_IMPACT_TRANSACTION,
            assertion=qc_assertion,
            target_jurisdiction="CA-ON",
            current_time_iso="2026-10-13T01:00:00Z",
        )
        self.assertFalse(verdict_fed.advisory_pass)

    def test_missing_signature_fails_closed(self):
        unsigned = PointInTimeAssertion(
            assertion_id="asst-unsigned",
            entity_type=EntityType.MACHINE_AGENT,
            scope=AssertionScope.MINIMAL_CLAIM,
            issuer_did="did:cin:issuer:coop-alpha",
            subject_did="did:cin:agent:twin-042",
            jurisdiction="CA-ON",
            valid_from="2026-10-13T00:00:00Z",
            valid_until="2026-10-13T04:00:00Z",
            signature="",
        )
        verdict = ConsequenceGatedAssuranceContract.evaluate_capability_request(
            consequence_tier=ConsequenceTier.LOW_IMPACT_TRANSACTION,
            assertion=unsigned,
            target_jurisdiction="CA-ON",
            current_time_iso="2026-10-13T01:00:00Z",
        )
        self.assertFalse(verdict.advisory_pass)
        self.assertIn("unsigned assertion", verdict.reason)

    def test_invalid_types_raise_type_error(self):
        with self.assertRaises(TypeError):
            ConsequenceGatedAssuranceContract.evaluate_capability_request(
                consequence_tier="invalid_tier",  # type: ignore
                assertion=self.valid_assertion,
                target_jurisdiction="CA-ON",
            )
        with self.assertRaises(TypeError):
            ConsequenceGatedAssuranceContract.evaluate_capability_request(
                consequence_tier=ConsequenceTier.READ_ONLY,
                assertion=self.valid_assertion,
                target_jurisdiction="",
            )

    def qc(self):
        from dataclasses import replace
        return replace(self.valid_assertion, jurisdiction="CA-QC", signature="x")

    def evaluate_qc(self, target, **kwargs):
        return ConsequenceGatedAssuranceContract.evaluate_capability_request(
            ConsequenceTier.LOW_IMPACT_TRANSACTION, self.qc(), target,
            "2026-10-13T01:00:00Z", **kwargs)

    def test_all_external_destinations_need_pia_reference(self):
        for target in ("EU", "CA-ON", "US"):
            with self.subTest(target=target):
                self.assertFalse(self.evaluate_qc(target).advisory_pass)
                self.assertTrue(self.evaluate_qc(target, pia_reference="synthetic-pia-1").advisory_pass)
        self.assertTrue(self.evaluate_qc("CA-QC").advisory_pass)

    def test_regime_labels_are_not_destinations(self):
        for target in ("CA-FED", "US-FED", "GLOBAL-DECENTRALIZED", "UNKNOWN"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.evaluate_qc(target, pia_reference="synthetic-pia-1")

    def test_fabricated_signature_is_never_called_verified(self):
        result = self.evaluate_qc("CA-ON", pia_reference="synthetic-pia-1")
        self.assertTrue(result.advisory_pass)
        self.assertIn("present, not verified", result.reason)
        self.assertFalse(result.details["signature_checked"])

    def test_pia_reference_rejects_malformed_values(self):
        for ref in ("", " ", " x", "x\n", True, 1, [], {}):
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                self.evaluate_qc("EU", pia_reference=ref)

    def test_over_collection_switch_removed(self):
        with self.assertRaises(TypeError):
            ConsequenceGatedAssuranceContract.evaluate_capability_request(
                ConsequenceTier.READ_ONLY, self.qc(), "CA-QC", allow_over_collection=True)
        result = ConsequenceGatedAssuranceContract.evaluate_capability_request(
            ConsequenceTier.READ_ONLY, self.qc(), "CA-QC")
        self.assertFalse(result.advisory_pass)
        self.assertTrue(result.over_collection_detected)
        self.assertNotEqual(result.admitted_scope, AssertionScope.ANONYMOUS)

    def test_timestamps_need_explicit_utc(self):
        for timestamp in ("2026-10-13T01:00:00", "2026-10-13T01:00:00+01:00", "2026-02-30T01:00:00Z"):
            with self.subTest(timestamp=timestamp), self.assertRaises(ValueError):
                ConsequenceGatedAssuranceContract.parse_iso_time(timestamp)

    def test_exact_expiry_is_refused(self):
        result = ConsequenceGatedAssuranceContract.evaluate_capability_request(
            ConsequenceTier.LOW_IMPACT_TRANSACTION, self.qc(), "CA-QC", "2026-10-13T04:00:00Z")
        self.assertFalse(result.advisory_pass)

    def test_invalid_assertion_type_rejected(self):
        with self.assertRaises(TypeError):
            ConsequenceGatedAssuranceContract.evaluate_capability_request(
                ConsequenceTier.READ_ONLY, {}, "CA-QC")


if __name__ == "__main__":
    unittest.main()
