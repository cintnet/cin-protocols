#!/usr/bin/env python3
"""Conformance and security tests for AgentVerifiableMandate v0.1.0 and validator.

Enforces fail-closed validation, authority separation invariants, monotonic scope attenuation,
integer-only financial accounting, and token status list revocation under
IETF WIMSE draft-hulea-wimse-agent-mandate-01 and Floor Rights F1, F17, and F19.
Standard library only.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unittest

# Resilient import path for discovery from any working directory
_repo_root = Path(__file__).resolve().parent.parent.parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))
_standards_dir = Path(__file__).resolve().parent.parent
if str(_standards_dir) not in sys.path:
    sys.path.insert(0, str(_standards_dir))

try:
    from research.standards.agent_verifiable_mandate import (
        AgentVerifiableMandateValidator,
        parse_iso8601,
    )
except ImportError:
    from agent_verifiable_mandate import (
        AgentVerifiableMandateValidator,
        parse_iso8601,
    )


class TestAgentVerifiableMandateConformance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.standards_dir = Path(__file__).resolve().parent.parent
        cls.example_path = cls.standards_dir / "examples" / "cross-domain-procurement-mandate.json"
        with open(cls.example_path, "r", encoding="utf-8") as f:
            cls.canonical_example = json.load(f)
        cls.validator = AgentVerifiableMandateValidator()

    def setUp(self):
        self.doc = copy.deepcopy(self.canonical_example)
        # Reference evaluation time within active window: 2026-11-05T12:00:00Z
        self.eval_time = parse_iso8601("2026-11-05T12:00:00Z")

    def test_canonical_example_passes_with_clock(self):
        """Canonical example must pass full semantic and schema validation."""
        valid, err = self.validator.validate_mandate(self.doc, as_of=self.eval_time)
        self.assertTrue(valid, f"Canonical example must pass: {err}")
        self.assertIsNone(err)

    def test_rejects_extra_properties_root_fail_closed(self):
        """Reject undeclared properties at root level."""
        self.doc["unexpected_field"] = "malicious_payload"
        valid, err = self.validator.validate_schema(self.doc)
        self.assertFalse(valid)
        self.assertIn("extra_properties", err)

    def test_rejects_extra_properties_nested_fail_closed(self):
        """Reject undeclared properties inside limits and authority statement."""
        self.doc["mandate_grant"]["limits"]["unlimited_override"] = True
        valid, err = self.validator.validate_mandate(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("extra_properties", err)

    def test_rejects_expired_mandate(self):
        """Mandate evaluated after expiration must be rejected fail-closed."""
        late_clock = parse_iso8601("2026-11-20T00:00:00Z")
        valid, err = self.validator.validate_mandate(self.doc, as_of=late_clock)
        self.assertFalse(valid)
        self.assertEqual(err, "mandate_expired")

    def test_rejects_not_yet_valid_mandate(self):
        """Mandate evaluated prior to issuance must be rejected fail-closed."""
        early_clock = parse_iso8601("2026-11-01T08:00:00Z")
        valid, err = self.validator.validate_mandate(self.doc, as_of=early_clock)
        self.assertFalse(valid)
        self.assertEqual(err, "mandate_not_yet_valid")

    def test_rejects_reversed_lifespan(self):
        """Reversed or zero duration windows fail closed."""
        self.doc["mandate_grant"]["issued_at"] = "2026-11-15T00:00:00Z"
        self.doc["mandate_grant"]["expires_at"] = "2026-11-10T00:00:00Z"
        valid, err = self.validator.validate_mandate(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertEqual(err, "mandate_grant:zero_or_negative_lifespan")

    def test_rejects_mandate_exceeding_authority_window(self):
        """Mandate expiration extending beyond authority statement expiration must fail closed."""
        # Authority expires 2026-12-01T00:00:00Z; mandate extending to 2026-12-05T00:00:00Z fails
        self.doc["mandate_grant"]["expires_at"] = "2026-12-05T00:00:00Z"
        valid, err = self.validator.validate_mandate(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertEqual(err, "mandate_expires_after_authority_window")

    def test_rejects_privilege_escalation_actions(self):
        """Conferring an action not permitted by the delegator authority statement fails closed."""
        self.doc["mandate_grant"]["conferred_actions"].append("treasury:disburse_unilateral_funds")
        valid, err = self.validator.validate_mandate(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("privilege_escalation:unauthorized_actions", err)

    def test_rejects_privilege_escalation_domain(self):
        """Targeting a domain not authorized by the delegator authority statement fails closed."""
        self.doc["mandate_grant"]["target_domain"] = "untrusted.commercial-broker.com"
        valid, err = self.validator.validate_mandate(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("privilege_escalation:target_domain_not_allowed", err)

    def test_rejects_budget_escalation(self):
        """Mandate budget exceeding authority statement maximum budget fails closed."""
        # Authority maximum is 5,000,000 cents ($50k); mandate requests 6,000,000 cents ($60k)
        self.doc["mandate_grant"]["limits"]["max_budget_cents"] = 6000000
        valid, err = self.validator.validate_mandate(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("budget_escalation", err)

    def test_rejects_per_transaction_spend_exceeding_total(self):
        """Per-transaction limit exceeding total mandate budget fails closed."""
        self.doc["mandate_grant"]["limits"]["max_spend_per_transaction_cents"] = 2000000
        self.doc["mandate_grant"]["limits"]["max_budget_cents"] = 1000000
        valid, err = self.validator.validate_mandate(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("spend_limit_inconsistency", err)

    def test_rejects_non_integer_budget_fail_closed(self):
        """Floats, booleans, and negative numbers in financial fields must fail closed (LS-a25669)."""
        bad_budgets = [1000.50, -500, True, False, "100000"]
        for bad in bad_budgets:
            doc_copy = copy.deepcopy(self.doc)
            doc_copy["mandate_grant"]["limits"]["max_budget_cents"] = bad
            valid, err = self.validator.validate_schema(doc_copy)
            self.assertFalse(valid, f"Budget {bad} must fail validation")

    def test_rejects_revoked_status_list(self):
        """Token status list indicating non-valid status must fail closed."""
        self.doc["mandate_grant"]["token_status_list"]["expected_status"] = "revoked"
        valid, err = self.validator.validate_mandate(self.doc, as_of=self.eval_time)
        self.assertFalse(valid)
        self.assertIn("mandate_revocation_status_not_valid", err)


if __name__ == "__main__":
    unittest.main()
