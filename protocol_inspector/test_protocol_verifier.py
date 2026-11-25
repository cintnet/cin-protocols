"""Unit tests for `research.protocol_inspector.protocol_verifier` (>= 16 tests)."""

from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

try:
    from research.protocol_inspector.protocol_verifier import (
        DEMO_SIGNING_KEY,
        MAX_HEARTBEAT_GAP_MS,
        MAX_LEASE_DURATION_SEC,
        apply_adversarial_faults,
        build_browser_test_vectors,
        build_valid_clearing_envelope,
        build_valid_interlock_envelope,
        build_valid_lease_envelope,
        build_valid_provenance_envelope,
        canonical_json,
        hmac_sha256_hex,
        sha256_hex,
        verify_actuator_interlock,
        verify_capability_lease,
        verify_cooperative_clearing,
        verify_envelope,
        verify_provenance_receipt,
    )
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from protocol_verifier import (
        DEMO_SIGNING_KEY,
        MAX_HEARTBEAT_GAP_MS,
        MAX_LEASE_DURATION_SEC,
        apply_adversarial_faults,
        build_browser_test_vectors,
        build_valid_clearing_envelope,
        build_valid_interlock_envelope,
        build_valid_lease_envelope,
        build_valid_provenance_envelope,
        canonical_json,
        hmac_sha256_hex,
        sha256_hex,
        verify_actuator_interlock,
        verify_capability_lease,
        verify_cooperative_clearing,
        verify_envelope,
        verify_provenance_receipt,
    )


class TestProtocolVerifier(unittest.TestCase):
    """Comprehensive deterministic test suite across all four protocol layers."""

    def test_01_canonical_json_key_order_independence(self) -> None:
        a = {"z": 1, "a": [3, 2, {"y": "ok", "b": "hi"}]}
        b = {"a": [3, 2, {"b": "hi", "y": "ok"}], "z": 1}
        self.assertEqual(canonical_json(a), canonical_json(b))
        self.assertEqual(sha256_hex(a), sha256_hex(b))

    def test_02_layer1_valid_capability_lease_passes_all_invariants(self) -> None:
        env = build_valid_lease_envelope()
        report = verify_capability_lease(env)
        self.assertTrue(report.passed)
        self.assertEqual(report.failed_check_ids, ())
        self.assertEqual(len(report.checks), 4)
        self.assertTrue(all(c.passed for c in report.checks))

    def test_03_layer1_blocks_forged_lease_ceiling_or_wrong_key(self) -> None:
        forged = apply_adversarial_faults(build_valid_lease_envelope(), ["forge_lease_ceiling"])
        report = verify_capability_lease(forged)
        self.assertFalse(report.passed)
        self.assertIn("L1_PRINCIPAL_BINDING", report.failed_check_ids)

        wrong_key_report = verify_capability_lease(
            build_valid_lease_envelope(), signing_key="wrong-attacker-key"
        )
        self.assertFalse(wrong_key_report.passed)
        self.assertIn("L1_PRINCIPAL_BINDING", wrong_key_report.failed_check_ids)

    def test_04_layer1_blocks_unlisted_tool_escalation(self) -> None:
        escalated = apply_adversarial_faults(build_valid_lease_envelope(), ["escalate_tool_scope"])
        report = verify_capability_lease(escalated)
        self.assertFalse(report.passed)
        self.assertEqual(report.failed_check_ids, ("L1_TOOL_AND_CEILING_SCOPE",))

    def test_05_layer1_blocks_unit_ceiling_overrun_on_allowed_tool(self) -> None:
        env = build_valid_lease_envelope()
        env["invocation"]["requested_tool"] = "supplier.quote"
        env["invocation"]["requested_units"] = 251
        report = verify_capability_lease(env)
        self.assertFalse(report.passed)
        self.assertEqual(report.failed_check_ids, ("L1_TOOL_AND_CEILING_SCOPE",))

    def test_06_layer1_blocks_expired_and_standing_indefinite_leases(self) -> None:
        expired = apply_adversarial_faults(build_valid_lease_envelope(), ["use_expired_lease"])
        report_exp = verify_capability_lease(expired)
        self.assertFalse(report_exp.passed)
        self.assertEqual(report_exp.failed_check_ids, ("L1_EXPIRY_WINDOW",))

        # Exact boundary: evaluated_at == expires_at must be rejected (`issued <= now < expires`)
        exact_cutoff = build_valid_lease_envelope()
        exact_cutoff["evaluated_at_epoch"] = exact_cutoff["expires_at_epoch"]
        self.assertFalse(verify_capability_lease(exact_cutoff).passed)

        # Standing grant > 24h must be rejected even if re-signed by principal
        standing = build_valid_lease_envelope()
        standing["expires_at_epoch"] = standing["issued_at_epoch"] + MAX_LEASE_DURATION_SEC + 60
        standing["delegation_mac"] = hmac_sha256_hex(
            DEMO_SIGNING_KEY,
            {
                "allowed_tools": standing["allowed_tools"],
                "ceiling_units": standing["ceiling_units"],
                "delegate_agent_id": standing["delegate_agent_id"],
                "expires_at_epoch": standing["expires_at_epoch"],
                "issued_at_epoch": standing["issued_at_epoch"],
                "lease_id": standing["lease_id"],
                "principal_id": standing["principal_id"],
            },
        )
        rep_standing = verify_capability_lease(standing)
        self.assertFalse(rep_standing.passed)
        self.assertEqual(rep_standing.failed_check_ids, ("L1_EXPIRY_WINDOW",))

    def test_07_layer1_blocks_indirect_prompt_injection_from_invoice(self) -> None:
        injected = apply_adversarial_faults(build_valid_lease_envelope(), ["inject_invoice_command"])
        report = verify_capability_lease(injected)
        self.assertFalse(report.passed)
        self.assertEqual(report.failed_check_ids, ("L1_TAINT_SEPARATION",))

    def test_08_layer2_valid_provenance_receipt_passes_all_invariants(self) -> None:
        env = build_valid_provenance_envelope()
        report = verify_provenance_receipt(env)
        self.assertTrue(report.passed)
        self.assertEqual(report.failed_check_ids, ())
        self.assertEqual(len(report.checks), 4)

    def test_09_layer2_blocks_input_payload_tampering(self) -> None:
        tampered = apply_adversarial_faults(build_valid_provenance_envelope(), ["tamper_input_payload"])
        report = verify_provenance_receipt(tampered)
        self.assertFalse(report.passed)
        self.assertIn("L2_INPUT_DIGEST", report.failed_check_ids)

    def test_10_layer2_blocks_output_payload_doctoring(self) -> None:
        tampered = apply_adversarial_faults(build_valid_provenance_envelope(), ["tamper_output_payload"])
        report = verify_provenance_receipt(tampered)
        self.assertFalse(report.passed)
        self.assertIn("L2_OUTPUT_DIGEST", report.failed_check_ids)

    def test_11_layer2_blocks_parent_chain_cherry_picking(self) -> None:
        tampered = apply_adversarial_faults(build_valid_provenance_envelope(), ["tamper_parent_digest"])
        report = verify_provenance_receipt(tampered)
        self.assertFalse(report.passed)
        self.assertEqual(report.failed_check_ids, ("L2_PARENT_CHAIN_LINK",))

    def test_12_layer2_blocks_unfaithful_spot_check_replay(self) -> None:
        tampered = apply_adversarial_faults(build_valid_provenance_envelope(), ["fail_spot_replay"])
        report = verify_provenance_receipt(tampered)
        self.assertFalse(report.passed)
        self.assertEqual(report.failed_check_ids, ("L2_REPLAY_SPOT_PROOF",))

    def test_13_layer3_valid_actuator_interlock_passes_all_invariants(self) -> None:
        env = build_valid_interlock_envelope()
        report = verify_actuator_interlock(env)
        self.assertTrue(report.passed)
        self.assertEqual(report.failed_check_ids, ())
        self.assertEqual(len(report.checks), 4)

    def test_14_layer3_heartbeat_boundary_50ms_vs_51ms_and_optical_isolation(self) -> None:
        at_limit = build_valid_interlock_envelope()
        at_limit["heartbeat_gap_ms"] = MAX_HEARTBEAT_GAP_MS
        self.assertTrue(verify_actuator_interlock(at_limit).passed)

        over_limit = apply_adversarial_faults(build_valid_interlock_envelope(), ["drop_relay_heartbeat"])
        rep_over = verify_actuator_interlock(over_limit)
        self.assertFalse(rep_over.passed)
        self.assertEqual(rep_over.failed_check_ids, ("L3_OPTICAL_HEARTBEAT",))

        no_opt = build_valid_interlock_envelope()
        no_opt["optical_isolation_present"] = False
        rep_opt = verify_actuator_interlock(no_opt)
        self.assertFalse(rep_opt.passed)
        self.assertIn("L3_OPTICAL_HEARTBEAT", rep_opt.failed_check_ids)

    def test_15_layer3_blocks_dual_channel_sensor_divergence(self) -> None:
        spoofed = apply_adversarial_faults(build_valid_interlock_envelope(), ["spoof_single_sensor"])
        report = verify_actuator_interlock(spoofed)
        self.assertFalse(report.passed)
        self.assertEqual(report.failed_check_ids, ("L3_DUAL_SENSOR_PLAUSIBILITY",))

    def test_16_layer3_blocks_manual_estop_and_software_reenergize_packets(self) -> None:
        estop = apply_adversarial_faults(build_valid_interlock_envelope(), ["press_manual_estop"])
        rep_estop = verify_actuator_interlock(estop)
        self.assertFalse(rep_estop.passed)
        self.assertEqual(rep_estop.failed_check_ids, ("L3_MANUAL_ESTOP_CLEAR",))

        reenergize = apply_adversarial_faults(build_valid_interlock_envelope(), ["software_reenergize_relay"])
        rep_re = verify_actuator_interlock(reenergize)
        self.assertFalse(rep_re.passed)
        self.assertEqual(rep_re.failed_check_ids, ("L3_NO_SOFTWARE_REENERGIZE",))

    def test_17_layer4_valid_cooperative_clearing_passes_all_invariants(self) -> None:
        env = build_valid_clearing_envelope()
        report = verify_cooperative_clearing(env)
        self.assertTrue(report.passed)
        self.assertEqual(report.failed_check_ids, ())
        self.assertEqual(len(report.checks), 4)

    def test_18_layer4_blocks_duplicate_sybil_epoch_nullifier(self) -> None:
        sybil = apply_adversarial_faults(build_valid_clearing_envelope(), ["replay_sybil_nullifier"])
        report = verify_cooperative_clearing(sybil)
        self.assertFalse(report.passed)
        self.assertEqual(report.failed_check_ids, ("L4_HUMAN_ROOT_NULLIFIER",))

    def test_19_layer4_blocks_nonzero_sum_mutual_credit_minting(self) -> None:
        unbalanced = apply_adversarial_faults(build_valid_clearing_envelope(), ["break_zero_sum_balance"])
        report = verify_cooperative_clearing(unbalanced)
        self.assertFalse(report.passed)
        self.assertEqual(report.failed_check_ids, ("L4_ZERO_SUM_CLEARING",))

    def test_20_layer4_blocks_raw_household_or_sponsor_pii_leakage(self) -> None:
        leaked = apply_adversarial_faults(build_valid_clearing_envelope(), ["leak_household_pii"])
        report = verify_cooperative_clearing(leaked)
        self.assertFalse(report.passed)
        self.assertEqual(report.failed_check_ids, ("L4_PRIVACY_MINIMIZATION",))

        # Also catch inline phone number inside an otherwise benign field name
        inline_phone = copy.deepcopy(build_valid_clearing_envelope())
        inline_phone["memo"] = "Call household sponsor at 613-555-0199"
        rep_phone = verify_cooperative_clearing(inline_phone)
        self.assertFalse(rep_phone.passed)
        self.assertIn("L4_PRIVACY_MINIMIZATION", rep_phone.failed_check_ids)

    def test_21_layer4_blocks_credit_cap_overrun_and_tampered_batch_digest(self) -> None:
        breached = apply_adversarial_faults(build_valid_clearing_envelope(), ["breach_credit_cap_and_commit"])
        report = verify_cooperative_clearing(breached)
        self.assertFalse(report.passed)
        self.assertEqual(report.failed_check_ids, ("L4_CLEARING_CAP_AND_COMMIT",))

    def test_22_boolean_type_confusion_rejected_across_numeric_fields(self) -> None:
        env = build_valid_lease_envelope()
        env["invocation"]["requested_units"] = True  # isinstance(True, int) is True in Python!
        report = verify_capability_lease(env)
        self.assertFalse(report.passed)
        self.assertIn("L1_TOOL_AND_CEILING_SCOPE", report.failed_check_ids)

    def test_23_dispatcher_and_combined_multi_fault_composition(self) -> None:
        combined = apply_adversarial_faults(
            build_valid_lease_envelope(),
            ["inject_invoice_command", "escalate_tool_scope", "use_expired_lease", "forge_lease_ceiling"],
        )
        rep = verify_envelope(combined)
        self.assertFalse(rep.passed)
        self.assertEqual(
            rep.failed_check_ids,
            (
                "L1_PRINCIPAL_BINDING",
                "L1_TOOL_AND_CEILING_SCOPE",
                "L1_EXPIRY_WINDOW",
                "L1_TAINT_SEPARATION",
            ),
        )
        with self.assertRaises(ValueError):
            verify_envelope({"envelope_type": "unknown_type"})

    def test_24_browser_test_vectors_roundtrip_and_fault_coverage(self) -> None:
        vectors = build_browser_test_vectors()
        serialized = json.dumps(vectors)
        parsed = json.loads(serialized)
        self.assertEqual(len(parsed["layers"]), 4)
        for layer in parsed["layers"]:
            base_rep = verify_envelope(layer["envelope"])
            self.assertTrue(base_rep.passed, f"{layer['id']} baseline failed")
            self.assertEqual(len(layer["faults"]), 4)
            for fault in layer["faults"]:
                mutated = apply_adversarial_faults(layer["envelope"], [fault["id"]])
                mut_rep = verify_envelope(mutated)
                self.assertFalse(
                    mut_rep.passed,
                    f"Fault {fault['id']} in {layer['id']} failed to trip an invariant",
                )


if __name__ == "__main__":
    unittest.main()
