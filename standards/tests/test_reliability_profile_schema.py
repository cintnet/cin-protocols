"""Deterministic validation and conformance test suite for Agent Reliability Profiles."""
import copy
import datetime as dt
import json
import re
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCHEMA_FILE = HERE.parent / "agent-reliability-profile-v0.1.json"
EXAMPLE_FILE = HERE.parent / "examples" / "financial-advisor-reliability-profile.json"


def _parse_iso_utc(ts_str):
    """Parse ISO 8601 string requiring explicit timezone offset (Z or [+-]HH:MM)."""
    if not isinstance(ts_str, str):
        raise ValueError("timestamp must be a string")
    if not (ts_str.endswith("Z") or re.search(r"[+-]\d{2}:\d{2}$", ts_str)):
        raise ValueError("timestamp must include explicit timezone offset (Z or [+-]HH:MM)")
    return dt.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))


def validate_reliability_profile(profile, now_iso=None):
    """Deterministic validator enforcing fail-closed bounds and schema rules for Agent Reliability Profiles."""
    errs = []
    if not isinstance(profile, dict):
        return ["profile must be a dictionary"]

    req = [
        "schema_version",
        "profile_id",
        "agent_id",
        "issued_at",
        "expires_at",
        "assurance_level",
        "domain",
        "operational_bounds",
        "error_tolerances",
        "handoff_governance",
        "fallback_policy",
        "signatures",
    ]
    for k in req:
        if k not in profile:
            errs.append(f"missing required key: {k}")
    extra = set(profile.keys()) - set(req)
    if extra:
        errs.append(f"unknown top-level keys: {sorted(extra)}")
    if errs:
        return errs

    if profile["schema_version"] != "0.1.0":
        errs.append("schema_version must be '0.1.0'")

    pid = profile.get("profile_id")
    if not isinstance(pid, str) or not re.match(r"^arp-[a-zA-Z0-9_-]+$", pid):
        errs.append("profile_id must match pattern ^arp-[a-zA-Z0-9_-]+$")

    aid = profile.get("agent_id")
    if not isinstance(aid, str) or not (3 <= len(aid) <= 128):
        errs.append("agent_id must be a string between 3 and 128 characters")

    try:
        issued = _parse_iso_utc(profile["issued_at"])
        expires = _parse_iso_utc(profile["expires_at"])
        if expires <= issued:
            errs.append("expires_at must be strictly after issued_at")
        if now_iso:
            now_dt = _parse_iso_utc(now_iso)
            if now_dt < issued:
                errs.append("profile is not yet valid (future issuance)")
            if now_dt >= expires:
                errs.append("profile has expired")
    except (ValueError, TypeError, AttributeError) as ex:
        errs.append(f"malformed ISO timestamp: {ex}")

    if profile.get("assurance_level") not in ("asserted", "validated", "verified"):
        errs.append("assurance_level must be one of: asserted, validated, verified")

    valid_domains = (
        "financial_advisory",
        "healthcare_records",
        "operational_infrastructure",
        "personal_twin",
        "general_assistant",
    )
    if profile.get("domain") not in valid_domains:
        errs.append(f"domain must be one of: {', '.join(valid_domains)}")

    # Operational bounds validation
    ob = profile.get("operational_bounds", {})
    if not isinstance(ob, dict):
        errs.append("operational_bounds must be a dictionary")
    else:
        ob_req = ["max_consecutive_steps", "max_daily_invocations", "max_exposure_units", "action_allowlist"]
        for k in ob_req:
            if k not in ob:
                errs.append(f"operational_bounds missing {k}")
        ob_extra = set(ob.keys()) - set(ob_req)
        if ob_extra:
            errs.append(f"operational_bounds contains unknown keys: {sorted(ob_extra)}")

        steps = ob.get("max_consecutive_steps")
        if not isinstance(steps, int) or isinstance(steps, bool) or steps < 1 or steps > 500:
            errs.append("max_consecutive_steps must be integer between 1 and 500")

        invocations = ob.get("max_daily_invocations")
        if not isinstance(invocations, int) or isinstance(invocations, bool) or invocations < 1 or invocations > 100000:
            errs.append("max_daily_invocations must be integer between 1 and 100000")

        exposure = ob.get("max_exposure_units")
        if not isinstance(exposure, int) or isinstance(exposure, bool) or exposure < 0 or exposure > 100000000:
            errs.append("max_exposure_units must be integer between 0 and 100000000")

        actions = ob.get("action_allowlist")
        if not isinstance(actions, list) or len(actions) == 0:
            errs.append("action_allowlist must be a non-empty list")
        elif not all(isinstance(a, str) and len(a.strip()) > 0 for a in actions):
            errs.append("action_allowlist must contain non-empty strings")

    # Error tolerances validation
    et = profile.get("error_tolerances", {})
    if not isinstance(et, dict):
        errs.append("error_tolerances must be a dictionary")
    else:
        et_req = ["max_error_rate_bps", "max_drift_tolerance_bps"]
        for k in et_req:
            if k not in et:
                errs.append(f"error_tolerances missing {k}")
        et_extra = set(et.keys()) - set(et_req)
        if et_extra:
            errs.append(f"error_tolerances contains unknown keys: {sorted(et_extra)}")

        err_rate = et.get("max_error_rate_bps")
        if not isinstance(err_rate, int) or isinstance(err_rate, bool) or err_rate < 0 or err_rate > 10000:
            errs.append("max_error_rate_bps must be integer between 0 and 10000")

        drift = et.get("max_drift_tolerance_bps")
        if not isinstance(drift, int) or isinstance(drift, bool) or drift < 0 or drift > 10000:
            errs.append("max_drift_tolerance_bps must be integer between 0 and 10000")

    # Handoff governance validation
    hg = profile.get("handoff_governance", {})
    if not isinstance(hg, dict):
        errs.append("handoff_governance must be a dictionary")
    else:
        hg_req = ["contract_anchor_hash", "validator_mode", "halt_on_failure"]
        for k in hg_req:
            if k not in hg:
                errs.append(f"handoff_governance missing {k}")
        hg_extra = set(hg.keys()) - set(hg_req)
        if hg_extra:
            errs.append(f"handoff_governance contains unknown keys: {sorted(hg_extra)}")

        c_hash = hg.get("contract_anchor_hash")
        if not isinstance(c_hash, str) or not re.match(r"^[a-f0-9]{64}$", c_hash):
            errs.append("contract_anchor_hash must be a 64-char hex SHA-256 string")

        v_mode = hg.get("validator_mode")
        if v_mode not in ("deterministic_gate", "human_gate"):
            errs.append("validator_mode must be 'deterministic_gate' or 'human_gate'")

        halt = hg.get("halt_on_failure")
        if not isinstance(halt, bool):
            errs.append("halt_on_failure must be a boolean")

    # Fallback policy validation
    fp = profile.get("fallback_policy", {})
    if not isinstance(fp, dict):
        errs.append("fallback_policy must be a dictionary")
    else:
        fp_req = ["on_breach", "designated_supervisor_id"]
        for k in fp_req:
            if k not in fp:
                errs.append(f"fallback_policy missing {k}")
        fp_extra = set(fp.keys()) - set(fp_req)
        if fp_extra:
            errs.append(f"fallback_policy contains unknown keys: {sorted(fp_extra)}")

        on_breach = fp.get("on_breach")
        if on_breach not in ("halt", "escalate_to_human", "safe_state"):
            errs.append("on_breach must be 'halt', 'escalate_to_human', or 'safe_state'")

        sup_id = fp.get("designated_supervisor_id")
        if not isinstance(sup_id, str) or not (3 <= len(sup_id.strip()) <= 128):
            errs.append("designated_supervisor_id must be between 3 and 128 characters")

    # Signatures validation
    sigs = profile.get("signatures")
    if not isinstance(sigs, list) or len(sigs) == 0:
        errs.append("signatures must be a non-empty list")
    else:
        for idx, s in enumerate(sigs):
            if not isinstance(s, dict):
                errs.append(f"signature[{idx}] must be an object")
                continue
            s_req = ["signer_id", "algorithm", "signature_hex"]
            for k in s_req:
                if k not in s:
                    errs.append(f"signature[{idx}] missing {k}")
            s_extra = set(s.keys()) - set(s_req)
            if s_extra:
                errs.append(f"signature[{idx}] contains unknown keys: {sorted(s_extra)}")

            signer = s.get("signer_id")
            if not isinstance(signer, str) or not (3 <= len(signer.strip()) <= 128):
                errs.append(f"signature[{idx}].signer_id must be a string between 3 and 128 characters")

            if s.get("algorithm") != "ed25519":
                errs.append(f"signature[{idx}].algorithm must be 'ed25519'")

            sig_hex = s.get("signature_hex")
            if not isinstance(sig_hex, str) or not re.match(r"^[a-f0-9]{128}$", sig_hex):
                errs.append(f"signature[{idx}].signature_hex must be a 128-char hex string")

    return errs


class TestReliabilityProfileSchema(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(SCHEMA_FILE, "r", encoding="utf-8") as f:
            cls.schema_data = json.load(f)
        with open(EXAMPLE_FILE, "r", encoding="utf-8") as f:
            cls.example_data = json.load(f)

    def test_schema_structure_and_fail_closed_rules(self):
        """Schema file must declare $schema, title, and fail-closed additionalProperties: false."""
        self.assertIn("$schema", self.schema_data)
        self.assertEqual(self.schema_data.get("title"), "AgentReliabilityProfile")
        self.assertEqual(self.schema_data.get("type"), "object")
        self.assertFalse(self.schema_data.get("additionalProperties"))

    def test_conforming_example_passes_validation(self):
        """Conforming example artifact passes validation without errors."""
        errs = validate_reliability_profile(self.example_data)
        self.assertEqual(errs, [], f"Example failed validation: {errs}")

    def test_reject_unknown_top_level_fields(self):
        """Fail-closed validator must reject unknown top-level keys."""
        bad = copy.deepcopy(self.example_data)
        bad["unexpected_field"] = "malicious_payload"
        errs = validate_reliability_profile(bad)
        self.assertTrue(any("unknown top-level keys" in e for e in errs))

    def test_reject_unknown_nested_fields(self):
        """Fail-closed validator must reject unexpected keys in nested sections."""
        for section in ["operational_bounds", "error_tolerances", "handoff_governance", "fallback_policy"]:
            bad = copy.deepcopy(self.example_data)
            bad[section]["unauthorized_subfield"] = 123
            errs = validate_reliability_profile(bad)
            self.assertTrue(
                any("unknown keys" in e for e in errs),
                f"Failed to reject unknown key in nested section {section}",
            )

    def test_reject_expired_or_inverted_lifespan(self):
        """Validator must reject profiles with expires_at <= issued_at or past expiry."""
        bad = copy.deepcopy(self.example_data)
        bad["expires_at"] = bad["issued_at"]
        errs = validate_reliability_profile(bad)
        self.assertTrue(any("strictly after issued_at" in e for e in errs))

        # Check explicit expiration check
        errs_expired = validate_reliability_profile(self.example_data, now_iso="2027-01-01T00:00:00Z")
        self.assertTrue(any("has expired" in e for e in errs_expired))

    def test_reject_future_issuance(self):
        """Validator must reject profiles evaluated before their issued_at timestamp."""
        errs_future = validate_reliability_profile(self.example_data, now_iso="2026-01-01T00:00:00Z")
        self.assertTrue(any("future issuance" in e for e in errs_future))

    def test_reject_naive_timestamps(self):
        """Validator must reject timestamps lacking explicit timezone offsets."""
        bad = copy.deepcopy(self.example_data)
        bad["issued_at"] = "2026-10-11T00:00:00"
        errs = validate_reliability_profile(bad)
        self.assertTrue(any("explicit timezone offset" in e for e in errs))

    def test_reject_invalid_assurance_level(self):
        """Only asserted, validated, and verified are permitted assurance tiers."""
        bad = copy.deepcopy(self.example_data)
        bad["assurance_level"] = "unconditional_guarantee"
        errs = validate_reliability_profile(bad)
        self.assertTrue(any("assurance_level must be one of" in e for e in errs))

    def test_reject_out_of_range_error_tolerances(self):
        """Negative basis points or > 10000 bps (100%) must be rejected."""
        bad = copy.deepcopy(self.example_data)
        bad["error_tolerances"]["max_error_rate_bps"] = -1
        errs = validate_reliability_profile(bad)
        self.assertTrue(any("max_error_rate_bps must be integer" in e for e in errs))

        bad["error_tolerances"]["max_error_rate_bps"] = 10001
        errs2 = validate_reliability_profile(bad)
        self.assertTrue(any("max_error_rate_bps must be integer" in e for e in errs2))

        # Drift tolerance bounds
        bad_drift = copy.deepcopy(self.example_data)
        bad_drift["error_tolerances"]["max_drift_tolerance_bps"] = -5
        errs3 = validate_reliability_profile(bad_drift)
        self.assertTrue(any("max_drift_tolerance_bps must be integer" in e for e in errs3))

        bad_drift["error_tolerances"]["max_drift_tolerance_bps"] = 20000
        errs4 = validate_reliability_profile(bad_drift)
        self.assertTrue(any("max_drift_tolerance_bps must be integer" in e for e in errs4))

    def test_reject_floats_and_booleans_on_integer_fields(self):
        """Floating point values and booleans must fail closed on integer fields."""
        # Floats
        bad_float = copy.deepcopy(self.example_data)
        bad_float["operational_bounds"]["max_consecutive_steps"] = 10.5
        errs = validate_reliability_profile(bad_float)
        self.assertTrue(any("max_consecutive_steps must be integer" in e for e in errs))

        bad_float2 = copy.deepcopy(self.example_data)
        bad_float2["error_tolerances"]["max_error_rate_bps"] = 25.0
        errs2 = validate_reliability_profile(bad_float2)
        self.assertTrue(any("max_error_rate_bps must be integer" in e for e in errs2))

        # Booleans
        bad_bool = copy.deepcopy(self.example_data)
        bad_bool["operational_bounds"]["max_daily_invocations"] = True
        errs3 = validate_reliability_profile(bad_bool)
        self.assertTrue(any("max_daily_invocations must be integer" in e for e in errs3))

    def test_reject_empty_or_whitespace_action_allowlist(self):
        """Action allowlist cannot be empty or contain non-string / whitespace-only entries."""
        bad_empty = copy.deepcopy(self.example_data)
        bad_empty["operational_bounds"]["action_allowlist"] = []
        errs = validate_reliability_profile(bad_empty)
        self.assertTrue(any("action_allowlist must be a non-empty list" in e for e in errs))

        bad_space = copy.deepcopy(self.example_data)
        bad_space["operational_bounds"]["action_allowlist"] = ["   "]
        errs2 = validate_reliability_profile(bad_space)
        self.assertTrue(any("non-empty strings" in e for e in errs2))

        bad_type = copy.deepcopy(self.example_data)
        bad_type["operational_bounds"]["action_allowlist"] = [123]  # type: ignore
        errs3 = validate_reliability_profile(bad_type)
        self.assertTrue(any("non-empty strings" in e for e in errs3))

    def test_reject_invalid_enums(self):
        """Invalid domain, validator mode, and on_breach enum values must be rejected."""
        bad_dom = copy.deepcopy(self.example_data)
        bad_dom["domain"] = "unregulated_arbitrage"
        errs = validate_reliability_profile(bad_dom)
        self.assertTrue(any("domain must be one of" in e for e in errs))

        bad_mode = copy.deepcopy(self.example_data)
        bad_mode["handoff_governance"]["validator_mode"] = "oracle_guess"
        errs2 = validate_reliability_profile(bad_mode)
        self.assertTrue(any("validator_mode must be" in e for e in errs2))

        bad_breach = copy.deepcopy(self.example_data)
        bad_breach["fallback_policy"]["on_breach"] = "ignore_and_continue"
        errs3 = validate_reliability_profile(bad_breach)
        self.assertTrue(any("on_breach must be" in e for e in errs3))

    def test_reject_malformed_handoff_hash(self):
        """Handoff contract anchor hash must be valid 64-char hex SHA-256."""
        bad = copy.deepcopy(self.example_data)
        bad["handoff_governance"]["contract_anchor_hash"] = "not_a_valid_hash"
        errs = validate_reliability_profile(bad)
        self.assertTrue(any("contract_anchor_hash must be a 64-char hex" in e for e in errs))

    def test_reject_non_boolean_halt_on_failure(self):
        """halt_on_failure must be strictly boolean, rejecting string coercion."""
        bad = copy.deepcopy(self.example_data)
        bad["handoff_governance"]["halt_on_failure"] = "true"  # type: ignore
        errs = validate_reliability_profile(bad)
        self.assertTrue(any("halt_on_failure must be a boolean" in e for e in errs))

    def test_reject_malformed_signatures(self):
        """Signatures must validate signer_id length, algorithm, hex length and extra keys."""
        # Empty array
        bad_empty = copy.deepcopy(self.example_data)
        bad_empty["signatures"] = []
        errs = validate_reliability_profile(bad_empty)
        self.assertTrue(any("signatures must be a non-empty list" in e for e in errs))

        # Bad signer_id (too short or empty or wrong type)
        bad_signer = copy.deepcopy(self.example_data)
        bad_signer["signatures"][0]["signer_id"] = ""
        errs2 = validate_reliability_profile(bad_signer)
        self.assertTrue(any("signer_id must be a string between 3 and 128" in e for e in errs2))

        bad_signer2 = copy.deepcopy(self.example_data)
        bad_signer2["signatures"][0]["signer_id"] = 12345  # type: ignore
        errs3 = validate_reliability_profile(bad_signer2)
        self.assertTrue(any("signer_id must be a string between 3 and 128" in e for e in errs3))

        # Unsupported algorithm
        bad_algo = copy.deepcopy(self.example_data)
        bad_algo["signatures"][0]["algorithm"] = "rsa2048"
        errs4 = validate_reliability_profile(bad_algo)
        self.assertTrue(any("algorithm must be 'ed25519'" in e for e in errs4))

        # Bad signature hex
        bad_hex = copy.deepcopy(self.example_data)
        bad_hex["signatures"][0]["signature_hex"] = "tooshort"
        errs5 = validate_reliability_profile(bad_hex)
        self.assertTrue(any("signature_hex must be a 128-char hex" in e for e in errs5))


if __name__ == "__main__":
    unittest.main()
