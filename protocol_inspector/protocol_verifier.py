"""Reference stdlib verifier for CIN Open Protocol & Safety-Case Envelopes.

Implements deterministic, zero-dependency verification across four protocol layers:
  1. Scoped Capability Lease (MCP / A2A + Dennis & Van Horn 1966 + Debenedetti et al. 2025)
  2. Tamper-Evident Provenance Receipt (W3C PROV-DM + Necula 1997)
  3. Physical Dead-Man Actuator Interlock (Knight & Leveson 1986 + Bainbridge 1983)
  4. Selective-Disclosure Cooperative Task Receipt (Stodder 2009 + Saltzer & Schroeder 1975)

Pure Python standard library only (`dataclasses`, `hashlib`, `hmac`, `json`, `re`, `copy`).
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
from typing import Any

PROTOCOL_VERSION = "cin-protocol/v0.4"
DEMO_SIGNING_KEY = "cin-sandbox-demo-principal-key-room304-v04"
MAX_LEASE_DURATION_SEC = 86_400
MAX_HEARTBEAT_GAP_MS = 50

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_PII_KEYS = frozenset({
    "full_name",
    "household_name",
    "sponsor_name",
    "street_address",
    "postal_address",
    "email",
    "phone",
    "phone_number",
    "national_id",
    "sin",
    "ssn",
    "raw_household_id",
    "date_of_birth",
})
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b")
_STREET_PII_RE = re.compile(
    r"\b\d{1,5}\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\s+(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Boulevard|Blvd|Lane|Ln)\b"
)


@dataclass(frozen=True)
class InvariantCheck:
    """Single deterministic check result within a protocol layer."""

    check_id: str
    label: str
    passed: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "label": self.label,
            "passed": self.passed,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class VerificationReport:
    """Complete 4-check scorecard for a protocol envelope."""

    layer_id: str
    layer_name: str
    passed: bool
    failed_check_ids: tuple[str, ...]
    protection_summary: str
    checks: tuple[InvariantCheck, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "layer_id": self.layer_id,
            "layer_name": self.layer_name,
            "passed": self.passed,
            "failed_check_ids": list(self.failed_check_ids),
            "protection_summary": self.protection_summary,
            "checks": [c.to_dict() for c in self.checks],
        }


def canonical_json(obj: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes with sorted keys and compact ASCII separators."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_hex(obj: Any) -> str:
    """Return lowercase 64-char SHA-256 hex digest over canonical JSON (or raw UTF-8 string)."""
    if isinstance(obj, bytes):
        data = obj
    elif isinstance(obj, str):
        data = obj.encode("utf-8")
    else:
        data = canonical_json(obj)
    return hashlib.sha256(data).hexdigest()


def hmac_sha256_hex(secret: str, payload: Any) -> str:
    """Return lowercase 64-char HMAC-SHA256 hex tag over canonical JSON."""
    key_bytes = secret.encode("utf-8")
    msg_bytes = payload if isinstance(payload, bytes) else canonical_json(payload)
    return hmac.new(key_bytes, msg_bytes, hashlib.sha256).hexdigest()


def _lease_grant_payload(envelope: dict[str, Any]) -> dict[str, Any]:
    return {
        "allowed_tools": list(envelope.get("allowed_tools") or []),
        "ceiling_units": envelope.get("ceiling_units"),
        "delegate_agent_id": envelope.get("delegate_agent_id"),
        "expires_at_epoch": envelope.get("expires_at_epoch"),
        "issued_at_epoch": envelope.get("issued_at_epoch"),
        "lease_id": envelope.get("lease_id"),
        "principal_id": envelope.get("principal_id"),
    }


def _replay_commitment_payload(seed: str, input_sha256: str, output_payload: Any) -> dict[str, Any]:
    return {
        "input_sha256": input_sha256,
        "output_payload": output_payload,
        "seed": seed,
    }


def _clearing_commitment_payload(epoch_id: str, epoch_nullifier: str, entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "entries": entries,
        "epoch_id": epoch_id,
        "epoch_nullifier": epoch_nullifier,
    }


# ---------------------------------------------------------------------------
# Layer 1: Scoped Capability Lease
# ---------------------------------------------------------------------------

def verify_capability_lease(
    envelope: dict[str, Any],
    signing_key: str = DEMO_SIGNING_KEY,
) -> VerificationReport:
    """Verify Layer 1 Scoped Capability Lease invariants."""
    principal_id = str(envelope.get("principal_id") or "").strip()
    delegate_id = str(envelope.get("delegate_agent_id") or "").strip()
    claimed_mac = str(envelope.get("delegation_mac") or "").strip().lower()
    expected_mac = hmac_sha256_hex(signing_key, _lease_grant_payload(envelope))
    mac_ok = (
        bool(principal_id)
        and bool(delegate_id)
        and bool(_HEX64_RE.match(claimed_mac))
        and hmac.compare_digest(claimed_mac, expected_mac)
    )
    c1 = InvariantCheck(
        check_id="L1_PRINCIPAL_BINDING",
        label="Owner signature binds lease terms",
        passed=mac_ok,
        detail=(
            f"Verified HMAC binding from {principal_id} to {delegate_id}."
            if mac_ok
            else "Blocked: lease grant terms were altered without a valid owner signature."
        ),
    )

    allowed_tools = envelope.get("allowed_tools")
    allowed_list = [str(t) for t in allowed_tools] if isinstance(allowed_tools, list) else []
    invocation = envelope.get("invocation") if isinstance(envelope.get("invocation"), dict) else {}
    req_tool = str(invocation.get("requested_tool") or "")
    ceiling = envelope.get("ceiling_units")
    req_units = invocation.get("requested_units")
    units_valid = (
        isinstance(ceiling, int)
        and not isinstance(ceiling, bool)
        and isinstance(req_units, int)
        and not isinstance(req_units, bool)
        and 0 < req_units <= ceiling
    )
    tool_valid = bool(req_tool) and req_tool in allowed_list
    scope_ok = tool_valid and units_valid
    if scope_ok:
        scope_detail = (
            f"Tool '{req_tool}' is allow-listed and {req_units} units stays within the {ceiling}-unit cap."
        )
    elif not tool_valid:
        scope_detail = (
            f"Blocked: tool '{req_tool or 'none'}' is outside leased allow-list {allowed_list}."
        )
    else:
        scope_detail = (
            f"Blocked: requested {req_units} units exceeds the {ceiling}-unit lease ceiling."
        )
    c2 = InvariantCheck(
        check_id="L1_TOOL_AND_CEILING_SCOPE",
        label="Allow-listed tool and unit ceiling",
        passed=scope_ok,
        detail=scope_detail,
    )

    issued = envelope.get("issued_at_epoch")
    expires = envelope.get("expires_at_epoch")
    now = envelope.get("evaluated_at_epoch")
    times_typed = all(
        isinstance(v, int) and not isinstance(v, bool) for v in (issued, expires, now)
    )
    window_bounded = times_typed and (0 < (expires - issued) <= MAX_LEASE_DURATION_SEC)
    active_now = window_bounded and (issued <= now < expires)
    if active_now:
        rem_min = (expires - now) // 60
        exp_detail = f"Active lease window valid ({rem_min} min remaining before automatic cutoff)."
    elif times_typed and (expires - issued) > MAX_LEASE_DURATION_SEC:
        exp_detail = "Blocked: lease duration exceeds 24-hour standing-grant safety cap."
    elif times_typed and now >= expires:
        over_min = max(1, (now - expires) // 60)
        exp_detail = f"Blocked: lease expired {over_min} min ago; keycard drained back to zero authority."
    else:
        exp_detail = "Blocked: lease timestamps are missing, inverted, or not yet valid."
    c3 = InvariantCheck(
        check_id="L1_EXPIRY_WINDOW",
        label="Time-bounded lease expiry window",
        passed=active_now,
        detail=exp_detail,
    )

    control_origin = str(invocation.get("control_origin") or "")
    tainted_tokens = invocation.get("tainted_control_tokens")
    has_taint_list = isinstance(tainted_tokens, list)
    taint_free = (
        control_origin == "trusted_principal_intent"
        and has_taint_list
        and len(tainted_tokens) == 0
    )
    if taint_free:
        taint_detail = "Control flow originates strictly from the verified owner intent, isolated from external documents."
    else:
        src_hint = ", ".join(str(x) for x in (tainted_tokens or [])) or control_origin or "external_input"
        taint_detail = (
            f"Blocked: untrusted external text ({src_hint}) attempted to steer tool selection or arguments."
        )
    c4 = InvariantCheck(
        check_id="L1_TAINT_SEPARATION",
        label="Untrusted-input taint separation",
        passed=taint_free,
        detail=taint_detail,
    )

    checks = (c1, c2, c3, c4)
    failed = tuple(c.check_id for c in checks if not c.passed)
    summary = (
        "All four capability-lease invariants hold: the assistant acts inside an owner-signed, time-limited scope with untrusted document text quarantined as passive data."
        if not failed
        else "Action halted before execution: the capability airlock rejected an out-of-bounds, expired, forged, or prompt-injected tool call before any external state changed."
    )
    return VerificationReport(
        layer_id="capability_lease",
        layer_name="Layer 1 · Scoped Capability Lease",
        passed=(len(failed) == 0),
        failed_check_ids=failed,
        protection_summary=summary,
        checks=checks,
    )


# ---------------------------------------------------------------------------
# Layer 2: Tamper-Evident Provenance Receipt
# ---------------------------------------------------------------------------

def verify_provenance_receipt(envelope: dict[str, Any]) -> VerificationReport:
    """Verify Layer 2 Tamper-Evident Provenance Receipt invariants."""
    input_payload = envelope.get("input_payload")
    claimed_in = str(envelope.get("claimed_input_sha256") or "").strip().lower()
    actual_in = sha256_hex(input_payload) if input_payload is not None else ""
    in_ok = bool(_HEX64_RE.match(claimed_in)) and hmac.compare_digest(claimed_in, actual_in)
    c1 = InvariantCheck(
        check_id="L2_INPUT_DIGEST",
        label="Canonical SHA-256 input digest",
        passed=in_ok,
        detail=(
            f"Input payload matches recorded digest {actual_in[:12]}...."
            if in_ok
            else "Blocked: input payload no longer matches the SHA-256 digest sealed when the step ran."
        ),
    )

    output_payload = envelope.get("output_payload")
    claimed_out = str(envelope.get("claimed_output_sha256") or "").strip().lower()
    actual_out = sha256_hex(output_payload) if output_payload is not None else ""
    out_ok = bool(_HEX64_RE.match(claimed_out)) and hmac.compare_digest(claimed_out, actual_out)
    c2 = InvariantCheck(
        check_id="L2_OUTPUT_DIGEST",
        label="Canonical SHA-256 output digest",
        passed=out_ok,
        detail=(
            f"Output payload matches recorded digest {actual_out[:12]}...."
            if out_ok
            else "Blocked: output payload was altered after execution and fails SHA-256 verification."
        ),
    )

    step_index = envelope.get("step_index")
    parent_hash = str(envelope.get("parent_receipt_sha256") or "").strip().lower()
    expected_parent = str(envelope.get("expected_parent_receipt_sha256") or "").strip().lower()
    spot = envelope.get("replay_spot_check") if isinstance(envelope.get("replay_spot_check"), dict) else {}
    contiguous = spot.get("log_sequence_contiguous") is True
    omitted = spot.get("omitted_step_count")
    chain_ok = (
        isinstance(step_index, int)
        and not isinstance(step_index, bool)
        and step_index >= 1
        and bool(_HEX64_RE.match(parent_hash))
        and hmac.compare_digest(parent_hash, expected_parent)
        and contiguous
        and omitted == 0
    )
    if chain_ok:
        chain_detail = f"Step {step_index} chains cleanly to parent receipt {parent_hash[:12]}... with zero omitted steps."
    else:
        chain_detail = "Blocked: parent receipt hash link is broken or intermediate log steps were omitted."
    c3 = InvariantCheck(
        check_id="L2_PARENT_CHAIN_LINK",
        label="Append-only parent receipt link",
        passed=chain_ok,
        detail=chain_detail,
    )

    seed = str(spot.get("seed") or "")
    replay_out = str(spot.get("deterministic_replay_output_sha256") or "").strip().lower()
    claimed_proof = str(spot.get("replay_proof_sha256") or "").strip().lower()
    expected_proof = sha256_hex(_replay_commitment_payload(seed, actual_in, output_payload)) if seed else ""
    replay_ok = (
        bool(seed)
        and bool(_HEX64_RE.match(replay_out))
        and bool(_HEX64_RE.match(claimed_proof))
        and hmac.compare_digest(replay_out, actual_out)
        and hmac.compare_digest(claimed_proof, expected_proof)
    )
    c4 = InvariantCheck(
        check_id="L2_REPLAY_SPOT_PROOF",
        label="Deterministic spot-check replay proof",
        passed=replay_ok,
        detail=(
            f"Seeded replay ({seed}) reproduces identical output and proof {expected_proof[:12]}...."
            if replay_ok
            else "Blocked: deterministic spot-check replay produced a different output than the assistant claimed."
        ),
    )

    checks = (c1, c2, c3, c4)
    failed = tuple(c.check_id for c in checks if not c.passed)
    summary = (
        "All four provenance invariants hold: inputs, outputs, parent receipt chain, and seeded replay match byte for byte."
        if not failed
        else "Audit alarm raised: post-hoc tampering, log cherry-picking, or unfaithful output was caught by cryptographic receipt verification."
    )
    return VerificationReport(
        layer_id="provenance_receipt",
        layer_name="Layer 2 · Tamper-Evident Provenance Receipt",
        passed=(len(failed) == 0),
        failed_check_ids=failed,
        protection_summary=summary,
        checks=checks,
    )


# ---------------------------------------------------------------------------
# Layer 3: Physical Dead-Man Actuator Interlock
# ---------------------------------------------------------------------------

def verify_actuator_interlock(envelope: dict[str, Any]) -> VerificationReport:
    """Verify Layer 3 Physical Dead-Man Actuator Interlock invariants."""
    optical_ok = envelope.get("optical_isolation_present") is True
    gap_ms = envelope.get("heartbeat_gap_ms")
    max_gap = envelope.get("max_heartbeat_gap_ms", MAX_HEARTBEAT_GAP_MS)
    gap_typed = (
        isinstance(gap_ms, (int, float))
        and not isinstance(gap_ms, bool)
        and isinstance(max_gap, (int, float))
        and not isinstance(max_gap, bool)
    )
    hb_ok = (
        optical_ok
        and gap_typed
        and max_gap <= MAX_HEARTBEAT_GAP_MS
        and 0 <= gap_ms <= max_gap
    )
    if hb_ok:
        hb_detail = f"Optically isolated heartbeat arrived in {gap_ms} ms (within {MAX_HEARTBEAT_GAP_MS} ms physical relay limit)."
    elif not optical_ok:
        hb_detail = "Blocked: optical isolation missing between compute bus and motor relay."
    else:
        hb_detail = f"Blocked: heartbeat gap ({gap_ms} ms) exceeded the {MAX_HEARTBEAT_GAP_MS} ms hardware dead-man cutoff; relay dropped power."
    c1 = InvariantCheck(
        check_id="L3_OPTICAL_HEARTBEAT",
        label="50 ms optically isolated heartbeat",
        passed=hb_ok,
        detail=hb_detail,
    )

    sensors = envelope.get("dual_channel_sensors") if isinstance(envelope.get("dual_channel_sensors"), dict) else {}
    ch_a = sensors.get("channel_a_load_kg")
    ch_b = sensors.get("channel_b_load_kg")
    max_div = sensors.get("max_divergence_kg")
    plausible = sensors.get("hardware_plausibility_ok") is True
    nums_ok = all(
        isinstance(v, (int, float)) and not isinstance(v, bool)
        for v in (ch_a, ch_b, max_div)
    )
    divergence = abs(float(ch_a) - float(ch_b)) if nums_ok else 999.0
    sensor_ok = (
        nums_ok
        and ch_a >= 0
        and ch_b >= 0
        and max_div > 0
        and divergence <= max_div
        and plausible
    )
    if sensor_ok:
        sensor_detail = (
            f"Dual load channels agree within {divergence:.1f} kg (limit {max_div:.1f} kg)."
        )
    else:
        sensor_detail = (
            f"Blocked: independent load channels diverged by {divergence:.1f} kg (limit {max_div} kg) or failed plausibility."
        )
    c2 = InvariantCheck(
        check_id="L3_DUAL_SENSOR_PLAUSIBILITY",
        label="Dual-channel sensor plausibility",
        passed=sensor_ok,
        detail=sensor_detail,
    )

    estop_latched = envelope.get("manual_estop_latched") is not False
    c3 = InvariantCheck(
        check_id="L3_MANUAL_ESTOP_CLEAR",
        label="Manual physical E-stop unlatched",
        passed=not estop_latched,
        detail=(
            "Hardwired mushroom E-stop loop is closed and clear at the bay post."
            if not estop_latched
            else "Blocked: worker pressed the physical E-stop button; copper loop physically severed motor power."
        ),
    )

    relay_tripped = envelope.get("relay_tripped_latch") is True
    sw_reenergize = envelope.get("software_reenergize_attempt") is True
    no_sw_override = (not sw_reenergize) and (not relay_tripped)
    if no_sw_override:
        latch_detail = "Hardware latch clean; zero remote software reset commands permitted on the power rail."
    elif sw_reenergize:
        latch_detail = "Blocked: network packet tried to re-energize a tripped relay; only a physical key turn at the machine can reset power."
    else:
        latch_detail = "Blocked: physical safety relay is latched open and awaits on-site human inspection."
    c4 = InvariantCheck(
        check_id="L3_NO_SOFTWARE_REENERGIZE",
        label="Software cannot re-energize tripped latch",
        passed=no_sw_override,
        detail=latch_detail,
    )

    checks = (c1, c2, c3, c4)
    failed = tuple(c.check_id for c in checks if not c.passed)
    summary = (
        "All four physical interlock invariants hold: optical heartbeat, independent sensors, and manual E-stop circuits keep physical motion inside safe hardware bounds."
        if not failed
        else "Physical power cut engaged: hardware interlocks de-energized the actuator locally, and no software command over the network can force the relay closed."
    )
    return VerificationReport(
        layer_id="actuator_interlock",
        layer_name="Layer 3 · Physical Dead-Man Actuator Interlock",
        passed=(len(failed) == 0),
        failed_check_ids=failed,
        protection_summary=summary,
        checks=checks,
    )


# ---------------------------------------------------------------------------
# Layer 4: Selective-Disclosure Cooperative Task Receipt
# ---------------------------------------------------------------------------

def _scan_for_pii(obj: Any, path: str = "") -> list[str]:
    hits: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            k_norm = str(k).strip().lower()
            cur_path = f"{path}.{k}" if path else str(k)
            if k_norm in _FORBIDDEN_PII_KEYS:
                hits.append(f"forbidden field '{cur_path}'")
            hits.extend(_scan_for_pii(v, cur_path))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            hits.extend(_scan_for_pii(item, f"{path}[{idx}]"))
    elif isinstance(obj, str):
        if _EMAIL_RE.search(obj):
            hits.append(f"raw email in '{path}'")
        if _PHONE_RE.search(obj):
            hits.append(f"raw phone number in '{path}'")
        if _STREET_PII_RE.search(obj):
            hits.append(f"street address in '{path}'")
    return hits


def verify_cooperative_clearing(envelope: dict[str, Any]) -> VerificationReport:
    """Verify Layer 4 Selective-Disclosure Cooperative Task Receipt invariants."""
    epoch_id = str(envelope.get("epoch_id") or "")
    blinded_root = str(envelope.get("blinded_root_commitment") or "")
    nullifier = str(envelope.get("epoch_nullifier") or "").strip().lower()
    root_proof_valid = envelope.get("human_root_proof_valid") is True
    seen_list = envelope.get("seen_epoch_nullifiers")
    seen_set = {str(x).strip().lower() for x in seen_list} if isinstance(seen_list, list) else set()
    expected_nullifier = sha256_hex(f"nullifier|{epoch_id}|{blinded_root}") if (epoch_id and blinded_root) else ""
    nullifier_ok = (
        root_proof_valid
        and bool(_HEX64_RE.match(nullifier))
        and hmac.compare_digest(nullifier, expected_nullifier)
        and nullifier not in seen_set
    )
    if nullifier_ok:
        nul_detail = f"Unique 1-human-root nullifier {nullifier[:12]}... verified for epoch {epoch_id}."
    elif nullifier in seen_set:
        nul_detail = f"Blocked: duplicate epoch nullifier {nullifier[:12]}... replayed; extra bots under one person get zero extra claim."
    else:
        nul_detail = "Blocked: missing or invalid 1-human-root nullifier proof."
    c1 = InvariantCheck(
        check_id="L4_HUMAN_ROOT_NULLIFIER",
        label="1-human-root Sybil nullifier uniqueness",
        passed=nullifier_ok,
        detail=nul_detail,
    )

    entries = envelope.get("entries")
    valid_entries = isinstance(entries, list) and len(entries) >= 2
    deltas: list[int] = []
    entries_typed = True
    if valid_entries:
        for item in entries:
            if not isinstance(item, dict):
                entries_typed = False
                break
            d = item.get("delta_credits")
            if not isinstance(d, int) or isinstance(d, bool):
                entries_typed = False
                break
            deltas.append(d)
    else:
        entries_typed = False

    net_sum = sum(deltas) if entries_typed else None
    pos_vol = sum(d for d in deltas if d > 0) if entries_typed else 0
    zero_sum_ok = (
        entries_typed
        and pos_vol > 0
        and any(d < 0 for d in deltas)
        and net_sum == 0
    )
    if zero_sum_ok:
        zs_detail = f"Mutual credit deltas sum to exact 0 across {len(deltas)} blinded accounts ({pos_vol} units cleared)."
    elif net_sum is not None and net_sum != 0:
        zs_detail = f"Blocked: ledger deltas sum to {net_sum:+d} instead of 0; unbacked credit creation rejected."
    else:
        zs_detail = "Blocked: clearing batch lacks paired integer debit and credit entries."
    c2 = InvariantCheck(
        check_id="L4_ZERO_SUM_CLEARING",
        label="Zero-sum mutual credit conservation",
        passed=zero_sum_ok,
        detail=zs_detail,
    )

    pii_hits = _scan_for_pii(envelope)
    privacy_ok = len(pii_hits) == 0
    c3 = InvariantCheck(
        check_id="L4_PRIVACY_MINIMIZATION",
        label="Selective disclosure (zero raw PII)",
        passed=privacy_ok,
        detail=(
            "Envelope carries only blinded commitments; zero household names, addresses, emails, or phone numbers exposed."
            if privacy_ok
            else f"Blocked: raw personal data detected in shared ledger envelope ({', '.join(pii_hits[:2])})."
        ),
    )

    credit_limit = envelope.get("mutual_credit_limit")
    limit_typed = isinstance(credit_limit, int) and not isinstance(credit_limit, bool) and credit_limit > 0
    balances_within_cap = limit_typed and entries_typed
    breached_account = ""
    if balances_within_cap and isinstance(entries, list):
        for item in entries:
            post_bal = item.get("post_balance_credits")
            if not isinstance(post_bal, int) or isinstance(post_bal, bool) or abs(post_bal) > credit_limit:
                balances_within_cap = False
                breached_account = str(item.get("account_commitment") or "account")
                break

    claimed_commit = str(envelope.get("clearing_commitment_sha256") or "").strip().lower()
    expected_commit = (
        sha256_hex(_clearing_commitment_payload(epoch_id, nullifier, entries))
        if isinstance(entries, list)
        else ""
    )
    commit_ok = bool(_HEX64_RE.match(claimed_commit)) and hmac.compare_digest(claimed_commit, expected_commit)
    cap_and_commit_ok = balances_within_cap and commit_ok
    if cap_and_commit_ok:
        cc_detail = f"Post-clearing balances stay within +/-{credit_limit} cap and batch digest {expected_commit[:12]}... matches."
    elif not balances_within_cap:
        cc_detail = f"Blocked: {breached_account or 'account'} breached the +/-{credit_limit}-unit cooperative credit exposure cap."
    else:
        cc_detail = "Blocked: clearing batch commitment digest does not match entries."
    c4 = InvariantCheck(
        check_id="L4_CLEARING_CAP_AND_COMMIT",
        label="Bounded credit cap and batch commitment",
        passed=cap_and_commit_ok,
        detail=cc_detail,
    )

    checks = (c1, c2, c3, c4)
    failed = tuple(c.check_id for c in checks if not c.passed)
    summary = (
        "All four cooperative-clearing invariants hold: one-human-root nullifiers prevent bot double-counting, credits clear to exact zero, and household privacy stays intact."
        if not failed
        else "Settlement rejected: the clearinghouse blocked Sybil replay, unbacked credit minting, personal-data leakage, or credit-cap overrun before ledger commit."
    )
    return VerificationReport(
        layer_id="cooperative_clearing",
        layer_name="Layer 4 · Selective-Disclosure Cooperative Receipt",
        passed=(len(failed) == 0),
        failed_check_ids=failed,
        protection_summary=summary,
        checks=checks,
    )


def verify_envelope(
    envelope: dict[str, Any],
    signing_key: str = DEMO_SIGNING_KEY,
) -> VerificationReport:
    """Dispatch verification by `envelope_type`."""
    etype = str(envelope.get("envelope_type") or "").strip()
    if etype == "capability_lease":
        return verify_capability_lease(envelope, signing_key=signing_key)
    if etype == "provenance_receipt":
        return verify_provenance_receipt(envelope)
    if etype == "actuator_interlock":
        return verify_actuator_interlock(envelope)
    if etype == "cooperative_clearing":
        return verify_cooperative_clearing(envelope)
    raise ValueError(f"Unsupported envelope_type: {etype!r}")


# ---------------------------------------------------------------------------
# Reference Valid Envelopes & Preset Adversarial Fault Mutations
# ---------------------------------------------------------------------------

def build_valid_lease_envelope(signing_key: str = DEMO_SIGNING_KEY) -> dict[str, Any]:
    """Build a valid Layer 1 Scoped Capability Lease envelope."""
    env: dict[str, Any] = {
        "protocol": PROTOCOL_VERSION,
        "envelope_type": "capability_lease",
        "lease_id": "lease-2026-11-clinic-0304",
        "principal_id": "principal:ottawa-dental-coop",
        "delegate_agent_id": "agent:supply-helper-04",
        "allowed_tools": ["calendar.read", "supplier.quote"],
        "ceiling_units": 250,
        "issued_at_epoch": 1794556800,
        "expires_at_epoch": 1794571200,
        "evaluated_at_epoch": 1794560400,
        "invocation": {
            "requested_tool": "supplier.quote",
            "requested_units": 120,
            "control_origin": "trusted_principal_intent",
            "untrusted_data_sources": ["vendor_invoice_pdf_884"],
            "tainted_control_tokens": [],
        },
    }
    env["delegation_mac"] = hmac_sha256_hex(signing_key, _lease_grant_payload(env))
    return env


def build_valid_provenance_envelope() -> dict[str, Any]:
    """Build a valid Layer 2 Tamper-Evident Provenance Receipt envelope."""
    parent_receipt = {
        "receipt_id": "rcpt-2026-11-quote-0081",
        "lease_id": "lease-2026-11-clinic-0304",
        "step_index": 1,
        "summary": "Read clinic stockroom reorder list",
    }
    parent_sha = sha256_hex(parent_receipt)
    input_payload = {
        "catalog_revision": "2026-11-coop",
        "item": "sterile_nitrile_gloves_box",
        "quantity": 40,
    }
    output_payload = {
        "delivery_days": 3,
        "quoted_units": 120,
        "selected_supplier": "eastern-ontario-med-supply",
    }
    in_sha = sha256_hex(input_payload)
    out_sha = sha256_hex(output_payload)
    seed = "spot-seed-2026-11-82"
    proof_sha = sha256_hex(_replay_commitment_payload(seed, in_sha, output_payload))
    return {
        "protocol": PROTOCOL_VERSION,
        "envelope_type": "provenance_receipt",
        "receipt_id": "rcpt-2026-11-quote-0082",
        "lease_id": "lease-2026-11-clinic-0304",
        "step_index": 2,
        "expected_parent_receipt_sha256": parent_sha,
        "parent_receipt_sha256": parent_sha,
        "input_payload": input_payload,
        "claimed_input_sha256": in_sha,
        "output_payload": output_payload,
        "claimed_output_sha256": out_sha,
        "replay_spot_check": {
            "seed": seed,
            "deterministic_replay_output_sha256": out_sha,
            "replay_proof_sha256": proof_sha,
            "log_sequence_contiguous": True,
            "omitted_step_count": 0,
        },
    }


def build_valid_interlock_envelope() -> dict[str, Any]:
    """Build a valid Layer 3 Physical Dead-Man Actuator Interlock envelope."""
    return {
        "protocol": PROTOCOL_VERSION,
        "envelope_type": "actuator_interlock",
        "actuator_id": "actuator:warehouse-lifter-bay-02",
        "optical_isolation_present": True,
        "heartbeat_gap_ms": 18,
        "max_heartbeat_gap_ms": MAX_HEARTBEAT_GAP_MS,
        "dual_channel_sensors": {
            "channel_a_load_kg": 41.2,
            "channel_b_load_kg": 41.5,
            "max_divergence_kg": 1.5,
            "hardware_plausibility_ok": True,
        },
        "manual_estop_latched": False,
        "relay_tripped_latch": False,
        "software_reenergize_attempt": False,
    }


def build_valid_clearing_envelope() -> dict[str, Any]:
    """Build a valid Layer 4 Selective-Disclosure Cooperative Task Receipt envelope."""
    epoch_id = "2026-W46"
    blinded_root = "commit:human-root-7f3a91c8b204"
    nullifier = sha256_hex(f"nullifier|{epoch_id}|{blinded_root}")
    prior_other = sha256_hex(f"nullifier|{epoch_id}|commit:human-root-19b044e2a110")
    entries = [
        {
            "account_commitment": "commit:clinic-member-04",
            "delta_credits": -120,
            "post_balance_credits": -180,
        },
        {
            "account_commitment": "commit:med-supply-coop-11",
            "delta_credits": 95,
            "post_balance_credits": 210,
        },
        {
            "account_commitment": "commit:courier-coop-07",
            "delta_credits": 25,
            "post_balance_credits": 65,
        },
    ]
    commit_sha = sha256_hex(_clearing_commitment_payload(epoch_id, nullifier, entries))
    return {
        "protocol": PROTOCOL_VERSION,
        "envelope_type": "cooperative_clearing",
        "clearing_id": "clr-2026-w46-0912",
        "epoch_id": epoch_id,
        "blinded_root_commitment": blinded_root,
        "human_root_proof_valid": True,
        "epoch_nullifier": nullifier,
        "seen_epoch_nullifiers": [prior_other],
        "mutual_credit_limit": 500,
        "entries": entries,
        "clearing_commitment_sha256": commit_sha,
    }


def apply_adversarial_faults(
    base_envelope: dict[str, Any],
    fault_ids: list[str] | tuple[str, ...],
) -> dict[str, Any]:
    """Return a deep-copied envelope with selected adversarial fault mutations applied."""
    env = copy.deepcopy(base_envelope)
    faults = set(fault_ids)
    etype = env.get("envelope_type")

    if etype == "capability_lease":
        if "inject_invoice_command" in faults:
            env["invocation"]["control_origin"] = "untrusted_external_data"
            env["invocation"]["tainted_control_tokens"] = [
                "vendor_invoice_pdf_884:hidden_footer_prompt"
            ]
        if "escalate_tool_scope" in faults:
            env["invocation"]["requested_tool"] = "treasury.transfer"
            env["invocation"]["requested_units"] = 900
        if "use_expired_lease" in faults:
            env["evaluated_at_epoch"] = env["expires_at_epoch"] + 2700
        if "forge_lease_ceiling" in faults:
            env["ceiling_units"] = 5000

    elif etype == "provenance_receipt":
        if "tamper_input_payload" in faults:
            env["input_payload"]["quantity"] = 400
        if "tamper_output_payload" in faults:
            env["output_payload"]["quoted_units"] = 45
        if "tamper_parent_digest" in faults:
            env["parent_receipt_sha256"] = "00" * 32
            env["replay_spot_check"]["log_sequence_contiguous"] = False
            env["replay_spot_check"]["omitted_step_count"] = 1
        if "fail_spot_replay" in faults:
            env["replay_spot_check"]["deterministic_replay_output_sha256"] = sha256_hex(
                {"delivery_days": 3, "quoted_units": 245, "selected_supplier": "shadow-broker"}
            )

    elif etype == "actuator_interlock":
        if "drop_relay_heartbeat" in faults:
            env["heartbeat_gap_ms"] = 84
        if "spoof_single_sensor" in faults:
            env["dual_channel_sensors"]["channel_b_load_kg"] = 9.4
        if "press_manual_estop" in faults:
            env["manual_estop_latched"] = True
        if "software_reenergize_relay" in faults:
            env["relay_tripped_latch"] = True
            env["software_reenergize_attempt"] = True

    elif etype == "cooperative_clearing":
        recompute_commit = True
        if "replay_sybil_nullifier" in faults:
            env["seen_epoch_nullifiers"].append(env["epoch_nullifier"])
        if "break_zero_sum_balance" in faults:
            env["entries"][1]["delta_credits"] = 120
        if "leak_household_pii" in faults:
            env["entries"][0]["street_address"] = "412 Bank Street"
            env["entries"][0]["email"] = "patient.billing@example.org"
        if "breach_credit_cap_and_commit" in faults:
            env["entries"][0]["post_balance_credits"] = -740
            recompute_commit = False
        if recompute_commit and faults:
            env["clearing_commitment_sha256"] = sha256_hex(
                _clearing_commitment_payload(
                    env["epoch_id"], env["epoch_nullifier"], env["entries"]
                )
            )

    return env


def build_browser_test_vectors() -> dict[str, Any]:
    """Export canonical test vectors and fault definitions for `/labs/protocol-inspector/`."""
    return {
        "protocol_version": PROTOCOL_VERSION,
        "demo_signing_key": DEMO_SIGNING_KEY,
        "max_lease_duration_sec": MAX_LEASE_DURATION_SEC,
        "max_heartbeat_gap_ms": MAX_HEARTBEAT_GAP_MS,
        "layers": [
            {
                "id": "capability_lease",
                "short_label": "1. Capability Lease",
                "eyebrow": "Layer 1 · Authority Scope",
                "title": "Scoped capability lease",
                "everyday_summary": "Like a hotel pass stamped only for Room 304 until noon, each assistant gets a signed, expiring tool lease.",
                "envelope": build_valid_lease_envelope(),
                "faults": [
                    {
                        "id": "inject_invoice_command",
                        "label": "Inject hidden command inside vendor invoice",
                        "hint": "Simulates untrusted text inside an external PDF trying to steer tool execution.",
                    },
                    {
                        "id": "escalate_tool_scope",
                        "label": "Escalate beyond leased tool scope",
                        "hint": "Requests treasury.transfer (900 units) on a quote-only 250-unit pass.",
                    },
                    {
                        "id": "use_expired_lease",
                        "label": "Use expired lease past cutoff",
                        "hint": "Replays the keycard 45 minutes after its noon expiration timestamp.",
                    },
                    {
                        "id": "forge_lease_ceiling",
                        "label": "Raise unit ceiling without owner signature",
                        "hint": "Edits ceiling_units from 250 to 5000 without the clinic's signing key.",
                    },
                ],
            },
            {
                "id": "provenance_receipt",
                "short_label": "2. Provenance Receipt",
                "eyebrow": "Layer 2 · Audit Trail",
                "title": "Tamper-evident provenance receipt",
                "everyday_summary": "Like an itemised checkout folio chained to every prior slip, each action seals its inputs, outputs, parent link, and a seeded spot-check replay digest.",
                "envelope": build_valid_provenance_envelope(),
                "faults": [
                    {
                        "id": "tamper_parent_digest",
                        "label": "Tamper with parent receipt digest",
                        "hint": "Breaks the hash link to step 1 and drops an intermediate log entry.",
                    },
                    {
                        "id": "tamper_input_payload",
                        "label": "Alter recorded order quantity after the fact",
                        "hint": "Changes input quantity from 40 to 400 without matching the sealed input hash.",
                    },
                    {
                        "id": "tamper_output_payload",
                        "label": "Doctor quoted unit price in receipt output",
                        "hint": "Edits quoted_units after execution, breaking the output SHA-256 digest.",
                    },
                    {
                        "id": "fail_spot_replay",
                        "label": "Submit unfaithful summary that fails replay",
                        "hint": "Simulates a step whose seeded deterministic replay disagrees with the claimed output.",
                    },
                ],
            },
            {
                "id": "actuator_interlock",
                "short_label": "3. Physical Interlock",
                "eyebrow": "Layer 3 · Hardware Safety",
                "title": "Physical dead-man actuator interlock",
                "everyday_summary": "Like the brass deadbolt chain inside a hotel door, an optically isolated hardware relay cuts motor power if pulses lag past 50 ms or a worker hits the red stop button.",
                "envelope": build_valid_interlock_envelope(),
                "faults": [
                    {
                        "id": "drop_relay_heartbeat",
                        "label": "Drop physical relay heartbeat past 50 ms",
                        "hint": "Stalls control pulses to 84 ms so the hardware dead-man switch drops power.",
                    },
                    {
                        "id": "spoof_single_sensor",
                        "label": "Spoof single-channel load sensor reading",
                        "hint": "Drives channel B down to 9.4 kg while channel A reads 41.2 kg.",
                    },
                    {
                        "id": "press_manual_estop",
                        "label": "Press manual mushroom E-stop at bay post",
                        "hint": "Opens the hardwired copper stop loop on Warehouse Bay 02.",
                    },
                    {
                        "id": "software_reenergize_relay",
                        "label": "Send network packet to re-energize tripped relay",
                        "hint": "Attempts to close a tripped physical relay remotely over software.",
                    },
                ],
            },
            {
                "id": "cooperative_clearing",
                "short_label": "4. Cooperative Clearing",
                "eyebrow": "Layer 4 · Shared Settlement",
                "title": "Selective-disclosure cooperative task receipt",
                "everyday_summary": "Clears mutual credit across local cooperatives to an exact zero sum while blocking bot farms from double-counting and keeping household identities off the ledger.",
                "envelope": build_valid_clearing_envelope(),
                "faults": [
                    {
                        "id": "replay_sybil_nullifier",
                        "label": "Replay duplicate Sybil nullifier",
                        "hint": "Spawns a second bot under the same human root to double-claim epoch W46.",
                    },
                    {
                        "id": "break_zero_sum_balance",
                        "label": "Break zero-sum credit balance",
                        "hint": "Inflates supplier credit from +95 to +120 so ledger deltas sum to +25.",
                    },
                    {
                        "id": "leak_household_pii",
                        "label": "Insert raw street address and email into ledger",
                        "hint": "Violates selective disclosure by writing personal contact details to the batch.",
                    },
                    {
                        "id": "breach_credit_cap_and_commit",
                        "label": "Exceed +/-500 mutual credit cap without commitment",
                        "hint": "Pushes post-clearing balance to -740 units and breaks the batch digest.",
                    },
                ],
            },
        ],
    }
