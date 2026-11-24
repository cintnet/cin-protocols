"""Agent Prove-Transform-Verify (PTV) Hardware Attestation Protocol Validator.

Grounded in:
- IETF Internet-Draft draft-anandakrishnan-rats-ptv-agent-identity (September 2026)
- IETF Remote ATtestation procedureS (RATS) Architecture (RFC 9334)
- IETF Entity Attestation Token (EAT) (RFC 9711)
- CIN Specification 03 and Floor Rights F1, F2, F17, F19

Standard library only, fail-closed validation.
"""

from __future__ import annotations

import datetime
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set


class PTVAttestationError(ValueError):
    """Raised when a PTV attestation record violates schema, invariants, or crypto bounds."""


ALLOWED_SCHEMA_VERSIONS: Set[str] = {"v0.1", "0.1.0"}
ALLOWED_ENCLAVE_TYPES: Set[str] = {
    "tpm2",
    "sev-snp",
    "nitro-enclaves",
    "apple-secure-enclave",
    "intel-tdx",
    "local-ocap-enclave",
}
ALLOWED_ISOLATION_TIERS: Set[str] = {
    "hardware-isolated-ocap",
    "process-isolated-seccomp",
    "microvm-firecracker",
}
ALLOWED_PTV_PHASES: Set[str] = {"PROVE", "TRANSFORM", "VERIFY"}
ALLOWED_SECURITY_LEVELS: Set[str] = {
    "hardware-enforced",
    "isolated-restricted",
    "software-only",
}

HEX64_PATTERN = re.compile(r"^[a-f0-9]{64}$")
HEX_SIG_PATTERN = re.compile(r"^[a-f0-9]{64,128}$")
URN_PATTERN = re.compile(r"^urn:cin:ptv-attestation:[a-f0-9]{16,64}$")
DID_AGENT_PATTERN = re.compile(r"^did:cin:agent:[a-zA-Z0-9._:-]+$")
NONCE_PATTERN = re.compile(r"^[a-zA-Z0-9._-]{16,128}$")
UEID_PATTERN = re.compile(r"^[a-f0-9]{16,64}$")


def _parse_iso_utc(ts: str, field_name: str) -> datetime.datetime:
    if not isinstance(ts, str) or not ts.strip():
        raise PTVAttestationError(f"{field_name} must be a non-empty ISO 8601 timestamp string")
    clean = ts.strip().replace("Z", "+00:00")
    try:
        dt = datetime.datetime.fromisoformat(clean)
    except ValueError as e:
        raise PTVAttestationError(f"Invalid ISO 8601 timestamp for {field_name}: '{ts}'") from e
    if dt.tzinfo is None:
        raise PTVAttestationError(f"{field_name} must include explicit timezone offset (e.g. 'Z')")
    return dt


def validate_ptv_attestation_dict(data: Any) -> Dict[str, Any]:
    """Validate a raw dict against the PTV attestation schema fail-closed."""
    if not isinstance(data, dict):
        raise PTVAttestationError(f"PTV attestation root must be a dict, got {type(data).__name__}")

    allowed_root_keys = {
        "schema_version",
        "attestation_id",
        "agent_id",
        "hardware_anchor",
        "configuration_binding",
        "ptv_lifecycle",
        "issued_at",
        "expires_at",
        "signature",
    }
    unknown_keys = set(data.keys()) - allowed_root_keys
    if unknown_keys:
        raise PTVAttestationError(f"Unknown root properties forbidden: {sorted(unknown_keys)}")

    missing_keys = allowed_root_keys - set(data.keys())
    if missing_keys:
        raise PTVAttestationError(f"Missing mandatory root properties: {sorted(missing_keys)}")

    # 1. Schema version
    ver = data["schema_version"]
    if ver not in ALLOWED_SCHEMA_VERSIONS:
        raise PTVAttestationError(f"Unsupported schema_version '{ver}'. Allowed: {sorted(ALLOWED_SCHEMA_VERSIONS)}")

    # 2. Identifiers
    att_id = data["attestation_id"]
    if not isinstance(att_id, str) or not URN_PATTERN.match(att_id):
        raise PTVAttestationError(f"Invalid attestation_id URN format: '{att_id}'")

    agent_id = data["agent_id"]
    if not isinstance(agent_id, str) or not DID_AGENT_PATTERN.match(agent_id):
        raise PTVAttestationError(f"Invalid agent_id DID format: '{agent_id}'")

    # 3. Hardware anchor
    ha = data["hardware_anchor"]
    if not isinstance(ha, dict):
        raise PTVAttestationError("hardware_anchor must be a dict")
    allowed_ha_keys = {"enclave_type", "attestation_key_fingerprint", "hardware_model"}
    if set(ha.keys()) != allowed_ha_keys:
        raise PTVAttestationError(f"hardware_anchor keys must strictly match {sorted(allowed_ha_keys)}")
    
    enclave = ha["enclave_type"]
    if enclave not in ALLOWED_ENCLAVE_TYPES:
        raise PTVAttestationError(f"Unknown enclave_type '{enclave}'. Allowed: {sorted(ALLOWED_ENCLAVE_TYPES)}")
    
    ak_fp = ha["attestation_key_fingerprint"]
    if not isinstance(ak_fp, str) or not HEX64_PATTERN.match(ak_fp):
        raise PTVAttestationError("attestation_key_fingerprint must be a 64-character lowercase hex string")
    
    hw_model = ha["hardware_model"]
    if not isinstance(hw_model, str) or not (2 <= len(hw_model.strip()) <= 128):
        raise PTVAttestationError("hardware_model must be a string between 2 and 128 characters")

    # 4. Configuration binding
    cb = data["configuration_binding"]
    if not isinstance(cb, dict):
        raise PTVAttestationError("configuration_binding must be a dict")
    allowed_cb_keys = {"model_id", "configuration_digest", "inference_runtime", "sandbox_isolation_tier"}
    if set(cb.keys()) != allowed_cb_keys:
        raise PTVAttestationError(f"configuration_binding keys must strictly match {sorted(allowed_cb_keys)}")
    
    model_id = cb["model_id"]
    if not isinstance(model_id, str) or not (2 <= len(model_id.strip()) <= 128):
        raise PTVAttestationError("model_id must be a string between 2 and 128 characters")
    
    cfg_dig = cb["configuration_digest"]
    if not isinstance(cfg_dig, str) or not HEX64_PATTERN.match(cfg_dig):
        raise PTVAttestationError("configuration_digest must be a 64-character lowercase hex string")
    
    runtime = cb["inference_runtime"]
    if not isinstance(runtime, str) or not (2 <= len(runtime.strip()) <= 128):
        raise PTVAttestationError("inference_runtime must be a string between 2 and 128 characters")
    
    tier = cb["sandbox_isolation_tier"]
    if tier not in ALLOWED_ISOLATION_TIERS:
        raise PTVAttestationError(f"Invalid sandbox_isolation_tier '{tier}'. Allowed: {sorted(ALLOWED_ISOLATION_TIERS)}")

    # 5. PTV lifecycle
    ptv = data["ptv_lifecycle"]
    if not isinstance(ptv, dict):
        raise PTVAttestationError("ptv_lifecycle must be a dict")
    allowed_ptv_keys = {"phase", "challenge_nonce", "zero_knowledge_proof_digest", "transformed_eat_claims"}
    if set(ptv.keys()) != allowed_ptv_keys:
        raise PTVAttestationError(f"ptv_lifecycle keys must strictly match {sorted(allowed_ptv_keys)}")
    
    phase = ptv["phase"]
    if phase not in ALLOWED_PTV_PHASES:
        raise PTVAttestationError(f"Invalid phase '{phase}'. Allowed: {sorted(ALLOWED_PTV_PHASES)}")
    
    nonce = ptv["challenge_nonce"]
    if not isinstance(nonce, str) or not NONCE_PATTERN.match(nonce):
        raise PTVAttestationError(f"challenge_nonce must match pattern [a-zA-Z0-9._-]{{16,128}}, got '{nonce}'")
    
    zk_dig = ptv["zero_knowledge_proof_digest"]
    if not isinstance(zk_dig, str) or not HEX64_PATTERN.match(zk_dig):
        raise PTVAttestationError("zero_knowledge_proof_digest must be a 64-character lowercase hex string")
    
    eat = ptv["transformed_eat_claims"]
    if not isinstance(eat, dict):
        raise PTVAttestationError("transformed_eat_claims must be a dict")
    allowed_eat_keys = {"ueid", "profile", "security_level"}
    if set(eat.keys()) != allowed_eat_keys:
        raise PTVAttestationError(f"transformed_eat_claims keys must strictly match {sorted(allowed_eat_keys)}")
    
    ueid = eat["ueid"]
    if not isinstance(ueid, str) or not UEID_PATTERN.match(ueid):
        raise PTVAttestationError("ueid must be a 16-64 character lowercase hex string")
    
    profile = eat["profile"]
    if not isinstance(profile, str) or not profile.startswith("http"):
        raise PTVAttestationError("profile must be a valid URI string")
    
    sec_lvl = eat["security_level"]
    if sec_lvl not in ALLOWED_SECURITY_LEVELS:
        raise PTVAttestationError(f"Invalid security_level '{sec_lvl}'. Allowed: {sorted(ALLOWED_SECURITY_LEVELS)}")

    # 6. Timestamps
    dt_issued = _parse_iso_utc(data["issued_at"], "issued_at")
    dt_expires = _parse_iso_utc(data["expires_at"], "expires_at")
    if dt_expires <= dt_issued:
        raise PTVAttestationError(
            f"expires_at ({data['expires_at']}) must be strictly after issued_at ({data['issued_at']})"
        )

    # 7. Signature
    sig = data["signature"]
    if not isinstance(sig, str) or not HEX_SIG_PATTERN.match(sig):
        raise PTVAttestationError("signature must be a 64 to 128 character lowercase hex string")

    return data


@dataclass(frozen=True)
class PTVAttestationRecord:
    attestation_id: str
    agent_id: str
    enclave_type: str
    attestation_key_fingerprint: str
    hardware_model: str
    model_id: str
    configuration_digest: str
    inference_runtime: str
    sandbox_isolation_tier: str
    phase: str
    challenge_nonce: str
    zero_knowledge_proof_digest: str
    ueid: str
    security_level: str
    issued_at: datetime.datetime
    expires_at: datetime.datetime
    signature: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PTVAttestationRecord:
        validated = validate_ptv_attestation_dict(data)
        return cls(
            attestation_id=validated["attestation_id"],
            agent_id=validated["agent_id"],
            enclave_type=validated["hardware_anchor"]["enclave_type"],
            attestation_key_fingerprint=validated["hardware_anchor"]["attestation_key_fingerprint"],
            hardware_model=validated["hardware_anchor"]["hardware_model"],
            model_id=validated["configuration_binding"]["model_id"],
            configuration_digest=validated["configuration_binding"]["configuration_digest"],
            inference_runtime=validated["configuration_binding"]["inference_runtime"],
            sandbox_isolation_tier=validated["configuration_binding"]["sandbox_isolation_tier"],
            phase=validated["ptv_lifecycle"]["phase"],
            challenge_nonce=validated["ptv_lifecycle"]["challenge_nonce"],
            zero_knowledge_proof_digest=validated["ptv_lifecycle"]["zero_knowledge_proof_digest"],
            ueid=validated["ptv_lifecycle"]["transformed_eat_claims"]["ueid"],
            security_level=validated["ptv_lifecycle"]["transformed_eat_claims"]["security_level"],
            issued_at=_parse_iso_utc(validated["issued_at"], "issued_at"),
            expires_at=_parse_iso_utc(validated["expires_at"], "expires_at"),
            signature=validated["signature"],
        )


def verify_ptv_attestation_exercise(
    record_dict: Dict[str, Any],
    expected_nonce: str,
    current_time_iso: str,
    trusted_enclave_types: Optional[Sequence[str]] = None,
    trusted_key_fingerprints: Optional[Sequence[str]] = None,
) -> bool:
    """Verify an agent PTV attestation at exercise time fail-closed."""
    record = PTVAttestationRecord.from_dict(record_dict)

    # 1. Nonce binding (replay protection)
    if not isinstance(expected_nonce, str) or not expected_nonce.strip():
        raise PTVAttestationError("expected_nonce must be a non-empty string")
    if record.challenge_nonce != expected_nonce:
        raise PTVAttestationError(
            f"Challenge nonce mismatch: expected '{expected_nonce}', got '{record.challenge_nonce}'"
        )

    # 2. Temporal validity
    now_dt = _parse_iso_utc(current_time_iso, "current_time_iso")
    if now_dt < record.issued_at:
        raise PTVAttestationError(
            f"Attestation not yet valid: issued_at {record.issued_at.isoformat()} is in the future relative to {now_dt.isoformat()}"
        )
    if now_dt >= record.expires_at:
        raise PTVAttestationError(
            f"Attestation has expired: expires_at {record.expires_at.isoformat()} <= current_time {now_dt.isoformat()}"
        )

    # 3. Phase check
    if record.phase != "VERIFY":
        raise PTVAttestationError(f"Exercise-time verification requires phase 'VERIFY', got '{record.phase}'")

    # 4. Enclave trust policy
    if trusted_enclave_types is not None:
        if record.enclave_type not in set(trusted_enclave_types):
            raise PTVAttestationError(
                f"Enclave type '{record.enclave_type}' not in trusted set {list(trusted_enclave_types)}"
            )

    # 5. Key fingerprint trust policy
    if trusted_key_fingerprints is not None:
        if record.attestation_key_fingerprint not in set(trusted_key_fingerprints):
            raise PTVAttestationError(
                f"Attestation key fingerprint '{record.attestation_key_fingerprint}' is untrusted"
            )

    return True
