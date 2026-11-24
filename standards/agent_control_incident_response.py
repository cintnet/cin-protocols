"""Agent Control Incident Response Specification & Conformance Engine (`research/standards`).

Top-of-file note:
- What it is: Reference validator and data model for logging, containing, verifying,
  and reporting autonomous agent control incidents, implementing the joint NIST CAISSI,
  NSA SISC, and CISA guidance (Document PP-26-4396, October 16, 2026; Signal S-20261030-2490)
  and NIST SP 800-61r3.
- What it is for: Mission `standards` - providing an auditable, fail-closed specification
  and deterministic conformance test harness for agent control incidents and capability revocation.
- What is uncertain / provisional: Federal reporting thresholds for near-misses, cross-organization
  anonymized sharing protocols, and automated recovery verification benchmarks.
- Scope boundary: Deterministic schema and state machine validation; no live external network calls
  or unverified telemetry ingestion.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
import hashlib
import json
import math
import re
from typing import Any, Literal

STAGE_ORDER = ("prepare", "detect", "respond", "recover", "report")
LifecycleStage = Literal["prepare", "detect", "respond", "recover", "report"]

CONTROL_INCIDENT_TYPES = (
    "uninstructed_tool_execution",
    "unauthorized_network_egress",
    "sandbox_boundary_violation",
    "credential_exfiltration_attempt",
    "monitor_subversion_attempt",
    "unauthorized_delegation_or_spawn",
    "policy_override_attempt",
)
ControlIncidentType = Literal[
    "uninstructed_tool_execution",
    "unauthorized_network_egress",
    "sandbox_boundary_violation",
    "credential_exfiltration_attempt",
    "monitor_subversion_attempt",
    "unauthorized_delegation_or_spawn",
    "policy_override_attempt",
]

ISO8601_REGEX = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
HEX64_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")
INCIDENT_ID_REGEX = re.compile(r"^inc-[a-zA-Z0-9_-]{8,64}$")


class IncidentValidationError(ValueError):
    """Raised when an incident record violates specification constraints."""
    pass


def validate_iso8601(name: str, value: Any) -> str:
    """Validate ISO-8601 date-time string, rejecting booleans or invalid formats."""
    if not isinstance(value, str) or not ISO8601_REGEX.match(value):
        raise IncidentValidationError(f"{name} must be a valid ISO-8601 date-time string, got {value!r}")
    return value


def validate_hex64(name: str, value: Any, allow_none: bool = False) -> str | None:
    """Validate 64-character SHA-256 hex string."""
    if allow_none and value is None:
        return None
    if not isinstance(value, str) or not HEX64_REGEX.match(value):
        raise IncidentValidationError(f"{name} must be a 64-character hex string, got {value!r}")
    return value.lower()


def validate_finite_score(name: str, value: Any) -> float:
    """Validate score is a finite float in [0.0, 1.0], strictly rejecting booleans."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise IncidentValidationError(f"{name} must be a numeric score, got {type(value).__name__}")
    val = float(value)
    if not math.isfinite(val) or val < 0.0 or val > 1.0:
        raise IncidentValidationError(f"{name} must be a finite float between 0.0 and 1.0, got {value!r}")
    return val


@dataclass(frozen=True)
class PreparationBaseline:
    allowed_tools: tuple[str, ...]
    network_policy: Literal["default_deny", "loopback_only", "restricted_allowlist"]
    credential_scope: Literal["ephemeral_short_lived", "isolated_session", "read_only"]
    baseline_state_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.allowed_tools, (list, tuple)):
            raise IncidentValidationError("allowed_tools must be a sequence of strings")
        for tool in self.allowed_tools:
            if not isinstance(tool, str) or not tool.strip():
                raise IncidentValidationError(f"Invalid tool entry: {tool!r}")
        if self.network_policy not in ("default_deny", "loopback_only", "restricted_allowlist"):
            raise IncidentValidationError(f"Invalid network_policy: {self.network_policy!r}")
        if self.credential_scope not in ("ephemeral_short_lived", "isolated_session", "read_only"):
            raise IncidentValidationError(f"Invalid credential_scope: {self.credential_scope!r}")
        validate_hex64("baseline_state_digest", self.baseline_state_digest)


@dataclass(frozen=True)
class DetectionTelemetry:
    detector_name: str
    anomaly_score: float
    uninstructed_action_summary: str
    execution_trajectory_digest: str
    timestamp_anomaly: str

    def __post_init__(self) -> None:
        if not isinstance(self.detector_name, str) or not self.detector_name.strip():
            raise IncidentValidationError("detector_name must be a non-empty string")
        validate_finite_score("anomaly_score", self.anomaly_score)
        if not isinstance(self.uninstructed_action_summary, str) or len(self.uninstructed_action_summary) < 10:
            raise IncidentValidationError("uninstructed_action_summary must be at least 10 characters")
        validate_hex64("execution_trajectory_digest", self.execution_trajectory_digest)
        validate_iso8601("timestamp_anomaly", self.timestamp_anomaly)


@dataclass(frozen=True)
class ResponseContainment:
    containment_action: Literal["immediate_kill", "network_sever", "credential_revocation", "sandbox_freeze", "none"]
    capability_tokens_revoked: bool
    execution_halted: bool
    timestamp_contained: str
    forensic_log_digest: str

    def __post_init__(self) -> None:
        if self.containment_action not in ("immediate_kill", "network_sever", "credential_revocation", "sandbox_freeze", "none"):
            raise IncidentValidationError(f"Invalid containment_action: {self.containment_action!r}")
        if not isinstance(self.capability_tokens_revoked, bool):
            raise IncidentValidationError("capability_tokens_revoked must be a boolean")
        if not isinstance(self.execution_halted, bool):
            raise IncidentValidationError("execution_halted must be a boolean")
        validate_iso8601("timestamp_contained", self.timestamp_contained)
        validate_hex64("forensic_log_digest", self.forensic_log_digest)


@dataclass(frozen=True)
class RecoveryVerification:
    containment_verified: bool
    rebuilt_from_trusted_baseline: bool
    rebuilt_state_digest: str | None
    verifier_identity: str

    def __post_init__(self) -> None:
        if not isinstance(self.containment_verified, bool):
            raise IncidentValidationError("containment_verified must be a boolean")
        if not isinstance(self.rebuilt_from_trusted_baseline, bool):
            raise IncidentValidationError("rebuilt_from_trusted_baseline must be a boolean")
        validate_hex64("rebuilt_state_digest", self.rebuilt_state_digest, allow_none=True)
        if not isinstance(self.verifier_identity, str) or not self.verifier_identity.strip():
            raise IncidentValidationError("verifier_identity must be a non-empty string")


@dataclass(frozen=True)
class ReportingStatus:
    internal_stakeholders_notified: bool
    affected_parties_coordinated: bool
    authority_notified: bool
    public_research_shared: bool
    authority_reference_id: str | None = None

    def __post_init__(self) -> None:
        for field_name in (
            "internal_stakeholders_notified",
            "affected_parties_coordinated",
            "authority_notified",
            "public_research_shared",
        ):
            if not isinstance(getattr(self, field_name), bool):
                raise IncidentValidationError(f"{field_name} must be a boolean")
        if self.authority_reference_id is not None:
            if not isinstance(self.authority_reference_id, str) or not self.authority_reference_id.strip():
                raise IncidentValidationError("authority_reference_id must be a non-empty string when provided")


@dataclass(frozen=True)
class AgentControlIncidentRecord:
    schema_version: str
    incident_id: str
    timestamp_detected: str
    agent_id: str
    model_id: str
    lifecycle_stage: LifecycleStage
    control_incident_type: ControlIncidentType
    preparation_baseline: PreparationBaseline
    detection_telemetry: DetectionTelemetry
    response_containment: ResponseContainment
    recovery_verification: RecoveryVerification
    reporting_status: ReportingStatus

    def __post_init__(self) -> None:
        if self.schema_version != "0.1.0":
            raise IncidentValidationError(f"Unsupported schema_version: {self.schema_version!r}")
        if not isinstance(self.incident_id, str) or not INCIDENT_ID_REGEX.match(self.incident_id):
            raise IncidentValidationError(f"Invalid incident_id format: {self.incident_id!r}")
        validate_iso8601("timestamp_detected", self.timestamp_detected)
        if not isinstance(self.agent_id, str) or not self.agent_id.strip():
            raise IncidentValidationError("agent_id must be a non-empty string")
        if not isinstance(self.model_id, str) or not self.model_id.strip():
            raise IncidentValidationError("model_id must be a non-empty string")
        if self.lifecycle_stage not in STAGE_ORDER:
            raise IncidentValidationError(f"Invalid lifecycle_stage: {self.lifecycle_stage!r}")
        if self.control_incident_type not in CONTROL_INCIDENT_TYPES:
            raise IncidentValidationError(f"Invalid control_incident_type: {self.control_incident_type!r}")

        # Fail-closed stage invariants:
        if self.lifecycle_stage in ("recover", "report"):
            if not self.response_containment.execution_halted:
                raise IncidentValidationError("Cannot reach recovery or reporting while execution_halted is False")
            if not self.recovery_verification.containment_verified:
                raise IncidentValidationError("Cannot reach recovery or reporting without verified containment")
            if not self.recovery_verification.rebuilt_from_trusted_baseline:
                raise IncidentValidationError("Cannot recover without rebuilding environment from trusted baseline")

    def compute_digest(self) -> str:
        """Compute deterministic SHA-256 digest of normalized canonical JSON representation."""
        data = asdict(self)
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_incident_dict(d: dict[str, Any]) -> AgentControlIncidentRecord:
    """Validate dictionary against schema, fail-closed on unknown fields and malformed types."""
    if not isinstance(d, dict):
        raise IncidentValidationError("Record must be a JSON object")

    allowed_top_keys = {
        "schema_version", "incident_id", "timestamp_detected", "agent_id", "model_id",
        "lifecycle_stage", "control_incident_type", "preparation_baseline",
        "detection_telemetry", "response_containment", "recovery_verification",
        "reporting_status"
    }
    unknown_top = set(d.keys()) - allowed_top_keys
    if unknown_top:
        raise IncidentValidationError(f"Unknown top-level fields: {sorted(unknown_top)}")

    missing_top = allowed_top_keys - set(d.keys())
    if missing_top:
        raise IncidentValidationError(f"Missing required fields: {sorted(missing_top)}")

    prep_d = d["preparation_baseline"]
    if not isinstance(prep_d, dict):
        raise IncidentValidationError("preparation_baseline must be an object")
    allowed_prep_keys = {
        "allowed_tools", "network_policy", "credential_scope", "baseline_state_digest"
    }
    unknown_prep = set(prep_d.keys()) - allowed_prep_keys
    if unknown_prep:
        raise IncidentValidationError(f"Unknown fields in preparation_baseline: {sorted(unknown_prep)}")
    prep = PreparationBaseline(
        allowed_tools=tuple(prep_d.get("allowed_tools", ())),
        network_policy=prep_d.get("network_policy"),
        credential_scope=prep_d.get("credential_scope"),
        baseline_state_digest=prep_d.get("baseline_state_digest", ""),
    )

    det_d = d["detection_telemetry"]
    if not isinstance(det_d, dict):
        raise IncidentValidationError("detection_telemetry must be an object")
    allowed_det_keys = {
        "detector_name", "anomaly_score", "uninstructed_action_summary",
        "execution_trajectory_digest", "timestamp_anomaly"
    }
    unknown_det = set(det_d.keys()) - allowed_det_keys
    if unknown_det:
        raise IncidentValidationError(f"Unknown fields in detection_telemetry: {sorted(unknown_det)}")
    det = DetectionTelemetry(
        detector_name=det_d.get("detector_name", ""),
        anomaly_score=det_d.get("anomaly_score", 0.0),
        uninstructed_action_summary=det_d.get("uninstructed_action_summary", ""),
        execution_trajectory_digest=det_d.get("execution_trajectory_digest", ""),
        timestamp_anomaly=det_d.get("timestamp_anomaly", ""),
    )

    resp_d = d["response_containment"]
    if not isinstance(resp_d, dict):
        raise IncidentValidationError("response_containment must be an object")
    allowed_resp_keys = {
        "containment_action", "capability_tokens_revoked", "execution_halted",
        "timestamp_contained", "forensic_log_digest"
    }
    unknown_resp = set(resp_d.keys()) - allowed_resp_keys
    if unknown_resp:
        raise IncidentValidationError(f"Unknown fields in response_containment: {sorted(unknown_resp)}")
    resp = ResponseContainment(
        containment_action=resp_d.get("containment_action"),
        capability_tokens_revoked=resp_d.get("capability_tokens_revoked"),
        execution_halted=resp_d.get("execution_halted"),
        timestamp_contained=resp_d.get("timestamp_contained", ""),
        forensic_log_digest=resp_d.get("forensic_log_digest", ""),
    )

    rec_d = d["recovery_verification"]
    if not isinstance(rec_d, dict):
        raise IncidentValidationError("recovery_verification must be an object")
    allowed_rec_keys = {
        "containment_verified", "rebuilt_from_trusted_baseline",
        "rebuilt_state_digest", "verifier_identity"
    }
    unknown_rec = set(rec_d.keys()) - allowed_rec_keys
    if unknown_rec:
        raise IncidentValidationError(f"Unknown fields in recovery_verification: {sorted(unknown_rec)}")
    rec = RecoveryVerification(
        containment_verified=rec_d.get("containment_verified"),
        rebuilt_from_trusted_baseline=rec_d.get("rebuilt_from_trusted_baseline"),
        rebuilt_state_digest=rec_d.get("rebuilt_state_digest"),
        verifier_identity=rec_d.get("verifier_identity", ""),
    )

    rep_d = d["reporting_status"]
    if not isinstance(rep_d, dict):
        raise IncidentValidationError("reporting_status must be an object")
    allowed_rep_keys = {
        "internal_stakeholders_notified", "affected_parties_coordinated",
        "authority_notified", "public_research_shared", "authority_reference_id"
    }
    unknown_rep = set(rep_d.keys()) - allowed_rep_keys
    if unknown_rep:
        raise IncidentValidationError(f"Unknown fields in reporting_status: {sorted(unknown_rep)}")
    rep = ReportingStatus(
        internal_stakeholders_notified=rep_d.get("internal_stakeholders_notified"),
        affected_parties_coordinated=rep_d.get("affected_parties_coordinated"),
        authority_notified=rep_d.get("authority_notified"),
        public_research_shared=rep_d.get("public_research_shared"),
        authority_reference_id=rep_d.get("authority_reference_id"),
    )

    return AgentControlIncidentRecord(
        schema_version=d["schema_version"],
        incident_id=d["incident_id"],
        timestamp_detected=d["timestamp_detected"],
        agent_id=d["agent_id"],
        model_id=d["model_id"],
        lifecycle_stage=d["lifecycle_stage"],
        control_incident_type=d["control_incident_type"],
        preparation_baseline=prep,
        detection_telemetry=det,
        response_containment=resp,
        recovery_verification=rec,
        reporting_status=rep,
    )
