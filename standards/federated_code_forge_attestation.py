"""Federated Code Forge Attestation and Rate-Limiting Gate.

Implements reference parser, canonical hash verification, fail-closed validation,
and sliding-window rate limiting for Proof-Carrying Code execution receipts
submitted to federated git code forges (Specification 03, Floor Rights F1, F17, F19).
"""

from __future__ import annotations

from dataclasses import dataclass, field
import datetime as dt
import hashlib
import hmac
import json
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple


# Regex patterns for strict fail-closed validation
HEX_40_RE = re.compile(r"^[a-f0-9]{40}$")
HEX_64_128_RE = re.compile(r"^[a-f0-9]{64,128}$")
NONCE_RE = re.compile(r"^[a-f0-9]{16,64}$")
ATTESTATION_ID_RE = re.compile(r"^urn:cin:forge-attestation:[a-f0-9]{16,64}$")
DID_RE = re.compile(r"^did:[a-z0-9]+:[a-zA-Z0-9._:-]+$")

VALID_ENCLAVE_TYPES = frozenset({"tpm2", "sev-snp", "nitro-enclaves", "local-ocap-sandbox"})
VALID_FRAMEWORKS = frozenset({"unittest", "pytest", "cargo-test", "go-test", "vitest"})
VALID_ISOLATION_LEVELS = frozenset({"hardware-enclave", "ocap-sandbox-egress-blocked", "container-isolated"})


def _parse_iso(s: str) -> dt.datetime:
    """Parse strict ISO-8601 UTC timestamp."""
    if not isinstance(s, str) or not s:
        raise ValueError("Timestamp must be a non-empty ISO-8601 string")
    # Require UTC indicator (Z or +00:00)
    if not (s.endswith("Z") or "+00:00" in s or "-00:00" in s):
        raise ValueError(f"Timestamp must specify UTC timezone: {s!r}")
    normalized = s.replace("Z", "+00:00")
    try:
        t = dt.datetime.fromisoformat(normalized)
    except Exception as e:
        raise ValueError(f"Malformed ISO-8601 timestamp {s!r}: {e}") from e
    if t.tzinfo is None:
        raise ValueError("Timestamp missing timezone information")
    return t


@dataclass(frozen=True)
class AttestorIdentity:
    attestor_did: str
    enclave_type: str
    public_key: str

    def __post_init__(self) -> None:
        if not DID_RE.match(self.attestor_did):
            raise ValueError(f"Invalid attestor_did: {self.attestor_did!r}")
        if self.enclave_type not in VALID_ENCLAVE_TYPES:
            raise ValueError(f"Invalid enclave_type: {self.enclave_type!r}")
        if not HEX_64_128_RE.match(self.public_key):
            raise ValueError(f"Invalid public_key hex: {self.public_key!r}")


@dataclass(frozen=True)
class TestSuiteRun:
    framework: str
    total_tests: int
    passed_tests: int
    failed_tests: int
    skipped_tests: int
    execution_time_ms: int
    isolation_level: str

    def __post_init__(self) -> None:
        if self.framework not in VALID_FRAMEWORKS:
            raise ValueError(f"Invalid framework: {self.framework!r}")
        if self.isolation_level not in VALID_ISOLATION_LEVELS:
            raise ValueError(f"Invalid isolation_level: {self.isolation_level!r}")
        for field_name, val in (
            ("total_tests", self.total_tests),
            ("passed_tests", self.passed_tests),
            ("failed_tests", self.failed_tests),
            ("skipped_tests", self.skipped_tests),
            ("execution_time_ms", self.execution_time_ms),
        ):
            if isinstance(val, bool) or not isinstance(val, int):
                raise ValueError(f"{field_name} must be integer, got {type(val).__name__}")
            if field_name == "total_tests" and val < 1:
                raise ValueError(f"total_tests must be >= 1, got {val}")
            elif val < 0:
                raise ValueError(f"{field_name} cannot be negative, got {val}")

        if self.passed_tests + self.failed_tests + self.skipped_tests != self.total_tests:
            raise ValueError(
                f"Test tally mismatch: passed({self.passed_tests}) + failed({self.failed_tests}) "
                f"+ skipped({self.skipped_tests}) != total({self.total_tests})"
            )


@dataclass(frozen=True)
class ResourceQuota:
    memory_mb: int
    cpu_cores: int
    network_egress_blocked: bool

    def __post_init__(self) -> None:
        for field_name, val in (("memory_mb", self.memory_mb), ("cpu_cores", self.cpu_cores)):
            if isinstance(val, bool) or not isinstance(val, int):
                raise ValueError(f"{field_name} must be integer, got {type(val).__name__}")
            if val < 1:
                raise ValueError(f"{field_name} must be >= 1, got {val}")
        if not isinstance(self.network_egress_blocked, bool):
            raise ValueError("network_egress_blocked must be boolean")


@dataclass(frozen=True)
class ForgeAttestation:
    schema_version: str
    attestation_id: str
    repo_uri: str
    commit_sha: str
    tree_hash: str
    attestor: AttestorIdentity
    test_suite_run: TestSuiteRun
    resource_quota: ResourceQuota
    issued_at: str
    expires_at: str
    nonce: str
    signature: str

    def __post_init__(self) -> None:
        if self.schema_version not in ("0.1.0", "v0.1"):
            raise ValueError(f"Unsupported schema_version: {self.schema_version!r}")
        if not ATTESTATION_ID_RE.match(self.attestation_id):
            raise ValueError(f"Invalid attestation_id: {self.attestation_id!r}")
        if not self.repo_uri or not (self.repo_uri.startswith("https://") or self.repo_uri.startswith("git://")):
            raise ValueError(f"Invalid repo_uri: {self.repo_uri!r}")
        if not HEX_40_RE.match(self.commit_sha):
            raise ValueError(f"Invalid commit_sha: {self.commit_sha!r}")
        if not HEX_40_RE.match(self.tree_hash):
            raise ValueError(f"Invalid tree_hash: {self.tree_hash!r}")
        if not NONCE_RE.match(self.nonce):
            raise ValueError(f"Invalid nonce: {self.nonce!r}")
        if not HEX_64_128_RE.match(self.signature):
            raise ValueError(f"Invalid signature hex: {self.signature!r}")

        t_iss = _parse_iso(self.issued_at)
        t_exp = _parse_iso(self.expires_at)
        if t_exp <= t_iss:
            raise ValueError(f"Attestation expires_at ({self.expires_at}) must be strictly after issued_at ({self.issued_at})")

    def canonical_bytes(self) -> bytes:
        """Deterministically canonicalize attestation payload for signing (excluding signature)."""
        doc = {
            "schema_version": self.schema_version,
            "attestation_id": self.attestation_id,
            "repo_uri": self.repo_uri,
            "commit_sha": self.commit_sha,
            "tree_hash": self.tree_hash,
            "attestor": {
                "attestor_did": self.attestor.attestor_did,
                "enclave_type": self.attestor.enclave_type,
                "public_key": self.attestor.public_key,
            },
            "test_suite_run": {
                "framework": self.test_suite_run.framework,
                "total_tests": self.test_suite_run.total_tests,
                "passed_tests": self.test_suite_run.passed_tests,
                "failed_tests": self.test_suite_run.failed_tests,
                "skipped_tests": self.test_suite_run.skipped_tests,
                "execution_time_ms": self.test_suite_run.execution_time_ms,
                "isolation_level": self.test_suite_run.isolation_level,
            },
            "resource_quota": {
                "memory_mb": self.resource_quota.memory_mb,
                "cpu_cores": self.resource_quota.cpu_cores,
                "network_egress_blocked": self.resource_quota.network_egress_blocked,
            },
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
        }
        return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def compute_hmac_signature(self, secret: str) -> str:
        """Compute HMAC-SHA256 hex signature over canonical bytes."""
        return hmac.new(secret.encode("utf-8"), self.canonical_bytes(), hashlib.sha256).hexdigest()

    def verify_signature(self, secret: str) -> bool:
        """Constant-time comparison against HMAC-SHA256 signature."""
        expected = self.compute_hmac_signature(secret)
        return hmac.compare_digest(self.signature, expected)


def parse_forge_attestation(d: Mapping[str, Any]) -> ForgeAttestation:
    """Parse raw dictionary into ForgeAttestation with fail-closed validation."""
    if not isinstance(d, dict):
        raise ValueError("Attestation payload must be a JSON object")

    allowed_keys = {
        "schema_version",
        "attestation_id",
        "repo_uri",
        "commit_sha",
        "tree_hash",
        "attestor",
        "test_suite_run",
        "resource_quota",
        "issued_at",
        "expires_at",
        "nonce",
        "signature",
    }
    extra_keys = set(d.keys()) - allowed_keys
    if extra_keys:
        raise ValueError(f"Undeclared properties in root attestation: {extra_keys}")

    missing_keys = allowed_keys - set(d.keys())
    if missing_keys:
        raise ValueError(f"Missing required properties in attestation: {missing_keys}")

    att = d["attestor"]
    if not isinstance(att, dict) or set(att.keys()) != {"attestor_did", "enclave_type", "public_key"}:
        raise ValueError("Invalid attestor identity block")
    attestor_id = AttestorIdentity(
        attestor_did=att["attestor_did"],
        enclave_type=att["enclave_type"],
        public_key=att["public_key"],
    )

    tsr = d["test_suite_run"]
    expected_tsr_keys = {
        "framework",
        "total_tests",
        "passed_tests",
        "failed_tests",
        "skipped_tests",
        "execution_time_ms",
        "isolation_level",
    }
    if not isinstance(tsr, dict) or set(tsr.keys()) != expected_tsr_keys:
        raise ValueError("Invalid test_suite_run block")
    test_suite = TestSuiteRun(
        framework=tsr["framework"],
        total_tests=tsr["total_tests"],
        passed_tests=tsr["passed_tests"],
        failed_tests=tsr["failed_tests"],
        skipped_tests=tsr["skipped_tests"],
        execution_time_ms=tsr["execution_time_ms"],
        isolation_level=tsr["isolation_level"],
    )

    rq = d["resource_quota"]
    if not isinstance(rq, dict) or set(rq.keys()) != {"memory_mb", "cpu_cores", "network_egress_blocked"}:
        raise ValueError("Invalid resource_quota block")
    resource_quota = ResourceQuota(
        memory_mb=rq["memory_mb"],
        cpu_cores=rq["cpu_cores"],
        network_egress_blocked=rq["network_egress_blocked"],
    )

    return ForgeAttestation(
        schema_version=d["schema_version"],
        attestation_id=d["attestation_id"],
        repo_uri=d["repo_uri"],
        commit_sha=d["commit_sha"],
        tree_hash=d["tree_hash"],
        attestor=attestor_id,
        test_suite_run=test_suite,
        resource_quota=resource_quota,
        issued_at=d["issued_at"],
        expires_at=d["expires_at"],
        nonce=d["nonce"],
        signature=d["signature"],
    )


@dataclass
class SlidingWindowAttestationRateLimiter:
    """Sliding-window rate limiter per contributor DID and repository."""

    window_seconds: int = 600       # 10 minute window
    max_requests_per_window: int = 10
    _history: Dict[Tuple[str, str], List[float]] = field(default_factory=dict)
    _seen_nonces: Dict[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.window_seconds, bool) or not isinstance(self.window_seconds, (int, float)) or self.window_seconds <= 0:
            raise ValueError(f"window_seconds must be positive, got {self.window_seconds!r}")
        if isinstance(self.max_requests_per_window, bool) or not isinstance(self.max_requests_per_window, int) or self.max_requests_per_window <= 0:
            raise ValueError(f"max_requests_per_window must be a positive integer, got {self.max_requests_per_window!r}")

    def check_and_record(self, attestor_did: str, repo_uri: str, nonce: str, current_time: float) -> Tuple[bool, str]:
        """Check rate limit and nonce replay. Returns (allowed, reason)."""
        # 1. Nonce replay check
        if nonce in self._seen_nonces:
            prev_time = self._seen_nonces[nonce]
            if current_time - prev_time < self.window_seconds:
                return False, f"Replay attack detected: nonce {nonce!r} was already consumed"

        # Prune expired nonces
        expired_nonces = [n for n, t in self._seen_nonces.items() if current_time - t >= self.window_seconds]
        for n in expired_nonces:
            del self._seen_nonces[n]

        # 2. Sliding window check
        key = (attestor_did, repo_uri)
        timestamps = self._history.setdefault(key, [])
        cutoff = current_time - self.window_seconds
        valid_timestamps = [t for t in timestamps if t > cutoff]
        self._history[key] = valid_timestamps

        if len(valid_timestamps) >= self.max_requests_per_window:
            return False, f"Rate limit exceeded: {len(valid_timestamps)} requests in window (limit {self.max_requests_per_window})"

        # Record admission
        valid_timestamps.append(current_time)
        self._seen_nonces[nonce] = current_time
        return True, "Admitted"


def verify_forge_attestation(
    raw_payload: Mapping[str, Any],
    secret_key: Optional[str] = None,
    current_time_iso: Optional[str] = None,
    require_zero_failures: bool = True,
    require_egress_blocked: bool = True,
) -> Tuple[bool, str, Optional[ForgeAttestation]]:
    """End-to-end verification of federated code forge attestation.

    Returns (valid, reason, parsed_attestation).
    """
    try:
        att = parse_forge_attestation(raw_payload)
    except Exception as e:
        return False, f"Schema validation failed: {e}", None

    # Temporal bounds check
    now_dt = _parse_iso(current_time_iso) if current_time_iso else dt.datetime.now(dt.timezone.utc)
    t_iss = _parse_iso(att.issued_at)
    t_exp = _parse_iso(att.expires_at)

    if now_dt < t_iss:
        return False, f"Premature attestation: current time {now_dt.isoformat()} predates issued_at {att.issued_at}", att
    if now_dt >= t_exp:
        return False, f"Expired attestation: current time {now_dt.isoformat()} is at or past expires_at {att.expires_at}", att

    # Test suite outcome validation
    if require_zero_failures and att.test_suite_run.failed_tests > 0:
        return False, f"Test suite contains {att.test_suite_run.failed_tests} failure(s); clean pass required", att
    if att.test_suite_run.passed_tests + att.test_suite_run.skipped_tests != att.test_suite_run.total_tests:
        return False, "Not all tests passed or were cleanly skipped", att

    # Egress isolation validation
    if require_egress_blocked and not att.resource_quota.network_egress_blocked:
        return False, "Network egress was not blocked during test execution; containment violation", att

    # Cryptographic signature check (if key provided)
    if secret_key:
        if not att.verify_signature(secret_key):
            return False, "Cryptographic signature mismatch; receipt has been tampered with or signed with unknown key", att

    return True, "Attestation verified successfully", att
