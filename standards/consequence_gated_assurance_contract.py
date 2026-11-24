"""Consequence-Gated Identity Assurance Contract (arXiv:2610.00287).

Simplified offline model of scope limits and validity windows, not legal advice or
execution authorization. A PIA reference records only caller-supplied text, not the
assessment's existence, adequacy or written agreement. Signature presence is not
verification. Trusted host classification and a separate authority gate are required.
No runtime wiring, transfer, settlement, identity issuance or cryptographic check occurs.
Claims and issuer/subject strings may identify people even at nominally anonymous scope;
the host must minimize payloads before calling this prototype. Scope labels are untrusted
metadata, not proof of actual disclosure. No claim of anonymous transport is made.
"""

from __future__ import annotations

import datetime as dt
import enum
from dataclasses import dataclass, field
from typing import Any, Mapping


class EntityType(str, enum.Enum):
    """Typed entity taxonomy under multi-jurisdictional legal frameworks."""
    NATURAL_PERSON = "natural_person"
    JURIDICAL_ENTITY = "juridical_entity"
    MACHINE_AGENT = "machine_agent"


class ConsequenceTier(str, enum.Enum):
    """Consequence tier of the requested operation."""
    READ_ONLY = "read_only"
    LOW_IMPACT_TRANSACTION = "low_impact_transaction"
    BOUNDED_DELEGATION = "bounded_delegation"
    IRREVERSIBLE_SETTLEMENT = "irreversible_settlement"


class AssertionScope(str, enum.Enum):
    """Scope of disclosed identity assertion."""
    ANONYMOUS = "anonymous"
    MINIMAL_CLAIM = "minimal_claim"
    PSEUDONYMOUS_ATTRIBUTE = "pseudonymous_attribute"
    DIRECT_IDENTIFIER = "direct_identifier"


# Maximum permitted assertion scope per consequence tier.
# Prevents over-collection and surveillance capture (F2: Answers, not data).
MAX_ALLOWED_SCOPE_BY_TIER: Mapping[ConsequenceTier, AssertionScope] = {
    ConsequenceTier.READ_ONLY: AssertionScope.ANONYMOUS,
    ConsequenceTier.LOW_IMPACT_TRANSACTION: AssertionScope.MINIMAL_CLAIM,
    ConsequenceTier.BOUNDED_DELEGATION: AssertionScope.PSEUDONYMOUS_ATTRIBUTE,
    ConsequenceTier.IRREVERSIBLE_SETTLEMENT: AssertionScope.DIRECT_IDENTIFIER,
}

# Required minimum assertion scope per consequence tier.
MIN_REQUIRED_SCOPE_BY_TIER: Mapping[ConsequenceTier, AssertionScope] = {
    ConsequenceTier.READ_ONLY: AssertionScope.ANONYMOUS,
    ConsequenceTier.LOW_IMPACT_TRANSACTION: AssertionScope.MINIMAL_CLAIM,
    ConsequenceTier.BOUNDED_DELEGATION: AssertionScope.PSEUDONYMOUS_ATTRIBUTE,
    ConsequenceTier.IRREVERSIBLE_SETTLEMENT: AssertionScope.PSEUDONYMOUS_ATTRIBUTE,
}

SCOPE_RANK: Mapping[AssertionScope, int] = {
    AssertionScope.ANONYMOUS: 0,
    AssertionScope.MINIMAL_CLAIM: 1,
    AssertionScope.PSEUDONYMOUS_ATTRIBUTE: 2,
    AssertionScope.DIRECT_IDENTIFIER: 3,
}


@dataclass(frozen=True)
class PointInTimeAssertion:
    """Caller-supplied assertion fields; no signature authenticity check."""
    assertion_id: str
    entity_type: EntityType
    scope: AssertionScope
    issuer_did: str
    subject_did: str
    jurisdiction: str
    valid_from: str  # ISO-8601 UTC
    valid_until: str  # ISO-8601 UTC
    claims: Mapping[str, str] = field(default_factory=dict)
    signature: str = ""

    def __post_init__(self) -> None:
        if not self.assertion_id or not isinstance(self.assertion_id, str):
            raise TypeError("assertion_id must be a non-empty string")
        if not isinstance(self.entity_type, EntityType):
            raise TypeError("entity_type must be an instance of EntityType")
        if not isinstance(self.scope, AssertionScope):
            raise TypeError("scope must be an instance of AssertionScope")
        if not self.issuer_did or not isinstance(self.issuer_did, str):
            raise TypeError("issuer_did must be a non-empty string")
        if not self.subject_did or not isinstance(self.subject_did, str):
            raise TypeError("subject_did must be a non-empty string")
        if not self.jurisdiction or not isinstance(self.jurisdiction, str):
            raise TypeError("jurisdiction must be a non-empty string")


@dataclass(frozen=True)
class AssuranceVerdict:
    """Immutable outcome from consequence-gated capability verification."""
    advisory_pass: bool
    consequence_tier: ConsequenceTier
    entity_type: EntityType
    admitted_scope: AssertionScope
    reason: str
    jurisdiction_valid: bool
    over_collection_detected: bool
    details: Mapping[str, Any] = field(default_factory=dict)


class ConsequenceGatedAssuranceContract:
    """Evaluates synthetic metadata; does not grant capabilities or certify compliance."""

    SUPPORTED_JURISDICTIONS = frozenset({"CA-QC", "CA-ON", "EU", "US"})

    @staticmethod
    def parse_iso_time(time_str: str) -> dt.datetime:
        """Parse ISO-8601 timestamp with strict UTC validation."""
        if not isinstance(time_str, str) or not time_str.strip():
            raise ValueError("Timestamp string cannot be empty")
        normalized = time_str.replace("Z", "+00:00")
        try:
            parsed = dt.datetime.fromisoformat(normalized)
            if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
                raise ValueError("Timestamp must have an explicit UTC offset")
            return parsed
        except Exception as e:
            raise ValueError(f"Invalid ISO-8601 timestamp '{time_str}': {e}") from e

    @classmethod
    def evaluate_capability_request(
        cls,
        consequence_tier: ConsequenceTier,
        assertion: PointInTimeAssertion | None,
        target_jurisdiction: str,
        current_time_iso: str | None = None,
        pia_reference: str | None = None,
    ) -> AssuranceVerdict:
        """Evaluate metadata only. PIA text is not authenticated or legally assessed."""
        if not isinstance(consequence_tier, ConsequenceTier):
            raise TypeError(f"consequence_tier must be ConsequenceTier, got {type(consequence_tier).__name__}")
        if not isinstance(target_jurisdiction, str) or not target_jurisdiction.strip():
            raise TypeError("target_jurisdiction must be a non-empty string")

        if assertion is not None and not isinstance(assertion, PointInTimeAssertion):
            raise TypeError("assertion must be PointInTimeAssertion or None")
        if target_jurisdiction not in cls.SUPPORTED_JURISDICTIONS:
            raise ValueError("Unrecognized destination; federal regimes are not places")
        if pia_reference is not None and (not isinstance(pia_reference, str)
                or not pia_reference.strip() or pia_reference != pia_reference.strip()
                or any(ord(c) < 32 for c in pia_reference)):
            raise ValueError("pia_reference must be nonempty plain reference text")

        current_time = (
            cls.parse_iso_time(current_time_iso)
            if current_time_iso is not None
            else dt.datetime.now(dt.timezone.utc)
        )

        # 1. READ_ONLY tier handling
        if consequence_tier == ConsequenceTier.READ_ONLY:
            if assertion is not None and assertion.scope != AssertionScope.ANONYMOUS:
                return AssuranceVerdict(
                    advisory_pass=False,
                    consequence_tier=consequence_tier,
                    entity_type=assertion.entity_type,
                    admitted_scope=assertion.scope,
                    reason="Rejected over-collection: read-only access prohibits personal identity disclosure",
                    jurisdiction_valid=True,
                    over_collection_detected=True,
                )
            return AssuranceVerdict(
                advisory_pass=True,
                consequence_tier=consequence_tier,
                entity_type=EntityType.MACHINE_AGENT if assertion is None else assertion.entity_type,
                admitted_scope=AssertionScope.ANONYMOUS,
                reason="Advisory pass: read-only operation requires no identity disclosure",
                jurisdiction_valid=True,
                over_collection_detected=False,
            )

        # 2. Non-read-only tiers require an assertion
        if assertion is None:
            return AssuranceVerdict(
                advisory_pass=False,
                consequence_tier=consequence_tier,
                entity_type=EntityType.MACHINE_AGENT,
                admitted_scope=AssertionScope.ANONYMOUS,
                reason=f"Rejected: tier {consequence_tier.value} requires assertion metadata",
                jurisdiction_valid=False,
                over_collection_detected=False,
            )

        # 3. Check over-collection against Floor Right F2 (Answers, not data)
        max_allowed_scope = MAX_ALLOWED_SCOPE_BY_TIER[consequence_tier]
        if SCOPE_RANK[assertion.scope] > SCOPE_RANK[max_allowed_scope]:
            return AssuranceVerdict(
                advisory_pass=False,
                consequence_tier=consequence_tier,
                entity_type=assertion.entity_type,
                admitted_scope=assertion.scope,
                reason=(
                    f"Rejected over-collection: tier {consequence_tier.value} permits at most "
                    f"{max_allowed_scope.value}, but received {assertion.scope.value}"
                ),
                jurisdiction_valid=True,
                over_collection_detected=True,
            )

        # 4. Check minimum required scope
        min_required_scope = MIN_REQUIRED_SCOPE_BY_TIER[consequence_tier]
        if SCOPE_RANK[assertion.scope] < SCOPE_RANK[min_required_scope]:
            return AssuranceVerdict(
                advisory_pass=False,
                consequence_tier=consequence_tier,
                entity_type=assertion.entity_type,
                admitted_scope=assertion.scope,
                reason=(
                    f"Rejected insufficient assurance: tier {consequence_tier.value} requires at least "
                    f"{min_required_scope.value}, received {assertion.scope.value}"
                ),
                jurisdiction_valid=True,
                over_collection_detected=False,
            )

        # 5. Temporal validity checks
        try:
            valid_from = cls.parse_iso_time(assertion.valid_from)
            valid_until = cls.parse_iso_time(assertion.valid_until)
        except ValueError as e:
            return AssuranceVerdict(
                advisory_pass=False,
                consequence_tier=consequence_tier,
                entity_type=assertion.entity_type,
                admitted_scope=assertion.scope,
                reason=f"Rejected malformed timestamp in assertion: {e}",
                jurisdiction_valid=False,
                over_collection_detected=False,
            )

        if valid_from > valid_until:
            return AssuranceVerdict(
                advisory_pass=False,
                consequence_tier=consequence_tier,
                entity_type=assertion.entity_type,
                admitted_scope=assertion.scope,
                reason="Rejected inverted validity window: valid_from is after valid_until",
                jurisdiction_valid=False,
                over_collection_detected=False,
            )

        if current_time < valid_from:
            return AssuranceVerdict(
                advisory_pass=False,
                consequence_tier=consequence_tier,
                entity_type=assertion.entity_type,
                admitted_scope=assertion.scope,
                reason="Rejected premature assertion: not yet valid",
                jurisdiction_valid=False,
                over_collection_detected=False,
            )

        if current_time >= valid_until:
            return AssuranceVerdict(
                advisory_pass=False,
                consequence_tier=consequence_tier,
                entity_type=assertion.entity_type,
                admitted_scope=assertion.scope,
                reason="Rejected expired assertion: valid_until has passed",
                jurisdiction_valid=False,
                over_collection_detected=False,
            )

        # 6. Jurisdictional checks
        if assertion.jurisdiction not in cls.SUPPORTED_JURISDICTIONS:
            return AssuranceVerdict(
                advisory_pass=False,
                consequence_tier=consequence_tier,
                entity_type=assertion.entity_type,
                admitted_scope=assertion.scope,
                reason=f"Rejected unrecognized assertion jurisdiction: {assertion.jurisdiction}",
                jurisdiction_valid=False,
                over_collection_detected=False,
            )

        # Simplified section 17 prerequisite; a reference does not certify compliance.
        if assertion.jurisdiction == "CA-QC" and target_jurisdiction != "CA-QC" and pia_reference is None:
            return AssuranceVerdict(
                advisory_pass=False,
                consequence_tier=consequence_tier,
                entity_type=assertion.entity_type,
                admitted_scope=assertion.scope,
                reason="Rejected cross-border transfer under Quebec Law 25 Section 17 without caller-supplied PIA reference",
                jurisdiction_valid=False,
                over_collection_detected=False,
            )

        # 7. Signature presence check
        if not assertion.signature or not assertion.signature.strip():
            return AssuranceVerdict(
                advisory_pass=False,
                consequence_tier=consequence_tier,
                entity_type=assertion.entity_type,
                admitted_scope=assertion.scope,
                reason="Rejected unsigned assertion: missing signature text",
                jurisdiction_valid=True,
                over_collection_detected=False,
            )

        # Admitted advisory pass
        return AssuranceVerdict(
            advisory_pass=True,
            consequence_tier=consequence_tier,
            entity_type=assertion.entity_type,
            admitted_scope=assertion.scope,
            reason="Advisory pass: scope and time checks passed; signature present, not verified; host decides execution",
            jurisdiction_valid=True,
            over_collection_detected=False,
            details={
                "assertion_id": assertion.assertion_id,
                "issuer": assertion.issuer_did,
                "jurisdiction": assertion.jurisdiction,
                "pia_reference": pia_reference,
                "signature_checked": False,
            },
        )
