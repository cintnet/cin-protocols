# Agent Policy Cards Standard (`research/standards`)

> **Top-of-file note:**
> - **What it is:** Draft JSON Schema (`agent-policy-card-v0.1.json`), example document (`personal-assistant-policy-card.json`), and deterministic conformance test suite for machine-readable runtime policy cards.
> - **What it is for:** Mission `standards` — offline specification of execution bounds, tool permissions, and human intervention thresholds for autonomous agents.
> - **What is uncertain / stubbed:** Cross-domain policy federation, hardware enclave attestation, and dynamic constraint negotiation between unfamiliar peers.
> - **Scope boundary:** Offline data standard proposal only; no runtime broker engine integration.

---

## 1. Grounding and Context

This draft draws on two primary research frameworks:
- **Policy Cards (Mavračić, 2025, arXiv:2510.24383):** Proposes deployment-layer machine-readable constraints (allow/deny rules) accompanying an agent at runtime to enforce operational and regulatory boundaries.
- **Layered Governance Architecture (Ge, 2026, arXiv:2603.07191):** Outlines multi-layer defense including sandboxing, intent verification, zero-trust authorization, and immutable audit logs.

---

## 2. Key Design Rules

- **Fail-Closed Scoping:** Unknown fields at root and nested levels are rejected.
- **Explicit Network Boundaries:** Network access defaults to isolated; egress requires explicit host allowlisting.
- **Bounded Compute Quotas:** Max execution steps, tokens, and timeouts prevent unbounded loops.
- **Human Intervention Triggers:** Irreversible or high-risk actions (e.g. data sharing, financial actions) require explicit human approval.
- **Non-Negotiable Revocation:** Cards must be revocable (`revocable: true`). Irrevocable policies are rejected.
- **Boundary Expiry:** Policies must define an explicit expiry window and fail once expired.

---

## 3. Status and Limits

- **What was tested:** `python -m unittest research/standards/tests/test_policy_card_schema.py` executes 10 deterministic tests covering valid card parsing, top-level and nested extra key rejection, irrevocable policy rejection, revocation status checks, empty tool allowlist rejection, negative compute quotas, negative financial limits, expiry window enforcement, evaluation expiry checks, path traversal rejection, cryptographic signature formatting, empty network allowlist rejection, strict rejection of unknown extra keys across human intervention, revocation, and signature objects, non-list and non-string tool definitions, non-boolean revocation status, dot-slash path variants, and non-string identifiers. All 10 tests passed.
- **What is not done:** Live runtime interception, operating system sandbox enforcement, and distributed policy discovery.
