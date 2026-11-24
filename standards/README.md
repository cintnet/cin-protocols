# Agent-to-Agent Consent and Delegation Standards (`research/standards`)

> **Top-of-file note:**
> - **What it is:** Draft JSON Schemas (`agent-consent-grant-v0.1.json`, `agent-policy-card-v0.1.json`, `agent-delegation-token-v0.1.json`, `agent-audit-record-v0.1.json`, `agent-mortal-contract-v0.1.json`, `agent-reliability-profile-v0.1.json`, `agent-evidence-receipt-v0.1.json`, `agent-scope-contract-v0.1.json`, `federated-code-forge-attestation-v0.1.json`), example documents, deterministic test suites, and the master catalog [`STANDARDS-INDEX.md`](./STANDARDS-INDEX.md).
> - **What it is for:** Mission `standards` — offline design of peer-to-peer agent consent, delegation, runtime audit records, policy cards, mortal computation contracts, reliability profiles, and evidence receipts under Specification 03 and Floor Rights F1, F3, F17, F19.
> - **Master Catalog:** See [`STANDARDS-INDEX.md`](./STANDARDS-INDEX.md) for full schema inventory, invariants, test commands, and absorbed draft tickets.
> - **What is uncertain / stubbed:** Canonical cryptographic envelope formatting (JOSE/COSE vs W3C VC), low-power device key rotation, and multi-party negotiation timeouts.
> - **Scope boundary:** Offline data standard proposal only; no broker engine integration.

---

## 1. Key Design Rules

- **Fail-Closed Scoping:** Grants, contracts, and delegation tokens strictly forbid extra properties at root and nested levels.
- **Mandatory Human Authorization:** Grants and contracts require explicit human authorization or principal binding. Cryptographic signatures verify key possession, not human intent or authority.
- **Strict Boundary Expiry:** Request evaluation at or after `expires_at` is rejected (`grant_expired` / `token_expired` / `contract_expired`). Lifespans must be strictly positive (`expires_at > issued_at`).
- **Mortal Resource Bounding:** Mortal computation contracts enforce multi-dimensional integer resource bounds (daily inference units, training units, memory, storage, replicas) and explicit budget conservation (Ye & Tan 2026, arXiv:2601.08815; Spec 03 §3). Unmetered execution is forbidden.
- **Always Revocable:** Requires `revocable: true` (constant) on consent grants. Irrevocable records are rejected.
- **Drift Protection:** Execution fails if recipient (`grantee_agent_id` or `delegatee_agent_id`) or action drifts.
- **Blast Radius Monotonicity:** Delegated tokens enforce monotonic scope attenuation (Muruaga 2026, arXiv:2608.15888; Ibrahim & Li 2026, arXiv:2606.03518): child scope must be a non-increasing subset of delegator scope (actions, data categories, and budgets); privilege or budget escalation is rejected.
- **Principal Chain Accountability:** Delegation tokens require a verifiable `principal_chain` whose root identifies the originating human principal (`person:...`). Cryptographic signatures verify key possession, not human intent or authority (hardware enclave binding is a future stub).
- **Hash-Chained Audit Integrity:** Audit and decision records require deterministic SHA-256 hash chaining (`prev_record_hash`) and payload digests rather than raw content leaks, enabling reconstructable evidence substrates (Tallam 2026, arXiv:2606.12320).

---

## 2. Standards Comparison [unverified]

> Note: Standards comparisons and architectural differences below are analytical summaries and marked [unverified] pending formal external specification review.

| Standard | Scope | Architectural Differences [unverified] | Primary Source |
| --- | --- | --- | --- |
| **OAuth 2.0 RAR** | Rich authorization requests [unverified] | [unverified] Designed for client-to-AS centralized flows; CIN model uses peer-to-peer bilateral twin contracts. | [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html) |
| **User-Managed Access (UMA 2.0)** | Resource owner auth delegation [unverified] | [unverified] Heavy multi-party token exchange requiring a central UMA Authorization Server hosting policy endpoints. | [Kantara UMA 2.0](https://kantarainitiative.org/groups/user-managed-access-work-group/) |
| **W3C Verifiable Credentials 2.0** | Cryptographic claims [unverified] | [unverified] Focuses on static credential assertions rather than active bilateral execution contracts with single-use limits. | [W3C VC 2.0](https://www.w3.org/TR/vc-data-model-2.0/) |
| **Agentic Principal Chain (APC)** | Delegation authority tracking [unverified] | [unverified] Muruaga (arXiv:2608.15888) evaluates session-state authorization; CIN specifies machine-checkable JSON tokens for decentralized peer-to-peer verification. | [arXiv:2608.15888](https://arxiv.org/abs/2608.15888) |
| **Agent Contracts** | Resource-bounded execution [unverified] | [unverified] Ye & Tan (arXiv:2601.08815) formalize resource constraints; CIN incorporates mortal lifespan and capability scopes (Spec 03). | [arXiv:2601.08815](https://arxiv.org/abs/2601.08815) |

---

## 3. Status and Limits

- **What this is:** Offline proposal and draft schemas for agent-to-agent consent grants, policy cards, delegation tokens, runtime audit records, mortal computation contracts, agent reliability profiles, evidence receipts, and executable scope contracts.
- **What was tested:** All eight standard test suites and catalog validator pass deterministically (`python -m unittest discover -s research/standards/tests` and `python -m unittest research/standards/test_standards_index.py`):
  1. `python -m unittest research/standards/tests/test_consent_grant_schema.py`: 2 positive checks and 21 adversarial conformance tests (23 checks total).
  2. `python -m unittest research/standards/tests/test_policy_card_schema.py`: 10 test methods covering schema validation, network allowlist bounds, path traversals, expiry windows, revocation enums, and identifier patterns.
  3. `python -m unittest research/standards/tests/test_delegation_token_schema.py`: 3 positive checks, 15 structural fail-closed rejections, 7 attenuation escalation and malformed input rejections, and 8 lifecycle boundary rejections (33 checks total).
  4. `python -m unittest research/standards/tests/test_audit_record_schema.py`: 3 positive checks (schema conformance, timestamp parsing, hash-chain continuity) and 20 adversarial fail-closed conformance checks (23 checks total).
  5. `python -m unittest research/standards/tests/test_mortal_contract_schema.py`: 2 positive validations, 1 lifecycle evaluation check, and 15 fail-closed rejections (18 checks total).
  6. `python -m unittest research/standards/tests/test_reliability_profile_schema.py`: 15 test methods covering schema validation, assurance ladders, basis point tolerances, floats and booleans, allowlists, enums, hash anchors, signatures, and fail-closed rejections.
  7. `python -m unittest research/standards/tests/test_evidence_receipt_schema.py`: 15 test methods covering schema validation, fail-closed property rejection, hash pattern enforcement, integer checks, and timestamp formatting.
  8. `python -m unittest research/standards/tests/test_scope_contract_schema.py`: 19 test methods covering schema metadata, example validation, missing fields, extra properties, float quotas, auto-halt const invariant, cross-run persistence prohibition, non-zero lifespans, path traversals, trailing dots/spaces, empty strings, direct IP endpoints, and offline mode.
  9. `python -m unittest research/standards/test_standards_index.py`: 6 catalog and index coverage tests.
- **What is not done:** Live broker runtime integration, hardware cryptographic signing, and multi-turn negotiation protocols.
