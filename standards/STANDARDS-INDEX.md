# Agent Standards Master Catalog (`research/standards`)

> **Top-of-file note:**
> - **What it is:** Consolidated reference catalog and architectural index of all machine-readable JSON schemas, example payloads, and conformance test suites in `research/standards/`.
> - **What it is for:** Mission `standards` / `library` — provides a single authoritative directory of bilateral agent consent grants, attenuated delegation tokens, hash-chained audit records, mortal computation contracts, agent policy cards, reliability profiles, evidence receipts, executable scope contracts, and web interaction contracts supporting Specification 03 and Floor Rights F1, F3, F17, and F19.
> - **Absorbed drafts:** Consolidates and indexes drafts D-0015 (consent grants), D-0037 (policy cards), D-0067 (delegation tokens), D-0081 (audit records), D-0130 & D-0143 (standards surveys), D-0170 (mortal contracts), D-0247 (reliability profiles), D-0255 (evidence receipts), D-0313 (executable scope contracts), D-0344 (agent web interaction contracts), and D-0385 (agent binding credentials).
> - **Grounding:** Aligns with ARISMA (Moghaddam & Alipour 2026, arXiv:2608.25050; auditable agent governance), Proactive Boundary Assurance (arXiv:2610.12463; executable scope contracts and egress controls), ClaimReceipt (arXiv:2609.01992; evidence coverage), Penumbra (arXiv:2610.04693; regulatory obligation bounds), Web$hell WebContract (arXiv:2610.13416; addressable object schemas for agent web access), and IETF WIMSE Verifiable Mandates (draft-hulea-wimse-agent-mandate-01, https://datatracker.ietf.org/doc/draft-hulea-wimse-agent-mandate/).
> - **Scope boundary:** Offline protocol and schema proposals; no live broker engine integration or cryptographic enclave signing yet.

---

## 1. Overview and Design Principles

The CIN architecture requires that all agent interactions adhere to constitutional boundaries defined in software. Rather than trusting natural-language instructions or heuristic guardrails, runtime boundaries are declared through machine-checkable, fail-closed JSON data structures.

All schemas in `research/standards/` enforce six common design rules:

1. **Fail-Closed Structural Validation:** Root and nested objects explicitly forbid undeclared properties (`additionalProperties: false`). Unknown fields are rejected immediately.
2. **Mandatory Human Authorization Root:** Bilateral delegations and contracts require an unambiguous human root principal (`person:<id>`). Signatures verify cryptographic key possession, not autonomous human authority or consent.
3. **Strict Non-Zero Lifespan Windows:** All tokens and contracts enforce strictly positive lifespans (`expires_at > issued_at`). Pre-expired or equal timestamps fail closed.
4. **Monotonic Scope Attenuation:** Delegated authority tokens enforce monotonic scope narrowing (Muruaga 2026, arXiv:2608.15888): delegatee actions, data categories, and resource budgets must form a strict subset of delegator permissions; privilege or budget escalation is rejected.
5. **Integer-Only Resource Conservation:** Compute, inference, memory, and storage allocations are strictly represented as positive integer units (Specification 04). Floating-point amounts and unmetered execution are rejected.
6. **Reconstructable Cryptographic Provenance:** Runtime evaluations and audit records require deterministic SHA-256 hash chaining (`prev_record_hash`) and content digests, preventing undetected tampering or state drift (Tallam 2026, arXiv:2606.12320).

---

## 2. Standards Catalog

| Schema Name | Version | Governing Floor Right | Schema File | Example Payload | Test Suite |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Agent Consent Grant** | `v0.1` | **F1, F3** (Data sovereignty; non-monetized disclosure) | `agent-consent-grant-v0.1.json` | `examples/dentist-visit-consent-grant.json` | `tests/test_consent_grant_schema.py` |
| **Agent Policy Card** | `v0.1` | **F13, F19** (No engagement traps; bounded compute) | `agent-policy-card-v0.1.json` | `examples/personal-assistant-policy-card.json` | `tests/test_policy_card_schema.py` |
| **Agent Delegation Token** | `v0.1` | **F1, F19** (Personal data sovereignty; bounded authority) | `agent-delegation-token-v0.1.json` | `examples/delegated-sensor-query-token.json` | `tests/test_delegation_token_schema.py` |
| **Agent Audit Record** | `v0.1` | **F2, F17** (Verify the watchers; cryptographic logs) | `agent-audit-record-v0.1.json` | `examples/runtime-gate-audit-record.json` | `tests/test_audit_record_schema.py` |
| **Agent Mortal Contract** | `v0.1` | **F19** (Mortal compute; hard resource limits) | `agent-mortal-contract-v0.1.json` | `examples/personal-twin-mortal-contract.json` | `tests/test_mortal_contract_schema.py` |
| **Agent Reliability Profile** | `v0.1` | **F1, F17, F19** (Verifiable assurance; bounded execution) | `agent-reliability-profile-v0.1.json` | `examples/financial-advisor-reliability-profile.json` | `tests/test_reliability_profile_schema.py` |
| **Agent Evidence Receipt** | `v0.1` | **F2, F17** (Verify the watchers; auditable evidence) | `agent-evidence-receipt-v0.1.json` | `examples/dentist-sensor-evidence-receipt.json` | `tests/test_evidence_receipt_schema.py` |
| **Agent Scope Contract** | `v0.1` | **F1, F3, F17, F19** (Bounded execution; egress and stop controls) | `agent-scope-contract-v0.1.json` | `examples/research-agent-scope-contract.json` | `tests/test_scope_contract_schema.py` |
| **Agent Web Contract** | `v0.1` | **F1, F3, F19** (Personal data sovereignty; bounded egress) | `agent-web-contract-v0.1.json` | `examples/web-research-contract.json` | `tests/test_web_contract_schema.py` |
| **Agent Binding Credential** | `v0.1` | **F1, F17, F19** (Agent binding; inner sovereignty; bounded compute) | `agent-binding-credential-v0.1.json` | `examples/agent-binding-credential-example.json` | `tests/test_agent_binding_credential_schema.py` |
| **Agent Control Incident Record** | `v0.1` | **F1, F17, F19** (Deterministic containment; verifiable evidence; kill switch) | `agent-control-incident-response-v0.1.json` | `examples/agent-control-incident-record-example.json` | `tests/test_agent_control_incident_response.py` |
| **Federated Code Forge Attestation** | `v0.1` | **F1, F17, F19** (Proof-Carrying Code; bounded compute; forge rate limiting) | `federated-code-forge-attestation-v0.1.json` | `examples/federated-code-forge-attestation.example.json` | `tests/test_federated_code_forge_attestation.py` |
| **Agent Verifiable Mandate** | `v0.1` | **F1, F17, F19** (Cross-domain mandate; authority separation; bounded limits) | `agent-verifiable-mandate-v0.1.json` | `examples/cross-domain-procurement-mandate.json` | `tests/test_verifiable_mandate_schema.py` |
| **Agent PTV Hardware Attestation** | `v0.1` | **F1, F2, F17, F19** (Hardware-anchored attestation; configuration binding; zero-knowledge claims) | `agent-ptv-attestation-v0.1.json` | `examples/agent-ptv-attestation-example.json` | `tests/test_agent_ptv_attestation.py` |

---

## 3. Schema Specifications & Invariants

### 3.1. Agent Consent Grant (`agent-consent-grant-v0.1.json`)
- **Absorbed Draft:** D-0015
- **Purpose:** Bilateral consent grants from a human user or twin to an external service or counterparty agent.
- **Key Invariants:**
  - `revocable` must be strictly `true` (irrevocable consent is rejected).
  - Explicit `data_scope.fields_permitted` allowlist; empty lists or unauthorized requested fields are rejected.
  - Strict ISO 8601 UTC timestamp parsing with boundary expiration enforcement (`evaluated_at >= expires_at` rejected).
  - Invocations capped by `data_scope.max_invocations` (integer >= 1).
- **Test Command:**
  ```bash
  python -m unittest research/standards/tests/test_consent_grant_schema.py
  ```

### 3.2. Agent Policy Card (`agent-policy-card-v0.1.json`)
- **Absorbed Draft:** D-0037
- **Purpose:** Declarative specification of an agent's runtime capabilities, permitted network hosts, storage boundaries, and model tiers.
- **Key Invariants:**
  - `runtime_bounds.network_egress.allowed_hosts` must not be empty if network mode is `allowlist_only`.
  - Storage paths strictly normalized; relative path traversals (`..`), dot-streams, and absolute rooted paths rejected under `runtime_bounds.data_boundaries.forbidden_paths`.
  - Tool execution boundaries enforced: `runtime_bounds.tools.permitted_tools` must be non-empty and `forbidden_capabilities` explicitly declared without wildcards.
- **Test Command:**
  ```bash
  python -m unittest research/standards/tests/test_policy_card_schema.py
  ```

### 3.3. Agent Delegation Token (`agent-delegation-token-v0.1.json`)
- **Absorbed Draft:** D-0067
- **Purpose:** Attenuated task-specific authority tokens passed from a delegating agent to a subordinate or third-party agent.
- **Key Invariants:**
  - `principal_chain` required, must be rooted in a human principal identifier (`person:...`).
  - Monotonic scope attenuation: delegatee `scope.allowed_actions` and `scope.data_categories` must be subsets of delegator scope, and `scope.max_budget_units` cannot escalate.
  - Delegation depth bounded by delegator `delegator.max_delegation_depth` (non-negative integer).
- **Test Command:**
  ```bash
  python -m unittest research/standards/tests/test_delegation_token_schema.py
  ```

### 3.4. Agent Audit Record (`agent-audit-record-v0.1.json`)
- **Absorbed Draft:** D-0081
- **Purpose:** Hash-chained append-only log entries documenting every capability broker grant, denial, or tool invocation.
- **Key Invariants:**
  - `prev_record_hash` must be a valid 64-character hexadecimal SHA-256 hash. Genesis record uses `0000...0000`.
  - Raw payload text is not stored in logs; cryptographic digests `evidence.input_digest` and `evidence.output_digest` are recorded to prevent data leakage in audit streams.
  - Enforces monotonic non-decreasing timestamp sequence and strict enumeration of `action_plane` and `adjudication.decision`.
- **Test Command:**
  ```bash
  python -m unittest research/standards/tests/test_audit_record_schema.py
  ```

### 3.5. Agent Mortal Contract (`agent-mortal-contract-v0.1.json`)
- **Absorbed Draft:** D-0170
- **Purpose:** Mortal computation contracts bounding agent lifecycle, maximum inference units, training quotas, and memory consumption.
- **Key Invariants:**
  - Hard expiry timestamp (`expires_at > issued_at`).
  - Strict integer-only budgets under `budgets`: `inference_units_per_day`, `training_units`, and `memory_mb`. Negative or float budgets rejected.
  - Remote model providers list `remote_models.allowed_providers` must be non-empty when `remote_models.permitted` is `true`.
  - Bound lifecycle status evaluation (`active` only within `[issued_at, expires_at)`).
- **Test Command:**
  ```bash
  python -m unittest research/standards/tests/test_mortal_contract_schema.py
  ```

### 3.6. Agent Reliability Profile (`agent-reliability-profile-v0.1.json`)
- **Absorbed Draft:** D-0247
- **Purpose:** Standardized machine-readable assurance profiles establishing a 3-level verification ladder (asserted, validated, verified), operational error bounds, and deterministic handoff contract anchors.
- **Key Invariants:**
  - Strict assurance levels: `asserted`, `validated`, or `verified`.
  - Non-negative integer basis-point bounds (`max_error_rate_bps <= 10000`, `max_drift_tolerance_bps <= 10000`).
  - Handoff governance requires deterministic 64-character SHA-256 contract anchor hash and strict boolean `halt_on_failure`.
  - Hard expiry with `expires_at > issued_at` and non-empty `action_allowlist`.
- **Test Command:**
  ```bash
  python -m unittest research/standards/tests/test_reliability_profile_schema.py
  ```

### 3.7. Agent Evidence Receipt (`agent-evidence-receipt-v0.1.json`)
- **Absorbed Draft:** D-0255
- **Purpose:** Machine-checkable receipt binding transaction evidence to signed action manifests, evaluating sufficiency and coverage per ClaimReceipt (arXiv:2609.01992).
- **Key Invariants:**
  - Verdict and status strictly typed as `PASS`, `INVALID`, or `INCONCLUSIVE`.
  - Merkle root and evidence hashes strictly formatted as 64-character hexadecimal SHA-256 strings.
  - Coverage check enforces non-negative integer action and evidence counts (`committed_action_count`, `accounted_action_count`, `withheld_evidence_count`).
  - Signatures require valid cryptographic roles (`runtime_host`, `gatekeeper`, `verifier`, `twin_agent`).
- **Test Command:**
  ```bash
  python -m unittest research/standards/tests/test_evidence_receipt_schema.py
  ```

### 3.8. Agent Scope Contract (`agent-scope-contract-v0.1.json`)
- **Absorbed Draft:** D-0313
- **Purpose:** Host-enforced executable scope contracts defining operational sandbox boundaries, allowed tools, filesystem traversal barriers, network egress allowlists, and automatic termination triggers. Grounded in frontier agent boundary assurance findings (arXiv:2610.12463) and regulatory obligation search (arXiv:2610.04693).
- **Key Invariants:**
  - `auto_halt_on_boundary_violation` strictly boolean `true`.
  - `cross_run_persistence_permitted` strictly boolean `false` (prohibiting cross-run covert coordination and state leakage).
  - Explicit integer-only quotas (`max_wall_time_seconds`, `max_tool_invocations`, `max_inbound_bytes`, `max_outbound_bytes`).
  - Strict network egress controls: `allowlist_only` requires non-empty `allowed_endpoints` with explicit HTTPS endpoints; `prohibit_direct_ip` and `prohibit_dns_rebinding` enforced.
  - Strict non-zero lifespan (`expires_at > issued_at`) with ISO 8601 timezone offsets.
- **Test Command:**
  ```bash
  python -m unittest research/standards/tests/test_scope_contract_schema.py
  ```

### 3.9. Agent Web Contract (`agent-web-contract-v0.1.json`)
- **Absorbed Draft:** D-0344
- **Purpose:** Machine-checkable web interaction contracts bounding domain egress, HTTP methods, payload limits, object compilation, and session credential isolation under Specification 03 Section 6 and Floor Rights F1, F3, and F19. Grounded in Web$hell WebContract specifications (arXiv:2610.13416), VEPA formal guardrails (arXiv:2610.12813), and ScopeBench boundary violation findings (arXiv:2609.30325).
- **Key Invariants:**
  - `prohibit_wildcard_domains` and `prohibit_direct_ip` strictly boolean `true`.
  - `allowed_endpoints` must be a non-empty array of strict canonical HTTPS endpoint patterns; malformed hostnames (consecutive dots, empty DNS labels), out-of-range ports (outside 1..65535), whitespace or control characters, naked domain wildcards, and bare IP addresses are rejected.
  - `allowed_methods` strictly enumerated (`GET`, `HEAD`, `POST`); mutating stateful HTTP verbs (`PUT`, `DELETE`) are rejected. Note that schema-level method restriction bounds declared verbs but does not guarantee side-effect-free execution, as even GET requests can trigger stateful effects, logging, or telemetry on remote services.
  - Integer-only resource quotas (`max_requests_per_session`, `max_payload_bytes`, `request_timeout_seconds`, `max_consecutive_http_errors`).
  - Strict privacy protections: `cookie_policy` limited to `disallowed` or `ephemeral_session_only`; `credential_retention_permitted` strictly `false`; `strip_personal_identifiers` strictly `true`.
  - Addressable object schemas require `require_address`, `require_value`, and `require_association` to be strictly `true`.
  - Strict non-zero lifespan (`expires_at > issued_at`) with ISO 8601 timezone offsets.
  - **Draft/Offline Boundary:** Schema validation verifies structural contract compliance offline; it does not replace runtime egress mediation, packet filtering, or cryptographic authorization by the local host gatekeeper.
- **Test Command:**
  ```bash
  python -m unittest research/standards/tests/test_web_contract_schema.py
  ```

### 3.10. Consequence-Gated Identity Assurance Contract (`consequence_gated_assurance_contract.py`)
- **Absorbed Draft:** D-0362
- **Purpose:** Offline consequence-to-scope metadata and validity-window checks; signature presence is not verification; PIA references are not authenticated (arXiv:2610.00287) holding assurance state apart from capability gates.
- **Key Invariants:**
  - Read-only operations require no identity disclosure (`AssertionScope.ANONYMOUS`); over-collection of personal data is rejected (F2: Answers, not data).
  - Progressive disclosure: `MINIMAL_CLAIM` for low-impact transactions, `PSEUDONYMOUS_ATTRIBUTE` for bounded delegation.
  - Strict point-in-time assertion validity windows (`valid_from <= current_time < valid_until`).
  - Simplified Quebec prerequisite: external destinations require a caller-supplied PIA reference, not proof of assessment adequacy or legal compliance.
- **Test Command:**
  ```bash
  python -m unittest research/standards/tests/test_consequence_gated_assurance_contract.py
  ```

### 3.11. Agent Binding Credential (`agent-binding-credential-v0.1.json`)
- **Absorbed Draft:** D-0385
- **Purpose:** Cryptographically bind an autonomous agent to an accountable human principal (via privacy-preserving personhood credentials) or registered organisation on the second internet, declaring model families, finite compute budgets, and expiring permission leases.
- **Key Invariants:**
  - Strict fail-closed schema validation rejecting unknown fields and extra properties.
  - Holder binding consistency: person binding requires valid `personhood_credential_ref` and forbids `organisation_ref`; organisation binding requires `organisation_ref` and forbids `personhood_credential_ref`.
  - Strict lifecycle windows: `expires_at > issued_at`.
  - Expiring permission leases: each lease must satisfy `lease.expires_at > lease.granted_at` and cannot outlive parent credential (`lease.expires_at <= credential.expires_at`).
  - Compute budget enforcement: positive integer bounds on tokens per hour, parallel threads, daily units, and rate limits.
- **Test Command:**
  ```bash
  python -m unittest research/standards/tests/test_agent_binding_credential_schema.py
  ```

### 3.12. Agent Control Incident Response (`agent-control-incident-response-v0.1.json`)
- **Absorbed Draft:** D-0790
- **Purpose:** Standardized schema and conformance engine for logging, containing, baseline recovery, and reporting autonomous agent control incidents under joint NIST CAISSI, NSA SISC, and CISA guidance (Document PP-26-4396, October 16, 2026; Signal `S-20261030-2490`) and NIST SP 800-61r3.
- **Key Invariants:**
  - Strict 5-stage lifecycle state machine (`prepare`, `detect`, `respond`, `recover`, `report`).
  - No skip-stage recovery: cannot enter `recover` or `report` unless `execution_halted` is `true`.
  - Containment verification gate: `containment_verified` must be `true` and verified by an identified auditor before resuming or reporting.
  - Trusted baseline rebuild: `rebuilt_from_trusted_baseline` must be `true` with matching cryptographic state digest.
  - Fail-closed validation rejecting unknown properties, non-ISO-8601 timestamps, and boolean or non-finite anomaly scores.
- **Test Command:**
  ```bash
  python -m unittest research/standards/tests/test_agent_control_incident_response.py
  ```

### 3.12. Federated Code Forge Attestation (`federated-code-forge-attestation-v0.1.json`)
- **Absorbed Draft:** D-0833
- **Purpose:** Cryptographic test execution receipts, Proof-Carrying Code verification, and sliding-window rate-limiting gates for federated git code forges.
- **Key Invariants:**
  - Mandatory `network_egress_blocked: true` during sandbox test execution.
  - Strict test tally conservation (`passed_tests + failed_tests + skipped_tests == total_tests`).
  - Clean pass verification (`failed_tests == 0` and `passed_tests + skipped_tests == total_tests`).
  - Cryptographic binding of Git commit SHA, tree hash, unique nonce, and expiration window.
  - Fail-closed validation rejecting unknown properties, boolean-as-integer spoofing, and replayed nonces.
- **Test Command:**
  ```bash
  python -m unittest research/standards/tests/test_federated_code_forge_attestation.py
  ```

### 3.13. Agent Verifiable Mandate (`agent-verifiable-mandate-v0.1.json`)
- **Absorbed Draft:** D-0989
- **Grounding:** IETF WIMSE `draft-hulea-wimse-agent-mandate-01` (November 2026, https://datatracker.ietf.org/doc/draft-hulea-wimse-agent-mandate/; Signal `S-20261103-3386`) and Spec 03.
- **Purpose:** Verifiable cross-administrative domain delegation contracts for autonomous agents acting across organizational boundaries.
- **Key Invariants:**
  - Strict separation of delegator authority evidence (`authority_statement`) from mandate grants (`mandate_grant`), preventing delegators from conferring rights they do not possess.
  - Monotonic scope attenuation: conferred agent actions and target domains must form a strict subset of delegator authority bounds.
  - Strict integer-only resource accounting for compute tokens and financial limits in cents (LS-a25669).
  - Explicit token status list URI and index for deterministic client-side revocation.
  - Fail-closed validation rejecting unknown properties, expired or reversed lifespans, and privilege or budget escalation.
- **Test Command:**
  ```bash
  python -m unittest research/standards/tests/test_verifiable_mandate_schema.py
  ```

### 3.14. Agent PTV Hardware Attestation (`agent-ptv-attestation-v0.1.json`)
- **Absorbed Draft:** D-1007
- **Purpose:** Cryptographic hardware-anchored attestation record binding autonomous agents to verified enclaves (TPM2, SEV-SNP, Nitro Enclaves) and configuration commitments without leaking model weights or prompt context.
- **Key Invariants:**
  - Strict separation of identity integrity from behavioral evaluation per `draft-anandakrishnan-rats-ptv-agent-identity`.
  - Zero-knowledge claim transformation mapping hardware measurements to EAT claims (RFC 9711).
  - Exercise-time challenge nonce validation to prevent replay attacks across execution sessions.
  - Fail-closed validation rejecting unknown properties, untrusted enclaves, expired validity windows, and malformed digests.
- **Test Command:**
  ```bash
  python -m unittest research/standards/tests/test_agent_ptv_attestation.py
  ```

---

## 4. Associated Research Documents

- **`AGENT-PTV-ATTESTATION.md`** (Absorbed draft D-1007):
  Specification and reference implementation for the Prove-Transform-Verify hardware-anchored attestation protocol grounded in IETF RATS (RFC 9334) and Entity Attestation Token (RFC 9711).

- **`FEDERATED-CODE-FORGE-ATTESTATION.md`** (Absorbed draft D-0833):
  Specification and reference implementation for cryptographic test execution attestations and rate-limiting gates on federated git code forges.
- **`AGENT-CONTROL-INCIDENT-RESPONSE.md`** (Absorbed draft D-0790):
  Specification and state machine rules for autonomous agent control incidents, containment gates, and baseline recovery.
- **`AGENT-BINDING-CREDENTIAL.md`** (Absorbed draft D-0385):
  Specification and mapping of agent binding credentials to W3C Verifiable Credentials and privacy-preserving personhood credentials for the second internet.
- **`STANDARDS-SURVEY.md`** (Absorbed drafts D-0130, D-0143, D-0344):
  Comprehensive survey comparing CIN agent standards against W3C Verifiable Credentials 2.0, OAuth 2.0 Rich Authorization Requests (RFC 9396), Kantara UMA 2.0, Model Context Protocol (MCP) data spaces, WebContract (arXiv:2610.13416), and Decentralized Identifiers (DIDs).
- **`POLICY-CARDS.md`** (Absorbed draft D-0037):
  Guide to writing and validating machine-readable Agent Policy Cards, detailing schema fields, containment boundaries, and verification examples.

---

## 5. Standards Crosswalk [unverified]

> Note: External standards mappings below are analytical comparisons marked [unverified] pending formal external multi-party interoperability testing.

| Dimension | CIN Architecture | Traditional Auth (OAuth RAR / UMA 2.0) [unverified] | Decentralized Identity (W3C VC / DID) [unverified] |
| :--- | :--- | :--- | :--- |
| **Trust Model** | Bilateral peer-to-peer personal twins | Centralized Authorization Server (AS) | Issuer / Holder / Verifier triad |
| **Data Custody** | Zero network custody; local SQLCipher (F1) | Resource Server custody | Holder wallet (often cloud/custodial) |
| **Revocation** | Constant-time local ledger revocation | Central token revocation endpoint (RFC 7009) | StatusList2021 / revocation registries |
| **Resource Limits** | Finite mortal compute budgets (Spec 03, F19) | Rate limits / billing tiers | N/A (identity/credential only) |
| **Audit Substrate** | Local deterministic hash-chained logs | Opaque server-side access logs | Verifiable data registries / ledgers |

---

## 6. Status and Limits

- **What was tested:**
  - All 10 schema validation test suites pass deterministically (`python -m unittest discover -s research/standards/tests`).
  - All 10 example documents conform strictly to their respective schemas.
  - Automated test suite `research/standards/test_standards_index.py` validates catalog completeness.
- **What is not done:**
  - Live runtime capability broker enforcement (Specification 03 milestone R1).
  - Hardware security module (HSM) or secure enclave key binding for token signing.
  - Multi-party peer negotiation timeouts and distributed conflict arbitration.



