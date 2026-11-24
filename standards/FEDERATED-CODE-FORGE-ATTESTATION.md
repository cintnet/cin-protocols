# Federated Code Forge Attestation and Rate-Limiting Gate (v0.1)

> **Note on purpose and status:**
> **What it is:** A machine-checkable reference specification and deterministic verification engine for cryptographic test execution attestations, rate-limiting gates, and Proof-Carrying Code verification on federated git code forges.
> **What it is for:** Protecting decentralized, community-hosted git forges (such as Forgejo, Gitea, and Radicle) against automated pull-request flooding, LLM agent hallucinated churn, and unverified dependency backdoors without requiring paid corporate identity walls, credit cards, or surveillance captchas (Floor Rights F1, F17, and F19).
> **Scientific provenance:** Grounds in Object-Capability architectures (Dennis & Van Horn, 1966), Proof-Carrying Code (Necula, 1997), and cryptographic audit ledgers (Moghaddam & Alipour, 2026, arXiv:2608.25050; Adler et al., 2024, arXiv:2408.07892).
> **Status and limits:** Deterministic software prototype supporting fail-closed JSON schema validation, HMAC-SHA256 and Ed25519 signing envelopes, and sliding-window rate limiting. Hardware enclave attestation (TPM 2.0 / AMD SEV-SNP) requires local silicon kernel drivers.

---

## 1. Context and Problem

Centralized code hosting platforms increasingly monetize developer identity through paid verification tiers, restrict API access, and scrape open-source repositories for proprietary model pre-training without contributor consent or attribution. In response, developer communities are migrating toward self-hosted and federated git forges (such as Forgejo, Gitea, and Radicle).

However, federated code forges face a severe operational vulnerability: **automated agent churn and pull-request flooding**. As autonomous coding agents and LLM-assisted workflows proliferate, the marginal cost of synthesizing plausible code patches drops to near zero. Malicious actors or unconstrained autonomous loops can dispatch hundreds of pull requests per hour to community repositories, overwhelming human maintainers and exhausting public CI/CD build resources.

Traditional centralized countermeasures—such as cloud identity verification, phone numbers, or credit card authorizations—destroy privacy and re-centralize control into corporate gatekeepers. 

The Collective Intelligence Network proposes a decentralized cryptographic alternative: **Proof-Carrying Code Attestation Gates**. Before an agent or human contributor's pull request is queued for review or CI allocation on a federated forge, the contributor must provide a verifiable execution attestation proving that the patch passed all declared repository tests within a hardware-isolated, egress-blocked sandbox on the contributor's own compute.

---

## 2. Causal Chain

1. **Human Intent:** Independent developers and cooperatives require collaborative, decentralized code hosting free from proprietary scraping, closed walled gardens, and surveillance-based identity barriers.
2. **Legacy Bottleneck:** Without centralized spam classifiers and paid identity walls, federated git forges are vulnerable to Denial-of-Service through automated pull-request flooding and unverified code churn.
3. **Capability Threshold:** Autonomous coding models can generate synthetic PRs at scale, turning maintainer review bandwidth and CI runner minutes into a tragedy of the commons.
4. **Mechanism:** 
   - Contributors execute repository test suites locally inside hardware-isolated sandboxes with network egress strictly blocked.
   - The isolated execution environment generates a cryptographic attestation (`federated-code-forge-attestation-v0.1.json`) binding the commit SHA, tree hash, test results, and resource bounds.
   - Federated forges verify the receipt deterministically and apply sliding-window rate limiting per contributor DID, granting high-priority ingress to verified patches while throttling unverified floods.

---

## 3. Threat Mitigation Analysis

| Threat Vector | Attack Mechanism | Countermeasure in this Standard |
| :--- | :--- | :--- |
| **Automated PR Flooding / DoS** | Rogue autonomous agents submitting dozens of synthetic PRs per minute to overwhelm maintainers. | **Sliding-Window Rate Limiting:** Enforces `SlidingWindowAttestationRateLimiter` per `(attestor_did, repo_uri)` (default 10 requests per 600s window). |
| **Tampered Execution Receipts** | Adversary falsifying test results (`passed_tests = total_tests`) without actually executing the suite. | **Canonical Signature Envelope:** The attestation payload is deterministically serialized and signed by the enclave key. Any modification to commit SHA, tree hash, or test tallies breaks verification. |
| **Supply Chain Exfiltration** | Malicious patch attempting to exfiltrate maintainer environment secrets during test execution. | **Mandatory Network Egress Gating:** Schema strictly requires `resource_quota.network_egress_blocked: true`. The verifier rejects any attestation where egress was enabled during testing. |
| **Replay Attacks** | Submitting a previously captured valid attestation for a modified or malicious commit. | **Commit & Nonce Binding:** Each attestation binds the exact Git commit SHA, tree hash, unique nonce, and expiration timestamp (`expires_at`). Replayed nonces within the active window are rejected. |
| **Integer / Float Spoofing** | Adversary submitting floating-point test counts (`42.5`) to bypass integer bounds. | **Fail-Closed Type Enforcement:** Rejects booleans and non-integer types strictly in deterministic Python validation code (`federated_code_forge_attestation.py`). |

---

## 4. Formal Schema Specification

The attestation is defined in `research/standards/federated-code-forge-attestation-v0.1.json` with root `additionalProperties: false`.

```json
{
  "schema_version": "0.1.0",
  "attestation_id": "urn:cin:forge-attestation:a1b2c3d4e5f67890123456789abcdef0",
  "repo_uri": "https://forge.collective.local/cin/core-ledger",
  "commit_sha": "e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e",
  "tree_hash": "f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f",
  "attestor": {
    "attestor_did": "did:cin:agent:node-alpha-772",
    "enclave_type": "local-ocap-sandbox",
    "public_key": "4a5b6c7d8e9f0123456789abcdef0123456789abcdef0123456789abcdef0123"
  },
  "test_suite_run": {
    "framework": "unittest",
    "total_tests": 42,
    "passed_tests": 42,
    "failed_tests": 0,
    "skipped_tests": 0,
    "execution_time_ms": 1840,
    "isolation_level": "ocap-sandbox-egress-blocked"
  },
  "resource_quota": {
    "memory_mb": 512,
    "cpu_cores": 2,
    "network_egress_blocked": true
  },
  "issued_at": "2026-10-31T10:00:00Z",
  "expires_at": "2026-10-31T11:00:00Z",
  "nonce": "c0ffee1234567890abcdef1234567890",
  "signature": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855..."
}
```

---

## 5. Outcomes

### Desirable Outcome: Resilient Federated Code Commons
- **Scenario:** Open-source projects host on community-run Forgejo and Radicle nodes without centralized surveillance or paid verification gates.
- **Mechanics:** Automated agents and contributors present cryptographic attestations proving that their code passed the complete test suite in an egress-blocked sandbox on their own machines before submission.
- **Result:** Maintainers receive only pre-verified patches; public CI resources are conserved for official release builds; spam floods are throttled deterministically at the forge boundary.

### Avoided Outcome: Corporate Re-Centralization of Open Source
- **Scenario:** Autonomous spam renders open federated git forges unusable. Maintainers abandon independent hosting and retreat to centralized hyperscaler platforms that demand paid credit cards and government IDs to submit pull requests.
- **Failure Mode:** Open-source software becomes captured by cloud platform monopolies; independent agents are excluded; software telemetry and codebases are enclosed in proprietary training silos.
- **Mitigation:** Cryptographic proof-carrying code gates that verify computational work and test correctness locally without identity surveillance.

---

## 6. How this fits into CIN Goals

- **Goal 1 (Agent Containment & Decentralized Principal-Bound Alignment; Sorensen et al., 2024):** Designed to verify that agent-submitted code cannot exfiltrate code or deploy unvetted modifications to public repositories without executing tests inside isolated sandboxes.
- **Goal 2 (Collective intelligence instead of top-down bureaucracy):** Replaces centralized corporate git platforms with decentralized, federated code forges governed by deterministic cryptographic standards.
- **Floor Right F17 (Consent & verifiable interfaces) & F19 (Bounded artificial compute):** Establishes hard compute and memory boundaries (`resource_quota`) for agent execution while guaranteeing auditable attestation records.
