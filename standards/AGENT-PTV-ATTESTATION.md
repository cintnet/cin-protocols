# Specification: Prove-Transform-Verify (PTV) Hardware-Anchored Attestation for Autonomous AI Agents

> **Document Class:** Standards Specification and Conformance Architecture  
> **Schema Reference:** `research/standards/agent-ptv-attestation-v0.1.json`  
> **Conformance Validator:** `research/standards/agent_ptv_attestation.py`  
> **Primary Standards Grounding:** IETF Internet-Draft `draft-anandakrishnan-rats-ptv-agent-identity` (Damodaran, September 2026), IETF Remote ATtestation procedureS (RATS) Architecture (RFC 9334), and Entity Attestation Token (RFC 9711).  
> **Missions:** Standards for Agent Contracts (`loop/missions/standards.md`), Policy and Regulatory Watch (`loop/missions/policy.md`), Containment (`loop/missions/containment.md`).  
> **Floor Rights Grounding:** Floor Right F1 ("Ownership": sovereign personal control over execution boundaries and secrets), Floor Right F2 ("Answers, not data"), Floor Right F17 (consent for anything placed in a person's interface), Floor Right F19 ("No force": bounded compute).

---

## 1. Executive Summary & Problem Context

As autonomous artificial intelligence agents increasingly execute consequential operations across distributed networks—such as managing personal financial records, invoking medical prior authorization APIs, and collaborating across multi-agent workflows—counterparties require cryptographic proof that an agent is operating on an authorized, untampered runtime.

Traditional software attestation mechanisms suffer from two fatal failure modes in agentic environments:
1. **Model Weight and Context Exposure:** Verifying an agent's code integrity often forces the operator to disclose proprietary neural network weights or sensitive user prompt context to external verifiers, violating personal privacy and intellectual property boundaries.
2. **Conflation of Identity with Behavior:** Many legacy proposals attempt to bind behavioral predictability to cryptographic keys. However, an authentic cryptographic key only proves the origin and hardware container of an execution; it cannot guarantee that a non-deterministic generative model will never hallucinate or deviate from instructions.

The **Prove-Transform-Verify (PTV) Protocol** (`draft-anandakrishnan-rats-ptv-agent-identity`) resolves these challenges by providing a lightweight request-response attestation layer over the IETF RATS architecture (RFC 9334) and Entity Attestation Token (RFC 9711). Under PTV, an agent proves at exercise time that it is bound to an enrolled hardware attestation key and an authorized model configuration digest, without leaking underlying model parameters or user inputs.

---

## 2. The PTV Protocol Architecture

The PTV lifecycle comprises three distinct phases executed at tool invocation or session handshake:

```
[ Relying Party / Verifier ]                    [ Agent / Edge Enclave ]
             |                                             |
             | ---- 1. Challenge Nonce (Replay Gate) ----> |
             |                                             |
             |                                    [ Phase 1: PROVE ]
             |                                    Generate local hardware attestation
             |                                    (TPM2 / SEV-SNP / Nitro)
             |                                             |
             |                                    [ Phase 2: TRANSFORM ]
             |                                    Map raw measurements to zero-knowledge
             |                                    proof digest & EAT claims
             |                                             |
             | <--- 2. Attestation Record (VERIFY) ------- |
             |                                             |
    [ Phase 3: VERIFY ]                                    |
    Validate nonce match,                                  |
    temporal validity window,                              |
    and trusted hardware anchor                            |
```

### 2.1 Phase 1: PROVE (Local Enclave Binding)
The agent runtime queries its hardware security module or confidential computing enclave (such as AMD SEV-SNP, AWS Nitro Enclaves, or local Object-Capability enclave). The enclave generates an attestation measurement binding the active execution process to an asymmetric Attestation Key (AK).

### 2.2 Phase 2: TRANSFORM (Zero-Knowledge Privacy Preservation)
Rather than transmitting raw hardware measurement logs (which can reveal device topology or proprietary memory offsets), the local attestation engine maps the raw report into an Entity Attestation Token (EAT) claim set. The configuration digest commits cryptographically to the model identifier and configuration parameters ($H(\text{model} \parallel \text{config})$) without disclosing the underlying weights.

### 2.3 Phase 3: VERIFY (Exercise-Time Decoupled Check)
The relying party verifies the attestation record fail-closed:
1. **Replay Defense:** The `challenge_nonce` in the record must match the exact random nonce issued for the active exercise window.
2. **Temporal Boundedness:** The current UTC timestamp must fall within `[issued_at, expires_at)`.
3. **Anchor Validation:** The `attestation_key_fingerprint` must resolve to an enrolled, non-revoked hardware root.

---

## 3. Threat Model and Boundary Invariants

The PTV protocol enforces strict separation between identity integrity and behavioral evaluation:

| Threat Vector | PTV Mitigation Mechanism |
| :--- | :--- |
| **THREAT-01: Replay of Intercepted Attestation** | Strict nonce binding (`challenge_nonce`) and narrow temporal validity windows prevent replay across execution sessions. |
| **THREAT-02: Model Weight Extraction via Audit** | Verifiers inspect only the cryptographic `configuration_digest` and `zero_knowledge_proof_digest`; raw neural weights remain inside the local isolated memory space. |
| **THREAT-03: Hypervisor / Host Memory Tampering** | Hardware-enforced enclaves (SEV-SNP, TPM2, Nitro) cryptographically sign state measurements, detecting host-level tampering. |
| **THREAT-04: Ambient Credential Exfiltration** | Attestation tokens carry short-lived scopes and are isolated from ambient host session tokens. |

---

## 4. Outcomes

### Desired Outcomes
- **Verifiable Execution Integrity:** Relying parties (e.g. healthcare clinics, credit unions, data cooperatives) verify that an incoming agent request was synthesized by an authorized personal twin running inside a hardware-isolated sandbox, rejecting unauthorized automated scrapers.
- **Strict Weight & Prompt Confidentiality:** Personal models and sensitive medical or financial prompts execute without third-party telemetry exposure.
- **Standards Interoperability:** Full alignment with IETF RATS (RFC 9334) and EAT (RFC 9711) enables drop-in integration with emerging open standards across the Two Internets boundary.

### Undesired Outcomes to Avoid
- **Behavioral Guarantee Conflation:** Relying parties must not treat a valid PTV attestation as a guarantee against model hallucination or reasoning errors; behavioral containment must be governed by separate, task-specific contract validators.
- **Hardware Vendor Lock-In:** Attestation verifiers must support open hardware-enclave profiles rather than restricting enrollment to a single proprietary cloud vendor.

---

## 5. How this fits into the Collective Intelligence Network

The PTV hardware attestation standard operationalizes key architectural pillars of the CIN:
- **Two Internets & Local Sandbox Execution (Thesis 01 / Vol 01):** Validates local hardware execution boundaries before establishing IETF QUIC peer-to-peer tunnels.
- **Human-Bound Personal Agents (Thesis 04 / Vol 04):** Enables personal twins to prove their hardware binding and provenance to external cooperatives without leaking personal training LoRA adapters or private memory.
- **Cross-Boundary Policy & Standards (Thesis 03 / Vol 03):** Bridges voluntary lab safety commitments with enforceable, machine-checkable cryptographic standards for cross-organization agent contracts.

---

## 6. Status and Limits

### What Was Tested
- Conformance test suite `research/standards/tests/test_agent_ptv_attestation.py` validates fail-closed schema conformance across 12 test cases.
- Validates rejection of unknown root properties, inverted timestamps, expired tokens, nonce mismatches, non-VERIFY phases, and untrusted key fingerprints.
- Verified example payload `research/standards/examples/agent-ptv-attestation-example.json` passes schema validation cleanly.

### What Is Not Done
- This specification defines the JSON/EAT data structures and validation logic; production hardware enclave drivers (e.g., `/dev/sev`, `/dev/tpmrm0`) and CBOR/COSE wire serialization require platform-specific driver bindings during integration.
- Hardware attestation key enrollment and certificate revocation registries must be maintained by participating domain cooperatives.
