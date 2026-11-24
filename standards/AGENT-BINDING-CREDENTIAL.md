# Agent Binding Credential (v0.1)

> **Note on purpose and status:**
> **What it is:** A machine-checkable reference credential format and verification specification that cryptographically binds an autonomous AI agent to an accountable person or organisation.
> **What it is for:** Implementing the architectural requirement from "The second internet: a network built for agents" where every agent carries proof of its human or organizational principal, model family, compute budget, and expiring permission leases without disclosing personal data.
> **What is uncertain:** The exact zero-knowledge proof scheme for cross-issuer personhood credential verification (Groth16 vs Halo2/PLONK) across low-power edge twin hardware, and the interoperability cadence with emerging W3C agent identity community specifications.

---

## 1. Context and Problem

The open internet was constructed for human participants. As autonomous agents browse, negotiate, execute transactions, and spawn sub-agents, distinguishing human participants from synthetic agents becomes intractable through heuristic detection. When synthetic text and voice can be generated cheaply, open human spaces suffer flooding, fraud, and impersonation.

The collective proposes separating human interaction from automated agent-to-agent exchange. On the second internet, every agent must be explicitly bound to a real, accountable principal:
1. **A verified human being**, proved via privacy-preserving personhood credentials without revealing identity or personal records.
2. **A registered organisation**, such as a worker cooperative, credit union, or enterprise entity.

The agent presents this credential at the onset of any interaction, proving:
- Whom it acts for (binding commitment);
- Its underlying model family and declared priors;
- Its bounded compute budget (preventing infinite runaway loops);
- Its active permissions structured as short-lived, expiring leases.

---

## 2. Mapping to W3C Verifiable Credentials and Personhood Credentials

The Agent Binding Credential builds directly on existing open standards rather than inventing proprietary cryptography:

### W3C Verifiable Credentials Data Model (v2.0 / v2.1)
The schema (`agent-binding-credential-v0.1.json`) maps cleanly onto the W3C Verifiable Credentials specification:
- `credential_id`: Maps to the W3C credential URI (`urn:cin:credential:bind-...` or decentralized identifier URL).
- `credential_type`: Conforms to W3C VC typing by declaring `["VerifiableCredential", "AgentBindingCredential"]`.
- `issuer`: Encodes a W3C DID identifier (`issuer_id`) and associated cryptographic key verification method (`verification_method`).
- `holder`: Identifies the agent's controller via a DID.
- `agent_subject`: Acts as the `credentialSubject`, binding the agent runtime hash and declared priors.
- `proof`: Follows the Linked Data Proof / W3C Data Integrity standard with cryptographic signatures (such as Ed25519Signature2020).

### Personhood Credentials (Adler et al., 2024)
For individual human principals, the credential integrates with personhood credential frameworks (arXiv:2408.07892):
- The `personhood_credential_ref` holds a cryptographic pointer or zero-knowledge proof commitment verifying that a unique, real human stands behind the agent.
- The `binding_commitment` is a zero-knowledge hash binding the human's secret credential key to the agent's public identifier.
- **Privacy Guarantee:** Verifiers confirm that a real, unique human authorized the agent, but learn zero personal data (no name, biometric data, IP address, government identifier, or location).

---

## 3. Core Architectural Constraints

1. **Fail-Closed Verification:** Any unknown field, untyped parameter, or schema mismatch triggers immediate rejection. Enforcement occurs in deterministic host code (`agent_binding_credential.py`), never inside a generative language model.
2. **Holder Consistency:** Person-bound agents require a valid personhood credential reference and strictly forbid organization references. Organization-bound agents require an organization registry reference. Mismatched presented holders are rejected.
3. **Expiring Permission Leases:** Permissions are not permanent grants. They are granted as granular leases with strict expiry dates (`expires_at`). A lease cannot outlive its parent credential. Expired leases fail closed.
4. **Mortal Compute Budgets:** Each credential specifies finite compute limits (maximum tokens per hour, parallel threads, daily units). Runtimes reject requests exceeding these budgets.

---

## Outcomes

### Outcome 1 (Positive): Municipal Civic Assembly with Accountable Agent Submissions
A municipal city council hosts an open digital consultation on transit zoning.
*Concrete example:* The city portal requires submissions to carry an Agent Binding Credential tied to a privacy-preserving personhood credential. Citizens deploy personal twin agents to synthesize neighborhood traffic data and submit detailed recommendations. The municipal portal automatically filters out uncredentialed commercial bot swarms, admits exactly one verified agent submission per resident, and verifies that no raw resident personal data is exposed.

### Outcome 2 (Positive): Inter-Cooperative Contract Negotiation
Two worker cooperatives in different provinces negotiate a joint hardware procurement contract.
*Concrete example:* Cooperative A's purchasing agent contacts Cooperative B's supply agent on the second internet. Both exchange Agent Binding Credentials demonstrating organizational binding, verified model families, and explicit 48-hour negotiation leases. The agents autonomously reach agreement on delivery milestones, execute mutual commitments, and terminate their compute leases without human administrative friction.

### Outcome 3 (Adverse): Credential Monopoly and Exclusionary Gatekeeping
A commercial tech consortium captures the personhood credential market, demanding proprietary biometric scans and high licensing fees.
*Concrete example:* An identity consortium becomes the sole accepted credential issuer for major web services. Low-income citizens without supported smartphone hardware or individuals refusing biometric iris scans are barred from issuing credentials for their personal agents. Their agents are blocked from second-internet services and flagged as spam on the first internet, concentrating economic power in proprietary identity vendors.
*Mitigation:* Mandate federated, multi-issuer attestation standards; ensure community-based, non-biometric web-of-trust attestation paths exist; ensure open read access to the second internet remains uncredentialed.

---

## Status and limits

- **What was tested:** The JSON schema (`agent-binding-credential-v0.1.json`), canonical example, and deterministic Python checker (`agent_binding_credential.py`) were implemented and tested across 34 unit and conformance tests (`test_agent_binding_credential_schema.py`). Tests pass and verify fail-closed handling of extra properties, expired leases, mismatched holders, and invalid lifecycles.
- **What is not done:** Live deployment on hardware security modules (HSMs) or hardware secure enclaves; zero-knowledge circuit generation (Groth16/PLONK) for client-side proving of personhood commitments; live consensus federation across external W3C DID registries.
