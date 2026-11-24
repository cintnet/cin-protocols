# Survey of Emerging Agent Identity, Delegation, and Authorization Standards

> **Note:**
> - **What it is:** A structured research survey of emerging identity, delegation, and capability standards for autonomous software agents, evaluating their applicability to bilateral agent-to-agent contracts.
> - **What it is for:** Mission `standards` (`loop/missions/standards.md`). Informs schema designs for bilateral twin consent grants and runtime contracts (Specification 03).
> - **What is uncertain:** Draft standards (such as IETF WIMSE) remain under active development. Final cryptographic binding formats (JWT vs. Biscuit vs. W3C Verifiable Credentials) remain open research questions.
> - **Scope boundary:** Offline comparative analysis and architectural evaluation; does not modify live runtime gate code.

---

## 1. Motivation and the Agent Identity Problem

As autonomous software agents execute multi-step workflows, tool calls, and cross-boundary delegations without continuous human prompting, classical identity architectures face structural limitations.

Recent foundational analysis ([arXiv:2604.23280](https://arxiv.org/abs/2604.23280), "AI Identity: Standards, Gaps, and Research Directions for AI Agents") demonstrates that adapting human-centric identity models to software agents fails due to fundamental asymmetries across four core dimensions:

1. **Substrate:** Human identity is rooted in biological continuity and physical personhood. Agent identity exists across heterogeneous runtime environments, transient compute processes, and distributed software models.
2. **Persistence:** Humans maintain persistent life histories and legal memory. Agents are frequently ephemeral, stateless, or reconstituted across separate invocations.
3. **Verifiability:** Human authorization relies on subjective intent, signatures, and physical credentials. Agent verification requires cryptographic execution proofs, deterministic runtime gates, and tamper-evident execution histories.
4. **Legal Standing:** Humans possess innate legal rights, duties, and personal liability. Agents possess no independent legal personality; their actions must resolve to identifiable human principals or legal entities.

---

## 2. Survey of Candidate Standards and Protocols

| Standard / Protocol | Sponsoring Body / Source | Primary Mechanism | Delegation & Attenuation Model | Primary Source |
| --- | --- | --- | --- | --- |
| **OAuth 2.0 RAR** | IETF (RFC 9396) | Rich Authorization Requests using fine-grained JSON authorization details | Centralized token issuance via Authorization Server; static authorization objects | [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html) |
| **OAuth 2.0 Token Exchange** | IETF (RFC 8693) | Token exchange specifying delegation and impersonation semantics via `act` (Actor) claims | Linear delegation chaining; relies on trust in intermediate token issuers | [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html) |
| **WIMSE** | IETF Working Group | Workload Identity in Multi-Service Environments; service identity tokens | Workload-to-workload mutual authentication; scoped token exchange | [IETF WIMSE](https://datatracker.ietf.org/wg/wimse/about/) |
| **Model Context Protocol (MCP)** | Linux Foundation AAIF / Anthropic | JSON-RPC protocol standardizing context, tools, and prompts for AI clients | Transport protocol; lacks built-in public-key agent identity or verifiable delegation | [AAIF / MCP](https://modelcontextprotocol.io/) |
| **Agent Identity Protocol (AIP)** | Academic (arXiv:2603.24775) | Invocation-Bound Capability Tokens (IBCTs) using Biscuit Datalog policies | Public-key verifiable delegation with holder-side monotonic attenuation and provenance records | [arXiv:2603.24775](https://arxiv.org/abs/2603.24775) |
| **W3C Verifiable Credentials 2.0** | W3C Standard | Cryptographically signed credential assertions anchored to Decentralized Identifiers (DIDs) | Cryptographic claim presentation; primarily static assertions rather than ephemeral single-use execution budgets | [W3C VC 2.0](https://www.w3.org/TR/vc-data-model-2.0/) |
| **SPIFFE / SPIRE** | CNCF Graduated Standard | Software package and workload identity using X.509 SVIDs | Workload attestation in managed infrastructure; platform-dependent, not client-to-client | [SPIFFE](https://spiffe.io/) |
| **MIGT (Machine Identity Governance Taxonomy)** | Andrew Kurtz & Klaudia Krawiecka (arXiv:2604.06148) | 37 risk sub-categories across 8 domains; cross-jurisdictional AI identity governance | Cross-domain lifecycle governance; foreign state actor threat model and credential proliferation controls | [arXiv:2604.06148](https://arxiv.org/abs/2604.06148) |
| **Eunomia / MCP Data Space Mediation** | Jaime Alonso Ruiz et al. (arXiv:2609.30341) | Architectural mediation layer translating data space capabilities into structured MCP tools | Policy-driven data access; preserves governance constraints across organizational boundaries without modifying data space backends | [arXiv:2609.30341](https://arxiv.org/abs/2609.30341) |
| **WebContract / Web$hell** | Academic (arXiv:2610.13416) | Standardized schemas compiling web pages into addressable objects (address, value, association) | Persistent, stateful web interaction schemas without unmetered browser execution | [arXiv:2610.13416](https://arxiv.org/abs/2610.13416) |

---

## 3. Eight Structural Governance Gaps

Analysis across surveyed standards identifies eight structural gaps where existing technical infrastructure does not yet fully resolve autonomous agent governance ([arXiv:2604.23280](https://arxiv.org/abs/2604.23280), [arXiv:2604.06148](https://arxiv.org/abs/2604.06148), [arXiv:2609.30341](https://arxiv.org/abs/2609.30341), [arXiv:2610.13416](https://arxiv.org/abs/2610.13416)):

1. **Semantic Intent Verification:** Existing protocols verify cryptographic key possession or bearer token validity, but cannot verify whether a generated action aligns with the human principal's actual semantic intent.
2. **Recursive Delegation Accountability:** As an agent delegates a task to secondary subagents, authority attenuation must be strictly non-increasing (monotonic). Chained tokens often lose provenance context or allow scope expansion across heterogeneous tool boundaries.
3. **Agent Identity Integrity:** Fast-moving agent runtimes lack standardized methods to guarantee that code, tool configurations, and prompt parameters have not been tampered with between token issuance and tool invocation.
4. **Governance Opacity and Enforcement:** Centralized authorization servers create single points of failure and custody concentration. Decentralized multi-agent systems require bilateral verification without trusting an external intermediary.
5. **Operational Sustainability:** High-overhead cryptographic handshake protocols introduce latency bottlenecks, while short-lived tokens risk premature expiration during long-running tasks.
6. **Machine-to-Human Identity Proliferation:** In production environments, non-human identities (agents, service accounts, ephemeral tokens) outnumber human identities by ratios exceeding 80 to 1 ([arXiv:2604.06148](https://arxiv.org/abs/2604.06148)). Standard human-sponsored IAM models degrade under machine-speed credential rotation, leaving orphaned or overprivileged machine credentials vulnerable to exploitation.
7. **Cross-Boundary Policy Mismatch in Sovereign Data Spaces:** Integrating probabilistic agent tool invocation with deterministic, policy-governed data sharing requires protocol-level mediation layers that validate schema constraints before execution ([arXiv:2609.30341](https://arxiv.org/abs/2609.30341)).
8. **Unconstrained Web DOM & Tool Action Surfaces:** Arbitrary browser automation permits unauthorized script injection, hidden telemetry, and prompt-injected redirection. Safe web interaction requires structured compilation of pages into addressable information and action objects under explicit contracts rather than open browser execution ([arXiv:2610.13416](https://arxiv.org/abs/2610.13416), [arXiv:2609.30325](https://arxiv.org/abs/2609.30325)).

---

## 4. Architectural Alignment for Personal Agent Runtimes

To address these gaps without requiring a central custody server or compromising user data sovereignty, the CIN runtime contracts (Specification 03) would benefit from adopting the following architectural design rules:

### 4.1 Bilateral Peer-to-Peer Consent Contracts
Rather than directing all authorization decisions through a centralized third-party OAuth provider, personal agents should form bilateral, machine-checkable consent contracts. The originating principal's local twin issues scoped, time-bounded grants directly to the recipient agent (as exemplified in `agent-consent-grant-v0.1.json`).

### 4.2 Monotonic Scope Attenuation
Borrowing the formal attenuation principles of Biscuit tokens and AIP (arXiv:2603.24775), any sub-delegation token must represent a strict mathematical subset of its parent token:
- Permitted actions must be a non-increasing subset.
- Authorized data categories must be non-increasing.
- Computational or financial budgets must strictly decrease or remain equal.
Privilege escalation across delegation chains must be deterministically rejected by fail-closed schema validators.

### 4.3 Deterministic Boundary Gates over Language Model Self-Restraint
Grounded in empirical findings on agent out-of-scope continuation ([arXiv:2609.38411](https://arxiv.org/abs/2609.38411)), runtime safety boundaries must never rely on prompt instructions or model self-policing. Tool invocations, filesystem access, and outbound network packets must be intercepted by a deterministic local gatekeeper that enforces explicit contract parameters.

### 4.4 Tamper-Evident Hash-Chained Audit Trails
To resolve recursive accountability without leaking sensitive personal payload data, audit records must employ deterministic SHA-256 hash chaining (`prev_record_hash`) and content digests (as specified in the draft schema `agent-audit-record-v0.1.json`), creating a verifiable, reconstructable ledger of actions.

### 4.5 Architectural Mediation for Sovereign Data Boundaries
Following the architectural mediation model demonstrated by the Eunomia Agent ([arXiv:2609.30341](https://arxiv.org/abs/2609.30341)), personal agents should interact with external institutional data repositories and peer co-operatives through schema-driven tool adapters. The mediation layer translates data space capabilities into verifiable contract schemas while ensuring local governance policies and data sovereignty invariants are enforced before requests leave the local device boundary.

### 4.6 Explicit Non-Human Machine Identity Lifecycle
In alignment with the Machine Identity Governance Taxonomy (MIGT; [arXiv:2604.06148](https://arxiv.org/abs/2604.06148)), runtime contracts must treat sub-agent machine identities as distinct from human principals. Each delegated token or sub-agent execution context must have an explicit parent binding, ephemeral lifetime, automated revocation path, and continuous watcher oversight.

### 4.7 Addressable Web Contracts and Credential Isolation
Grounded in the Web$hell architecture ([arXiv:2610.13416](https://arxiv.org/abs/2610.13416)), when an agent is authorized to interact with external web services, it must execute against an explicit `AgentWebContract` (`agent-web-contract-v0.1.json`). The runtime broker compiles external pages into addressable units of information and action (`address`, `value`, `association`), strictly disallowing direct credential persistence, wildcard domain egress, or cross-site tracking cookies.

Crucially, offline schema verification only guarantees structural contract conformance; it does not replace active runtime egress gating or network-level firewalling. Furthermore, filtering HTTP verbs (e.g. allowing `GET`, `HEAD`, `POST` while rejecting `PUT`, `DELETE`) does not prove or guarantee read-only or side-effect-free behavior, as remote services can trigger state changes, logging, or telemetry even on standard `GET` requests. Full containment requires deterministic host-level mediation.

---

## 5. Status and Limits

- **What was surveyed:** Ten candidate standards and protocols evaluated across four identity dimensions (substrate, persistence, verifiability, legal standing) and eight structural governance gaps, citing primary specifications (RFC 9396, RFC 8693, W3C VC 2.0, SPIFFE) and recent literature (arXiv:2604.23280, arXiv:2603.24775, arXiv:2609.38411, arXiv:2604.06148, arXiv:2609.30341, arXiv:2610.13416).
- **What was tested:** Verified document syntax, table alignment (5 columns), file size constraints (<350 lines), verified primary URLs, and consistency with existing draft schemas in `research/standards/` (`agent-consent-grant-v0.1.json`, `agent-delegation-token-v0.1.json`, `agent-audit-record-v0.1.json`, `agent-web-contract-v0.1.json`).
- **What is not done:**
  - This survey presents research analysis and architectural options; it does not implement wire protocol parsers.
  - Integration of cryptographic signature verification into live broker components remains future planned work.
  - Does not constitute legal advice or formal industry standards ratification.
