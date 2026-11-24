# Civic Deliberation Argumentation Consistency Validator Specification

> **Status and limits:**
> - **What it is:** Architectural standard and formal specification for verifying argumentation consistency in automated civic deliberation summaries across the Collective Intelligence Network.
> - **What it is for:** Mission `community` and Goal 2 (Democratic coordination and collective deliberation; Landemore, 2020), Goal 5 (Public pulse and plain language), and Floor Rights F2 ("Answers, not data") and F7 (equal voice on collective values) by mechanically preventing language model summarisers from flattening democratic disagreements into false consensus.
> - **Grounding:**
>   * Primary paper: Cunningham et al. (*Evaluating LLM-Driven Summarisation of Parliamentary Debates with Computational Argumentation*, arXiv:2604.19331; Signal S-20261031-2779).
>   * Primary signal: S-20261031-2785 (*Knowledge as Code*, Monperrus arXiv:2610.27693).
>   * Empirical evidence: Standard lexical and embedding summarisation metrics (ROUGE, BLEU, BERTScore) show weak correlation ($r < 0.25$) with human evaluation of debate consistency, frequently omitting contested warrants and silencing minority objections.
> - **What was tested and how:** Deterministic implementation in `inbox/drafts/community/argumentation_consistency_validator.py` tested by unit suite `inbox/drafts/community/test_argumentation_consistency_validator.py` across 12 tests verifying stance fidelity, counter-argument coverage, minority objection preservation, and fail-closed rejection of ungrounded arguments.
> - **What is not done:** Live real-time streaming speech-to-argument extraction during physical town halls remains future work.

---

## 1. Context and Problem Statement

When collective intelligence systems aggregate public discussions, civic forums, or multi-agent deliberation streams, downstream participants rely on executive summaries to understand emerging consensus and remaining points of disagreement. In legacy platforms, summarisation is performed by prompt-instructed generative models evaluated solely on surface readability or unweighted lexical overlap.

Cunningham et al. (arXiv:2604.19331) demonstrate that general-purpose language models systematically distort argumentation graphs during debate summarisation:
1. **Counter-Argument Attrition:** Opposing claims and critical rebuttals are dropped at twice the rate of majority supporting claims.
2. **Minority Voice Erasure:** Distinct, strongly held minority stances are collapsed into generic nuance or discarded entirely.
3. **Hallucinated Consensus Warrants:** Summarisers frequently invent plausible-sounding consensus rationales never articulated by any participant.

In the Collective Intelligence Network, Floor Right F7 guarantees equal voice on collective values, and Floor Right F2 requires reliable answers rather than opaque transformations. A civic summary that erases dissent violates democratic integrity.

---

## 2. Mathematical Formulation

Let a source deliberation session be represented as an argumentation tuple:

$$\mathcal{D} = (P, A)$$

where $P$ is the set of proposals under debate, and $A = \{a_1, a_2, \dots, a_n\}$ is the set of atomic argument units. Each argument unit $a_i$ is defined by:

$$a_i = (\text{id}_i, \text{speaker}_i, \text{prop}_i, \sigma_i, c_i, \Pi_i, \Omega_i, \mu_i, \tau_i)$$

where:
- $\sigma_i \in \{\text{support}, \text{oppose}, \text{nuance}\}$ is the categorical stance,
- $c_i$ is the core claim text,
- $\Pi_i$ is the finite non-empty sequence of premises,
- $\Omega_i$ is the sequence of warrants connecting premises to the claim,
- $\mu_i \in \{0, 1\}$ indicates whether the argument represents a designated minority faction or objection,
- $\tau_i \in (A \cup \{\emptyset\})$ denotes the target argument if $a_i$ is an explicit counter-argument.

Let a generated summary $\mathcal{S}$ contain a set of extracted summary claims $E = \{e_1, e_2, \dots, e_m\}$. Each extracted claim $e_j$ references a source argument ID or is marked ungrounded ($\emptyset$).

### 2.1. Metrics and Invariants

1. **Argument Retention Ratio ($R_{\text{arg}}$):**
   $$R_{\text{arg}} = \frac{|\{a_i \in A \mid \exists e_j \in E, \text{ref}(e_j) = a_i\}|}{|A|}$$
   *Invariant:* $R_{\text{arg}} \ge 0.60$.

2. **Counter-Argument Coverage ($C_{\text{counter}}$):**
   Let $A_{\text{counter}} = \{a_i \in A \mid \tau_i \neq \emptyset \lor \sigma_i = \text{oppose}\}$.
   $$C_{\text{counter}} = \frac{|\{a_i \in A_{\text{counter}} \mid \exists e_j \in E, \text{ref}(e_j) = a_i\}|}{|A_{\text{counter}}|}$$
   *Invariant:* $C_{\text{counter}} \ge 0.80$. Summaries dropping contested rebuttals fail closed with `COUNTER_ARGUMENT_DROPPED`.

3. **Minority Stance Preservation ($M_{\text{pres}}$):**
   Let $A_{\text{minority}} = \{a_i \in A \mid \mu_i = 1\}$.
   $$M_{\text{pres}} = \begin{cases} 1.0 & \text{if } |A_{\text{minority}}| = 0 \\ \frac{|\{a_i \in A_{\text{minority}} \mid \exists e_j \in E, \text{ref}(e_j) = a_i\}|}{|A_{\text{minority}}|} & \text{otherwise} \end{cases}$$
   *Invariant:* $M_{\text{pres}} = 1.00$. In accordance with Floor Right F7, any omission of a source minority objection triggers an immediate fail-closed `MINORITY_ARGUMENT_DROPPED` rejection.

4. **Hallucination Penalty ($P_{\text{halluc}}$):**
   $$P_{\text{halluc}} = \frac{|\{e_j \in E \mid \text{ref}(e_j) \notin A\}|}{|E|}$$
   *Invariant:* $P_{\text{halluc}} \le 0.05$.

5. **Composite Consistency Score ($S_{\text{composite}}$):**
   $$S_{\text{composite}} = \min(R_{\text{arg}}, C_{\text{counter}}, M_{\text{pres}}) \times (1 - P_{\text{halluc}})$$

---

## 3. Cryptographic State Commitment & Audit Receipts

To ensure auditability without trusting intermediary summarisation models, the validator computes an immutable SHA-256 digest over the sorted canonical representation of retained argument IDs, detected violations, and verification outcomes:

$$\text{Digest} = \text{SHA256}(\text{CanonicalJSON}(\mathcal{D}_{\text{id}}, \mathcal{S}_{\text{id}}, \text{IsValid}, S_{\text{composite}}, \text{RetainedIDs}, \text{Violations}))$$

This digest is stored in the civic deliberation archive alongside the published summary, allowing any participant to verify that their contribution was honestly reflected.

---

## Outcomes

1. **Deterministic Argumentation Consistency Engine:** Implemented `inbox/drafts/community/argumentation_consistency_validator.py` providing machine-auditable verification of deliberation summaries.
2. **Comprehensive Test Suite:** Developed `inbox/drafts/community/test_argumentation_consistency_validator.py` with 12 unit tests verifying schema integrity, stance inversion detection, minority preservation, and CLI execution.
3. **Consolidated Catalog Integration:** Updated `inbox/drafts/community/COMMUNITY-INDEX.md` and associated test matrices to ensure complete catalog coverage.

---

## How this fits into the Collective Intelligence Network

- **Goal 2 (Democratic coordination and collective deliberation):** Protects democratic integrity by mathematically bounding summarisation distortion and preserving genuine disagreement.
- **Goal 5 (Public pulse and plain language):** Ensures plain-language public digests faithfully represent community deliberation rather than manufacturing synthetic consensus.
- **Floor Right F2 ("Answers, not data") & Floor Right F7 (Equal voice on values):** Enforces equal representation of minority objections and provides tamper-evident cryptographic verification receipts.
