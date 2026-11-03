<!--
SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
SPDX-License-Identifier: Apache-2.0
-->
# Decision Protocol specification

- Spec: `decision/v0.1`. Status: **accepted for v0.1 by maintainer self-review (2026-10-29; not independently reviewed)** (issue #14, AP-037;
  acceptance also waits on #9).
- Normative source: plan v2 §4.3 and §6. This document refines them and takes precedence.
- Schemas: [`v0.1/protocol.schema.json`](v0.1/protocol.schema.json) and
  [`v0.1/decision.schema.json`](v0.1/decision.schema.json), generated from
  `aureproof.contracts.decision`. Implementation: `aureproof.stats` (pure). Vectors:
  [`conformance/decision/v0.1/vectors.json`](../../conformance/decision/v0.1/vectors.json).

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Purpose

A pre-registered description of an A/B comparison with a three-way outcome: **pass,
fail or inconclusive**. Its identity is the digest of its content. From M2 (#46), its
signature MUST predate the first assessment episode, so a claim can't be chosen after
seeing the data.

## 2. Protocol

| Field | Content |
| --- | --- |
| `estimand` | Metric **strict confirmed yield** (ADR-0006); contrast B − A; summary = mean of cluster-level differences; `undefined_yield`: `zero` (default) or `exclude_cluster` |
| `cohort[]` | `{task_identity, thr_digest, cluster_id}`: the frozen healthy cohort, the frozen Task Health Records it relies on, and the cluster map |
| `configurations` | `A` and `B` as `SystemSpec` identities; they MUST differ |
| `repetitions`, `budget` | Fixed repetitions per episode; per-episode budget (ADR-0007) |
| `failure_policy` | Fixed in v0.1: infra failure → re-run as a new attempt, then report; missing evidence blocks sealing; refusals reported separately, never misses; budget, agent-error and invalid-output episodes graded |
| `test` | `exact_sign_flip`, CI by `test_inversion`, `alpha` per side (default **0.025**, a 95% two-sided interval) |
| `margin` | δ ≥ 0, a non-inferiority margin on the primary metric |
| `stopping` | Fixed repetitions, no peeking; exploratory analyses listed in advance |
| `require_complete_adjudication` | Always `true` in v0.1 |
| `pilot_mde` | Minimum detectable effect from the pilot (#52) |
| `guardrails[]` | Optional `{metric, margin}`; v0.1 allows `known_defect_recall` once, with its own δ ≥ 0 (rule 6). An empty list is not serialized, so a protocol without guardrails keeps the identity it had before the field existed |

## 3. Cluster table

For each cluster, pool the graded episodes of each configuration, giving
`confirmed/submitted` per side. That is the cluster's yield (a cluster with
`submitted = 0` follows `undefined_yield`). The cluster difference is
`d_c = yield_B − yield_A`, computed **exactly** as a rational. The Decision reports
every row. Each row also carries known-defect recall support per side (`credited`,
`positives`: defects the matcher credited and defects present, over graded episodes),
which a guardrail uses; it follows the same `undefined_yield` policy when `positives = 0`.

## 4. Test and interval

- **Exact paired sign-flip.** Under the null, each cluster difference is equally likely
  to have either sign. All 2ᵏ assignments are enumerated (k ≤ 20).
- **Two-sided p-value** (at δ₀ = 0): the share of assignments with |Σ sᵢdᵢ| ≥ |Σdᵢ|.
- **Interval by test inversion.** For a hypothesized effect δ₀, flipping a set S of
  signs gives a sum at least as large as the observed one exactly when the mean of d over
  S is ≤ δ₀. So the one-sided p-value is (1 + #{non-empty S: mean_S(d) ≤ δ₀}) / 2ᵏ.
  With r = ⌊α·2ᵏ⌋, the bounds are the **r-th smallest** and **r-th largest** of the
  2ᵏ − 1 subset means.
- **If r = 0**, no finite bound exists. At α = 0.025 that holds exactly when **k < 6**,
  and the Decision reports that k clusters cannot reach a decisive outcome.
- **Wilson score intervals** for each configuration's pooled yield are reported
  alongside, at the same level.

## 5. Decision rule

With interval [L, U] and margin δ:

1. **pass** if L > −δ;
2. **fail** if U < −δ;
3. **inconclusive** otherwise. That includes an unbounded interval, and a bound exactly at −δ (the inequalities are strict).

δ is the decimal written in the protocol, compared as an exact rational: `0.05` is 1/20, not the nearest binary float.
4. **Incomplete adjudication:** if any unresolved finding remains, adjudicating it could move either yield. A decisive result is then recorded as `provisional_outcome`, and the `outcome` is **inconclusive**. An incomplete adjudication can never silently pass.
5. **Vacuous pass:** a pass MUST be one the data could have withheld. Recompute L with B's
   yield set to 0 in every cluster that entered the test (dᶜ = −aᶜ, where aᶜ is A's yield
   there). Each subset mean rises with every dᶜ, so this is B's worst case on those
   clusters. If that L is still > −δ, every possible B passes, and the result says
   nothing about B: the `provisional_outcome` is **pass** and the `outcome` is
   **inconclusive**. This happens when A's yields are too low for a regression to be
   measured, for example when both configurations submit nothing, as a broken runner or
   grader would. A fail can never be vacuous: with B's yield 1 everywhere, every dᶜ ≥ 0,
   so U ≥ 0 ≥ −δ. To claim that B beats a weak baseline, pre-register δ = 0 (vectors
   D-11 to D-15). Rule 4 is applied first.

6. **Guardrails:** strict confirmed yield is a precision, so volume cannot raise it, but
   restraint can. A B that reports only its surest finding, or nothing where A did well
   (under `exclude_cluster` those clusters leave the test), raises its yield while finding
   less. For each registered guardrail, the per-cluster difference of that metric gets the
   same exact test and interval (rules 1–3) against its own margin. The outcome is
   **fail** if the primary test or any guardrail fails, **pass** only if all pass, and
   **inconclusive** otherwise (an intersection–union test: a pass is still an α-level
   claim; a false fail can reach up to (1 + guardrails)·α). Recall counts defects the
   matcher credited, which adjudication does not change, so a guardrail fail is final
   while findings are unadjudicated (vectors G-01 to G-04). Rules 4 and 5 apply to the
   primary test before it is combined; a guardrail uses rules 1–3 only.

## 6. Review questions and their resolutions

- **G1.** *Resolved 2026-10-29 (maintainer self-review, ADR-0005 amendment):* yes, `undefined_yield = zero`. Was: is `undefined_yield = zero` the right default? An agent that submits nothing
  in a cluster earns 0 yield there.
- **G2.** *Resolved 2026-10-29 (maintainer self-review, ADR-0005 amendment):* no; the refusal-rate difference is reported beside the decision, not gated. Was: should the decision also gate on the refusal-rate difference? (v0.1 reports it
  alongside.)
