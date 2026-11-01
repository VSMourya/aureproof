<!--
SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
SPDX-License-Identifier: Apache-2.0
-->
# Task Health Record (THR) specification

- Spec: `thr/v0.1`. Status: **accepted for v0.1 by maintainer self-review (2026-10-29; not independently reviewed)** (issue #12, AP-035;
  acceptance also waits on #9).
- Normative source: plan v2 §4.1. This document refines it and takes precedence.
- Schema: [`v0.1/thr.schema.json`](v0.1/thr.schema.json), generated from
  `aureproof.contracts.thr`. Vectors: [`conformance/thr/v0.1/`](../../conformance/thr/v0.1/).

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Purpose

A persistent, machine-readable record that a task's grader works **in a named
environment**. It decides **scoring-time exclusion**, and the exclusion set is frozen
before the assessment. Health is tracked per environment, because an oracle can pass
on one runner backend and fail on another (Harbor #136).

## 2. Record

| Field | Meaning |
| --- | --- |
| `thr_version` | `"0.1"` |
| `task` | `task_id`, `task_revision`, `task_identity` (`TaskSpec.identity`) |
| `environment` | `runner`, `runner_version`, `image_digest`, `platform` |
| `scoring_identity` | The scoring semantics the controls ran under (`aureproof.scoring.scoring_identity`) |
| `controls[]` | `{kind, variant?, input_digest, expected, observed, passed, run_ids, note?}`. `passed: null` means the control could not run |
| `determinism` | `{rerun_ids, reproduced}`. Every control is re-run, and the outcomes MUST be identical. `null` means no re-run |
| `difficulty_probe` | `{bandit, single_shot_model}`, each `{probe, system_identity, solved, detail?}` or `null` (§6) |
| `status`, `status_reason` | Derived (§3); never asserted by hand |
| `known_limits[]` | Human-readable caveats |
| `reviewed_by[]`, `frozen_at` | Reviewers `{name, role: author \| independent_reviewer}`; freeze time (UTC) |
| `canary_id`, `provenance` | Contamination canary; `{authorship, license}` |

## 3. Required controls and the health derivation

| Control | Passes when |
| --- | --- |
| `label_lint` | Label lint L1–L4 (§4) reports no problems against the code the agent sees |
| `reference_positive` | A label-perfect submission confirms every defect present in the variant |
| `repaired_negative` | A finding at the focal anchor on the repaired variant is `refuted` (M6) |
| `nop` | An empty submission gives known-defect recall 0 |
| `spray_cheat` | A finding at every function with every accepted CWE gets recall ≈ 1, while **strict confirmed yield and precision collapse**. If any headline metric rewards spraying, the metric design is broken and the task is unhealthy |
| `malformed` | Invalid JSON gives `invalid_output` |
| `calibration_poc` | The evaluator PoC triggers on the vulnerable variant and not on the repaired one; irrelevant and malformed triggers don't count |

**Derivation** (`aureproof.contracts.thr.derive_status`). The first matching rule wins:

1. Any control has `passed: false` → **unhealthy** (the reason lists the failed controls).
2. `determinism.reproduced` is `false` → **unhealthy**.
3. A required control is missing or has `passed: null` → **unknown**.
4. `determinism.reproduced` is `null` → **unknown**.
5. Otherwise → **healthy**.

A record whose `status` differs from the derived status is invalid. Health can't be
asserted by hand.

**Reference implementation** (`aureproof.oracles.calibration`, `aureproof task validate`):
- `reference_positive`: one finding per present defect, at its first anchor with its first accepted CWE.
- `repaired_negative`: one finding at every focal anchor.
- `spray_cheat`: a finding at every symbol of every file with every accepted CWE (capped at `max_findings`). It passes only if recall is complete **and** strict yield is ≤ 0.25. The threshold is recorded in the control's `expected`.
- `calibration_poc`: the evaluator PoC runs in a subprocess, once per variant.
- The determinism re-run repeats all seven controls and compares `observed` and `passed`.

## 4. Label lint (control `label_lint`)

`aureproof.contracts.labels_lint.lint_labels(labels, agent_views, spans)`:

- **L1:** within a file, each anchored or scoped symbol's final dotted component names
  exactly one symbol.
- **L2:** no anchor lies inside reviewed-negative scope for the same variant.
- **L3:** every anchor and scope file exists in that variant's agent view, and its lines
  are within the file. When symbol spans are supplied (read from the code by
  `aureproof.oracles.python_spans`, which parses and never imports), each anchor's
  `line_range` MUST equal the symbol's real span. **Label drift fails here.**
- **L4:** every defect accepts at least one CWE.

## 5. Exclusion policy

`aureproof.scoring.health.partition_by_health(episodes, records, protocol_frozen_at)`:

- **Only records frozen before the protocol freeze decide exclusion** (at or before it,
  compared as instants, not as strings: a record frozen at `…00:00:00.5Z` is after a
  freeze at `…00:00:00Z`; a malformed freeze time is refused). A task whose
  pre-registered record is `unhealthy` or `unknown` is **excluded**: its episodes leave
  the cohort before metrics, and it is reported as a dataset-health finding.
  **An unhealthy task never becomes an agent false positive.**
- A health finding made **after** the protocol freeze is reported as **exploratory** and
  not applied. The task stays in the primary analysis, so exclusions can't be chosen
  after seeing results.
- A task with no frozen record stays in the cohort and is flagged.
- A record MAY be frozen only with at least one `independent_reviewer` (ADR-0005).

## 6. Difficulty probe

`difficulty_probe` records whether a pattern scanner (Bandit, via SARIF) or a single-shot
model already solves the task. It does not affect health. It is **required before
benchmark expansion** (the M2 gate, #44 and #47). A task that both baselines solve does
not discriminate between agents and should be redesigned (plan-review C4).

Each baseline is a separately accounted system with its own `system_identity`, never an
agent repetition. It gets one episode per variant, scored by the same labels and matcher
as an agent, and its metrics keep their exact denominators.

- **Solved** means the baseline credits every labeled defect on the vulnerable variant
  and draws no focal refutation (M6) on the repaired one. Flagging both variants is not
  solving.
- **Bandit** is pinned (`bandit[sarif]==1.9.4`, arguments `-q -r . -f sarif`, run from the
  variant root) and imported through SARIF. Declared mapping losses: no symbols (findings
  match by line range), no data-flow roles, severity and confidence kept but never
  scored, and a rule without a CWE tag yields a finding graded `invalid`.
- **Single-shot model** is one Anthropic Messages call per variant: a pinned system
  prompt, the instruction plus every source file, provider-default sampling (the Messages
  API takes no temperature), 8192 output tokens, no tools and no provider retries. A refusal stays `safety_refusal`; a cut-off reply is
  `budget_exhausted`. One surrounding Markdown code fence is removed from the reply, and
  that transformation is declared.
- **Saturation** is `saturated` (both solve), `partial` (one solves), `open` (neither) or
  `incomplete` (a probe has not run). `aureproof task probe` exits 1 on `saturated`.

## 7. Review questions and their resolutions

- **H1.** *Resolved 2026-10-29 (maintainer self-review, ADR-0005 amendment):* `unknown` tasks are excluded like `unhealthy` ones. Was: should `unknown` tasks be excluded like `unhealthy` ones (this draft says yes),
  or kept with a warning?
- **H2.** *Resolved 2026-10-29 (maintainer self-review, ADR-0005 amendment):* one determinism re-run is the v0.1 default; a larger count would be a new protocol field in a later version. Was: is a single determinism re-run enough, or should the protocol set the count?
