<!--
SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
SPDX-License-Identifier: Apache-2.0
-->
# v0.1.0 release acceptance

Issue #66. One row per gate in plan v2 §14, with the evidence that exists and what is
still missing. Status as of **29 October 2026**, after the `0.1.0a1` alpha (`153ecff`). A gate is **met**
only when its evidence passes today; **partly** means the machinery exists and passes,
but an item that needs a person or the release itself is outstanding; **not yet** means
the gate cannot pass until that item is done. Material failures block the tag.

The maintainer is the reviewer and self-review is disclosed (ADR-0005 amendment), so
no row below counts as independently reviewed.

| Gate | Status | Evidence | Still needed |
| --- | --- | --- | --- |
| Scope honesty | met | README "Scope and limits" and "How it compares"; the cited landscape in [`plan-review.md`](plan-review.md); [`scope.md`](scope.md) | — |
| Spec integrity | met | THR, Bundle and Decision schemas in `specs/*/v0.1/` with vectors in `conformance/`; `tests/test_compatibility.py` rejects unknown versions; accepted by maintainer self-review on 2026-10-29 | — |
| **Task health** | not yet | Every task is HEALTHY with all controls, `spray_cheat` and `nop` included, and a determinism rerun (`aureproof task validate`, run in CI on Linux) | A frozen THR needs an independent reviewer (#31); the healthy cohort is frozen with the assessment protocol (#52) |
| **Discrimination** | met (drafts) | [`research/difficulty-probe.md`](research/difficulty-probe.md): neither Bandit nor any single-shot model saturates any of the six public pairs, and the private eight are recorded in the assessment repository. Seven open models, three runs each (2026-11-01), separate the models (0 to 15 of 18 runs solved), but Kimi-K3 alone solves 15 of 18 | Accepting the pack needs the M2 go decision (#47); harder pairs should be judged on several runs of a strong model |
| Grade separation | met | Controller-side matcher (ADR-0004); `test_bridge_qualification.py` label and canary isolation (T-INFO-1); T-TAMP-1 tests | — |
| Artifact safety | met | Size, depth, count and path limits (#40), stated in every instruction; `test_each_instruction_states_the_scoring_limits`; fuzzed parsers (`fuzz/`) | — |
| Inference boundary | met | [`bridge-coverage.md`](bridge-coverage.md): no provider key in the sandbox, hosted tools withheld, budgets enforced, the Claude Code binary pinned (T-TAMP-4); Docker lane on the Linux host | — |
| Metric correctness | met | Golden cohort C-01 counted independently; the CI Phase-1 gate reproduces all 11 metrics from a fresh install | — |
| Failure accounting | met | One disposition per episode (D1–D8); refusals separate; [`research/m2-live-slice.md`](research/m2-live-slice.md) shows each attempt and its outcome | — |
| Evidence completeness | met | Missing mandatory evidence refuses to seal; a run with an `evidence_incomplete` episode seals only as `incomplete` and gates refuse it (`tests/bundle/test_completeness.py`; decision of 2026-10-29) | — |
| **Signed evidence** | partly | `sign.yml` signs protocols and bundles; the M2 protocol and live bundle are signed and verify offline from a fresh clone | Verification by an independent third party (#57) |
| Retry correctness | met | Aureproof-owned attempts in the journal (ADR-0003); runner retries off and detected (`config:runner_retried_sample`) | — |
| Offline reproduction | partly | Fresh-install Phase-1 gate in CI; the live slice bundle re-scores offline with no key | An independent person reproduces a table (#57) |
| Comparison validity | partly | `aureproof compare` and the Action: exact sign-flip test, at least 6 clusters, fail-closed linkage, three hand-worked examples | The signed assessment protocol and the assessment itself (#52, #54), after go |
| External portability | met | Claude Code 2.1.287 ran live through the documented contract (#48, the M2 slice) | — |
| Recovery | met | [`fault-qualification.md`](fault-qualification.md): restart, interrupted calls, duplicate delivery and partial writes, each with a test | — |
| **Supply chain** | partly | `0.1.0a1` is on [PyPI](https://pypi.org/p/aureproof/0.1.0a1) through Trusted Publishing with a PEP 740 attestation from `release.yml`; it installs fresh and passes the Phase-1 gate; its CycloneDX SBOM is attached to the GitHub release; from the next release `release.yml` also attaches Sigstore bundles for every file; Scorecard 7.8 with Fuzzing | Scorecard ≥ 8 (Code-Review approvals, the CII badge, project age; Signed-Releases counts after the next release) |
| **Licensing** | met | `reuse lint` passes; [`fixtures/DATASET_CARD.md`](../fixtures/DATASET_CARD.md) and Croissant RAI fields, "evaluation only, not for training" | — |
| **Responsible use** | met | `RESPONSIBLE_USE.md`, `SECURITY.md`, private vulnerability reporting enabled, gitleaks clean on every PR | — |
| **Benchmark rigor** | met | [`ABC.md`](ABC.md) published | The BetterBench request is tracked separately (#61) |
| **Demand** | not yet | — | One design partner runs task validation or the gate on their own logs (#62); the interviews (#6) for the M2 decision |
| External review | not yet | — | A second engineer reproduces a table and reviews selected verdicts (#57) |
| Compatibility | met | [`specs/COMPATIBILITY.md`](../specs/COMPATIBILITY.md) pinned combinations, kept equal to the real pins by `tests/test_release_metadata.py` | — |

## What blocks the tag

Everything in the "Still needed" column comes down to the following people's actions,
listed in [`maintainer-actions.md`](maintainer-actions.md):

1. **The maintainer:** the M2 go decision after the interviews (#6, #47). Go
   unblocks the pilot (#52) and the assessment (#54).
2. **A second person:** an independent reviewer to freeze THRs (#31), an independent
   reproduction (#57) and a design partner (#62).
3. **Time and the next release:** Scorecard's Maintained check needs 90 days of
   history; Signed-Releases counts once a release carries signature files.

The spec self-reviews were recorded on 2026-10-29, and the `0.1.0a1` alpha (#37) was published
the same day: <https://pypi.org/p/aureproof/0.1.0a1>.
