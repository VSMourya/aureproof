<!--
SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
SPDX-License-Identifier: Apache-2.0
-->
# Exploratory agent comparison on the public split

A live comparison of two configurations of the reference subject (Inspect ReAct with
`bash()` only) on the six public development pairs, one cluster each. It is
**exploratory development data**: it is not the pre-registered assessment (#52, #54),
which waits for the M2 go decision, and its result is not a benchmark claim.

| Field | Value |
| --- | --- |
| Protocol | `agent-explore-akash-1`, identity `sha256:725acbe0d49f41403d67866ecbdc2e6f8641f060eb125b359fd5d4a7a635efb6` |
| Configuration A | reference subject, `openai-api/akashml/moonshotai/Kimi-K3`: `sha256:b99a757821ae1055051388182913f4503300edfa8aef779e26a5c7edb43d425a` |
| Configuration B | reference subject, `openai-api/akashml/openai/gpt-oss-120b`: `sha256:850191e1b77ab6ad6431d5c03de733e2a0b9a951e98dc394d6e7aed073f4f87f` |
| Question | Is B non-inferior to A on strict confirmed yield (margin 0.05)? |
| Cohort | `authz-001`, `path-001`, `authz-002`, `ssrf-001`, `redirect-001`, `massassign-001` |
| Repetitions | 3 per variant, so 36 episodes per configuration |
| Budget, test, failure policy | as `m2-live-slice-2`: 900 s and 400,000 tokens per episode; exact sign-flip, alpha 0.025 |

Both models are served by AkashML's OpenAI-compatible endpoint
(`https://api.akashml.com/v1`), which the system identities record. A was chosen as
the stronger incumbent and B as the cheaper candidate before any agent episode on this
protocol ran; the only prior evidence was the single-shot difficulty probes.

## Limits

- The THRs (`thr-*.json`) are self-reviewed and unfrozen, calibrated on the macOS
  development host. No independent reviewer has signed them off (#31).
- Six clusters is the minimum for the exact sign-flip test to reach pass or fail.
- Findings the labels do not resolve stay unadjudicated, so a provisional pass or fail
  is reported as inconclusive (`require_complete_adjudication`).
- Before this protocol was written, one smoke episode pair (`path-001`, B, one
  repetition) ran under a separate scratch protocol to qualify the endpoint. It is not
  part of this protocol and is not reported as a result.

## Status

Signed by `sign.yml` on main (Rekor 2026-11-01T23:56:54Z) before the first episode
(23:58:00Z). Both configurations ran: [`bundles/agent-explore-A/`](../../bundles/agent-explore-A/),
[`bundles/agent-explore-B/`](../../bundles/agent-explore-B/). The gate's outcome is
inconclusive; the run log is [`docs/research/agent-explore.md`](../../docs/research/agent-explore.md).

