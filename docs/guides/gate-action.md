<!--
SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
SPDX-License-Identifier: Apache-2.0
-->
# The comparison gate

Issues #50 and #53. `aureproof compare` decides whether configuration B is
non-inferior to configuration A under a frozen Decision Protocol, using two saved
run bundles (`aureproof run`). It never calls a provider, so it is safe in ordinary
and fork CI.

```bash
uv run --extra sign aureproof compare \
  --protocol protocol.json --a bundles/a --b bundles/b \
  --require-signature --report report.md
```

| Exit | Outcome | Meaning |
| --- | --- | --- |
| 0 | pass | The exact CI's lower bound is above −margin |
| 1 | fail | The CI's upper bound is below −margin |
| 3 | inconclusive | Anything else: the CI spans −margin, fewer clusters than the protocol's alpha allows, findings left unadjudicated, or a vacuous pass (A's yields are so low that B would pass even with yield 0 everywhere) |
| 2 | not comparable | The evidence does not belong to the protocol; no decision is made |

## Fail closed

Before any statistic, each bundle must validate (V1–V6) and, with
`--require-signature`, be signed by the project's `sign.yml` workflow. It must also
match the protocol:

- the sealed protocol is the same document;
- the sealed system is configuration A (or B);
- every cohort task has the THR that the protocol names by digest;
- every task and variant has exactly the protocol's repetitions, and nothing else;
- every planned episode names this protocol and system;
- the bundle re-scores byte for byte.

Any mismatch lists every problem and exits 2.

## What the report shows

The report shows the protocol, both system identities, the repetitions, the margin and
alpha, and a per-cluster table of confirmed and submitted counts, unresolved findings
and the exact difference. It also gives the exact two-sided p, the test-inversion CI,
and Wilson intervals per configuration. Quality metrics and operational ones
(completion, refusals, infrastructure failures) are listed separately for each
configuration. The uncertainty covers the fixed suite's clusters only. It is not a claim
about a wider population of tasks.

## The GitHub Action

The repository root is a composite Action:

```yaml
- uses: bhargavchintam/aureproof@<release tag or commit SHA>
  id: gate
  with:
    protocol: eval/protocol.json
    a: eval/bundles/a
    b: eval/bundles/b
    # require-signature: "true"   (default)
    # inconclusive: fail          (default) or neutral
- run: echo "${{ steps.gate.outputs.outcome }}"
```

`outcome` is `pass`, `fail`, `inconclusive` or `error`. The step fails on `fail` and
`error`, and on `inconclusive` unless `inconclusive: neutral`. Neutral exits 0 with
a warning, and the output still says `inconclusive`, never `pass`. The report is added
to the job summary.

## Examples

`examples/gate/{pass,fail,inconclusive}` hold a protocol and two bundles each, over
eight synthetic clusters. Their outcomes, mean differences and exact p-values were
worked out by hand (`expected.json`). `scripts/make_gate_examples.py --check`
regenerates them. The `Gate examples` workflow runs the Action on all three, on
`inconclusive: neutral`, and on a swapped pair that is not comparable. The
examples are unsigned, so that workflow sets `require-signature: "false"`.
