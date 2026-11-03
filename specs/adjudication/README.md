<!--
SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
SPDX-License-Identifier: Apache-2.0
-->
# Adjudication v0.1

Status: draft for the independent reviewer (#31). Issue #51 (AP-038); plan §5.7;
[`scoring.md`](../scoring/scoring.md) §7. Code: `aureproof.contracts.adjudication`,
`aureproof.scoring.adjudication`, `aureproof adjudicate`.

## 1. Purpose

Unresolved findings are not false alarms. A finding the labels cannot decide
(`unresolved:class_mismatch`, M3, or `unresolved:out_of_scope`, M8) is decided by a
person, and that decision is recorded evidence. The matcher's verdict is never
edited, and neither is the sealed bundle.

## 2. Record

One JSON object per line (JSONL), in canonical JSON:

| Field | Meaning |
| --- | --- |
| `adjudication_version` | `"0.1"` |
| `bundle_seal` | `sha256:` of the sealed bundle's `seal.intoto.json`. A record applies to that bundle only |
| `finding` | `{episode_id, finding_index}`: the finding's position in that episode's captured submission |
| `original_verdict` | The matcher's verdict, which must be `unresolved:*` |
| `adjudicator` | Who decided |
| `role` | `primary`, `second` (an independent second opinion) or `resolution` (settles a disagreement) |
| `decision` | `confirmed`, `refuted` or `label_change` |
| `rationale` | Why |
| `evidence_refs` | What was consulted (paths, digests, links) |
| `timestamp` | RFC 3339 UTC |
| `dataset_revision_before`, `dataset_revision_after` | Equal unless `decision` is `label_change`, which MUST name a new revision |

A record that names another bundle, a finding that is not unresolved there, or the
wrong original verdict is refused. In a comparison, the evidence is then not
comparable.

## 3. Final decision per finding

Records are append-only. Re-adjudicating means adding a record. For each finding:

1. For each adjudicator and role, the latest record (by timestamp) counts. Timestamps
   are compared as instants, not as strings: `…12:00:00.5Z` is later than `…12:00:00Z`.
2. If there is a `resolution` record, the latest one decides.
3. Otherwise, if the `primary` and `second` records agree, that is the decision. If
   they disagree, the finding stays **undecided** until a resolution is recorded.
4. A `label_change` is decided, but under the current dataset revision the finding
   stays unresolved. Every result is re-scored under the new revision as well
   (scoring.md §7). Nothing is relabeled in place.

## 4. Effect on metrics and the gate

A decided finding counts under its adjudicated verdict: `confirmed` raises confirmed
findings and `refuted` raises refuted ones. Submitted findings are unchanged. Every
other unresolved finding stays unresolved. In `aureproof compare`, any finding still
unresolved keeps a decisive result provisional and the outcome inconclusive
(specs/decision §5). Incomplete or unequal adjudication can therefore never produce
a pass.

## 5. Agreement

At least 20% of queued findings need both a `primary` and a `second` record (plan
§5.7). The report gives the count, the agreements, and Cohen's κ over those pairs.
κ is undefined, with the reason stated, when no finding has two adjudicators or
when chance agreement is 1 (every decision in one category).

## 6. Commands

```bash
aureproof adjudicate queue  BUNDLE [--adjudications FILE]
aureproof adjudicate record BUNDLE --episode E --finding N --decision D \
    --adjudicator NAME --rationale TEXT --revision R [--role ROLE] \
    [--revision-after R2] [--evidence REF] --out FILE
aureproof adjudicate report BUNDLE --adjudications FILE [--json]
aureproof compare ... --adjudications-a FILE --adjudications-b FILE
```

`report` exits 1 while any finding is undecided or the double-adjudication coverage is
below 20%.

## 7. Open questions for the reviewer

- **A1.** Should a `label_change` block the gate until the new revision has been
  re-scored, as it does now (it stays unresolved), or should the comparison run
  under the new revision automatically?
- **A2.** Is κ over the three decision categories the right statistic, or should
  agreement be reported per verdict kind?
