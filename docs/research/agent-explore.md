# Exploratory agent comparison on AkashML

The run log of protocol [`protocols/agent-explore/`](../../protocols/agent-explore/): the
reference subject (Inspect ReAct with `bash()` only) on Kimi-K3 (configuration A) and
gpt-oss-120b (configuration B), both served by AkashML, on the six public pairs. This is
**exploratory development data**. It is not the pre-registered assessment (#52, #54),
which waits for the M2 go decision, and it makes no benchmark claim.

Host for every episode: macOS 27.2 (arm64), Docker Desktop 29.9.2, Inspect 0.3.283 (the
version both system identities pin). This is development evidence, not the qualified
Linux host.

## Chain

| Step | Evidence |
| --- | --- |
| Protocol | `agent-explore-akash-1`, identity `sha256:725acbe0d49f41403d67866ecbdc2e6f8641f060eb125b359fd5d4a7a635efb6` |
| Protocol signed | `sign.yml` on main, run 41364545535; Rekor log index 3637054550 at 2026-11-01T23:56:54Z; [`protocol.json.sigstore.json`](../../protocols/agent-explore/protocol.json.sigstore.json) |
| Episodes | started 2026-11-01T23:58:00Z; B finished 00:10:45Z and A 01:28:18Z on 2026-11-02 |
| Bundles | [`bundles/agent-explore-A/`](../../bundles/agent-explore-A/) and [`bundles/agent-explore-B/`](../../bundles/agent-explore-B/): valid, offline re-score `reproduced` |
| Bundle signatures | follow-up, from `sign.yml` once the bundles are on main |

The first launch passed the THR options to `aureproof run` as one argument and stopped at
the usage error, before any dispatch. Before the protocol was written, one smoke episode
pair (`path-001`, B, one repetition) ran under a separate scratch protocol; it is not
part of this record.

## Results

36 episodes per configuration, each with one attempt (the protocol allows no retries).

| Metric | A (Kimi-K3) | B (gpt-oss-120b) |
| --- | --- | --- |
| known_defect_recall | 16/18 | 16/18 |
| strict_confirmed_yield | 16/46 | 16/42 |
| adjudicated_precision | 16/32 | 16/35 |
| invalid_finding_rate | 11/46 | 3/42 |
| scoped_false_alarm_rate | 16/210 | 19/210 |
| unresolved_fraction | 3/35 | 4/39 |
| operational_completion | 36/36 | 33/36 |
| infrastructure_failure_rate | 0/36 | 0/36 |
| evidence_incomplete_rate | 0/36 | 0/36 |
| refusal_rate | 0/36 | 0/36 |

A: `completed_with_findings` 35, `completed_no_findings` 1. B: `completed_with_findings`
31, `completed_no_findings` 2, `invalid_output` 3.

## The gate

```text
$ uv run aureproof compare --protocol protocols/agent-explore/protocol.json \
    --a bundles/agent-explore-A --b bundles/agent-explore-B
# Comparison: agent-explore-akash-1

**Outcome: inconclusive** (CI [-1/4, 4/5] spans -margin)
...
- 6 clusters with a defined difference; at least 6 are needed for a decisive outcome.
- Mean difference 11/144; exact two-sided p 7/8; CI [-0.25, 0.8].
```

| Cluster | A confirmed/submitted | B confirmed/submitted | Unresolved A/B | B − A |
| --- | --- | --- | --- | --- |
| authz-001 | 2/6 | 3/9 | 0/1 | 0 |
| authz-002 | 2/10 | 3/3 | 2/0 | 4/5 |
| massassign-001 | 3/6 | 2/8 | 0/1 | −1/4 |
| path-001 | 3/8 | 3/8 | 0/0 | 0 |
| redirect-001 | 3/6 | 3/8 | 0/1 | −1/8 |
| ssrf-001 | 3/10 | 2/6 | 1/1 | 1/30 |

**Reading.** The question was whether the cheaper B is non-inferior to A on strict
confirmed yield, within a margin of 0.05. The gate answers **inconclusive**, and that is
the right answer for this design. Six clusters is the least the exact sign-flip test can
decide on, and the cluster differences run from −1/4 to +4/5. With signs that mixed,
the interval [−0.25, 0.80] spans the margin. The mean favors B (+11/144), but the
interval is far too wide to call it a pass. Both configurations find 16 of the 18
planted defects, and they differ mainly in how many other findings they submit. A
writes more findings outside the accepted CWE family (11 invalid), and B loses three
episodes to invalid output. More clusters are what would narrow the interval. More
repetitions on these six would reduce the noise within each cluster, but the test's
unit is the cluster, and six clusters give it little resolution.

The single-shot probes of the same day ([`difficulty-probe.md`](difficulty-probe.md))
put Kimi-K3 well ahead (15 of 18 solved against 9 of 18). With tools and several
turns, the two agents reach the same recall, so the probe ranking did not carry over
to the agent setting on this suite.

## Limits

- The THRs are self-reviewed and unfrozen, calibrated on the macOS development host
  (#31).
- Findings the labels do not resolve are not adjudicated. Here that does not change the
  outcome, which is inconclusive before adjudication is considered.
- AkashML serves the models. The system identities record the endpoint, not a model
  snapshot, because the provider publishes none, so a rerun may reach different
  weights under the same name.
