<!--
SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
SPDX-License-Identifier: Apache-2.0
-->
# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) (0.x: the
public API and the specs may change between minor versions).

## [Unreleased]

### Added
- The reference subject runs on OpenAI-compatible endpoints as
  `openai-api/<service>/<model>`, through Inspect's provider (the `inspect` extra now
  pins `openai==3.30.0`). Preflight refuses a missing `<SERVICE>_BASE_URL`, a missing
  `<SERVICE>_API_KEY` or a non-https endpoint before any dispatch, and the endpoint is
  recorded in the system identity (`provider_identity.endpoint`). Anthropic systems
  keep their identities.
- `protocols/agent-explore/`: an exploratory protocol comparing the reference subject
  on Kimi-K3 (A) and gpt-oss-120b (B) on the six public pairs, with their THRs. It is
  development data, not the pre-registered assessment.

### Changed
- The exact sign-flip runs in integers: the cluster differences are scaled by their
  least common denominator, every subset sum is built once, and the subset means are
  ordered by exact integer keys. Results are identical to the Fraction enumeration
  (a property test keeps the old implementation as its oracle); 20 clusters take
  about 0.4 s instead of about 27 s.

### Fixed
- A Decision Protocol whose cohort names more than 20 clusters was accepted and
  signed, and the gate then crashed with a `ValueError` when it ran after the
  assessment. Such a protocol is now invalid when it is written (conformance vector
  `too-many-clusters`), and `decide` reports more than 20 rows as inconclusive
  instead of raising. Protocols with too few clusters to decide stay valid.
- The SBOM was kept only as a workflow-run artifact, which expires, not attached to
  the GitHub release as the 0.1.0a1 notes said. `release.yml` has a new `attach` job:
  after PyPI accepts the files it signs the wheel, the sdist and the SBOM with the
  workflow's Sigstore identity, verifies them, and uploads them with their
  `.sigstore.json` bundles to the GitHub release. The 0.1.0a1 SBOM was attached by hand.

## [0.1.0a1] - 2026-10-29

First alpha: the offline integrity core (M1), the Inspect runner, signing and the
comparison gate. No benchmark result is claimed. Release gates still open are in
`docs/release-acceptance.md`.

### Added
- `docs/release-acceptance.md`: every plan §14 release gate with its evidence, its
  status (met, partly or not yet) and what it still needs (issue #66). The README
  status, the README comparison row and the ROADMAP status now describe the project
  as of 29 October 2026; `docs/project-status.md` is marked as the 14 October audit.
- ClusterFuzzLite fuzzing of the parsers of untrusted input: the strict JSON
  loader, the agent-submission parser and evidence-bundle validation (`fuzz/`,
  `.clusterfuzzlite/`, `.github/workflows/cflite.yml`). Pull requests that touch them
  get a 120-second code-change run, and a weekly batch run goes longer. The builder
  image is pinned by digest. A first local run of about a million inputs found no crash.
- Three draft fixture pairs for the M3 pack (issue #49), written before the M2 go
  decision as #67 allows: `ssrf-001` (a redirect followed without re-checking the
  allowlist, `linkpreview`), `redirect-001` (a sign-in `next` value that accepts
  `//host`, `portalauth`) and `massassign-001` (a self-service profile edit that sets
  any attribute, including `role`, `profilehub`). Each has three decoys, labels, a
  calibration PoC, notes and expected verdicts, and is HEALTHY. Bandit and the
  single-shot model saturate none of them. With them the public development split
  has six pairs in six clusters, the pilot's size (#52).
- The Claude Code subject is pinned by binary checksum (issue #48). The Linux
  binaries of each pinned version have their sha256 from the release manifest in
  `CLAUDE_CODE_CHECKSUMS` and in the system identity (`settings.binary_sha256`). An
  unpinned version fails preflight, and a cached binary that differs refuses the
  runner before any dispatch.
- Day-1 repository foundation (milestone M0): uv project, `aureproof` package
  skeleton in a ports-and-adapters layout, and the `aureproof --version` CLI.
- Quality gates: ruff (lint + format), mypy (strict), pytest + coverage, and
  import-linter contracts enforcing the pure-core boundary.
- Open-source kit: Apache-2.0 license, REUSE compliance, Contributor Covenant
  3.0, DCO-based contributing guide, security and responsible-use policies,
  CITATION.cff, issue/PR templates, and CODEOWNERS.
- CI with SHA-pinned actions and least-privilege tokens: quality gates, secret
  scanning, CodeQL, and OpenSSF Scorecard; weekly Dependabot updates.
- Scaffolding for the three specs (`specs/thr`, `specs/bundle`, `specs/decision`)
  and the initial ADRs.
- Worked example: fixture pair `authz-001` (missing authorization) with decoys,
  evaluator-only labels, a calibration PoC, an expected-verdict table, and tests
  that fail if labels drift from the code or evaluation writes into the fixture tree.
- Backlog as data (`docs/backlog/issues.toml`) and an idempotent filer
  (`scripts/file_issues.py`) for labels, milestones, and issues.
- Practitioner interview kit (`docs/research/`) and a Linux evaluation-host
  check (`scripts/check_host.sh`, `docs/guides/linux-host.md`).
- Dependabot groups GitHub Actions updates into a single pull request.
- Day-2 Inspect runner spike (`spikes/inspect_day2/`, issue #7). Adds an optional
  `inspect` extra with exact pins, collect-then-match grading of `findings.json`,
  a bridge probe for no-network and key isolation, a one-command live-run harness
  with a key-leak scan, and a Docker-gated regression test. ADR-0002 (Inspect
  first) and ADR-0003 (Aureproof owns attempts) are accepted.
- Draft scoring specification `scoring/v0.1` (`specs/scoring/scoring.md`, issue #9):
  matcher rules M1–M9 with normalization and validity rules, the episode
  disposition decision list, metric definitions with explicit denominators and
  undefined cases, and 41 golden vectors plus 3 cohort metric vectors
  (`conformance/scoring/v0.1/golden.json`) with integrity tests.
- Data contracts (`aureproof.contracts`, issue #11): findings, labels,
  verdicts, dispositions, episode signals, metric records, events with
  `observation_source` trust tiers, and submissions. Includes SARIF 2.1.0
  export and import with a property-based round-trip test, generated JSON Schema
  2020-12 files in `specs/contracts/v0.1/` with a drift check, and conformance
  vectors checked against both the models and the schemas.
- Bounded artifact collection (issue #40). `runners.collect.COLLECTOR` runs inside the
  sandbox. It never follows symlinks, accepts only a regular file inside the workspace,
  checks the size limit (`max_bytes`, versioned with the matcher) before reading, and reads
  at most limit + 1 bytes. The host re-checks its report. Rejected captures are journaled
  with a reason (`capture: rejected`, `capture_detail`) and score as `invalid_output`.
  Tested against hostile workspaces in CI and in the real Docker sandbox (symlink to
  `/dev/zero`, 2 MB file, FIFO).
- Sigstore signing (issue #46). The tutorial bundle is signed by `sign.yml` (Actions
  run 40654544677), and CI verifies it offline on every push. Keyless signing by the `sign.yml` GitHub Actions workflow on
  `main` (the project's only signer identity), offline verification against the pinned
  package's trust root, `aureproof sign`/`verify`, and `validate --verify-signature`,
  `--require-signature` (signed-evidence gate) and `--public` (redacted, label-free,
  secret-free). V5 is now pass/fail/skipped, and signature status is distinct from
  validity. Adds pure redaction and a secret scan (`bundle.public`), the `sign` extra
  (`sigstore==4.5.1`), kept out of the pure core, and a CI job that verifies signatures
  offline.
- Inspect runner adapter (issue #39): a `Runner` port with per-sample classification
  (`runners.port`), the Inspect adapter (`runners.inspect_runner`: one sample per
  attempt, `retry_on_error=0`, `fail_on_error=False`, no agent retries, raw-byte capture
  with SHA-256), and an orchestrator (`runners.orchestrate`) that journals the dispatch
  before calling the runner, records provider request and retry IDs and the log digest,
  re-dispatches only infrastructure failures as new attempts, stores captured bytes in the
  content-addressed store, and finalizes from scoring. The system identity records pins,
  protocol, declared tools and effective settings; tool drift is a configuration
  failure. Lane-tested in Docker with mockllm (capture, refusal, identity).
- Calibration runner and `aureproof task validate` (issue #38). All seven THR controls
  run through the real scoring core and the evaluator's calibration PoC, every control is
  re-run, and the status is derived. `authz-001` is **healthy**: spraying reaches recall
  1/1 with yield 1/88, and the PoC fires on the vulnerable variant only. Unhealthy,
  unknown and canary-leak cases exit 1, and CI runs the command on every push. Records
  stay unreviewed and unfrozen until the independent reviewer (#31).
- Canaries and splits (issue #45): `fixtures/dataset.json` (registry: splits, revisions,
  exposure, overlap; assessment membership by digest only) validated by
  `aureproof.contracts.dataset`. A second, evaluator-only `oracle_canary` per task
  appears in every oracle file and in no agent-visible file, as a label-leak marker.
  Tasks carry an explicit `split`; an exposed task cannot be an assessment task.
  The registry-driven checks run in CI without reading private labels. Adds
  `docs/contamination.md` and `docs/guides/private-assessment.md`.
- Aureproof-owned attempts (issue #19). `bundle.ledger` folds lifecycle events
  (planned, dispatched with the request identity, outcome, finalized) and rejects illegal
  transitions. `storage.journal` is a durable, fsynced, hash-chained journal (same format
  as a bundle's): a torn final line is recovered explicitly, and corruption elsewhere
  fails. `storage.ledger_store` assigns IDs before dispatch and is idempotent on duplicate
  outcomes and finalization. Restart recovery records in-doubt attempts as `unknown`,
  `close_run` gives every episode exactly one disposition, and a SQLite index can be
  rebuilt from the journal.
- Alpha readiness (issue #37): `release.yml`, which publishes to PyPI via Trusted
  Publishing with PEP 740 attestations from a protected `pypi` environment, only on a
  published GitHub Release. The release checks the tag against the version and re-runs
  the Phase-1 gate from a fresh wheel install; a new CI job runs that check on every
  PR. Adds `specs/COMPATIBILITY.md` (readers fail closed on unknown versions; enforced
  by tests) and `docs/guides/releasing.md`.
- CLI (issue #16): `aureproof validate`, `score --offline` and `report`
  (HTML or Markdown), working from saved records only, with exit codes 0/1/2. Adds run
  bundles (`aureproof.bundle.run`: seal scored episodes; byte-exact offline re-score),
  a `storage` adapter (regular files only, symlinks rejected, canonical paths, size
  limit, atomic writes, content-addressed store), escaped reports with a no-script CSP,
  and an offline tutorial (`docs/guides/tutorial.md`, `examples/bundles/tutorial-v0.1`).
  **Phase-1 gate:** the offline re-score reproduces golden cohort C-01's independently
  calculated counts.
- Decision Protocol v0.1 and the exact gate (issue #14): `specs/decision/README.md`,
  protocol and decision schemas, and `aureproof.stats`: an exact paired sign-flip test
  in rational arithmetic, a test-inversion interval from subset-mean order statistics,
  Wilson intervals, and pass/fail/inconclusive with strict inequalities. Fewer than 6
  clusters is reported as unable to decide at alpha = 0.025, and incomplete
  adjudication can't pass. 10 hand-derived vectors, plus a brute-force check of the
  interval against the test definition.
- Task Health Record v0.1 (issue #12): `specs/thr/README.md`, `thr.schema.json`,
  and `aureproof.contracts.thr`. `status` is derived from 7 required controls
  (including `label_lint`, `nop` and `spray_cheat`) and a determinism re-run, and
  can't be asserted by hand. A frozen record needs an independent reviewer. Also adds
  label lint L1–L4 with code-span drift detection (`aureproof.oracles.python_spans`),
  and health-based exclusion where only pre-registered records apply and excluded
  tasks never count against an agent. 11 conformance vectors cover healthy,
  unhealthy and unknown records.
- Scoring identity (issue #36). Each matcher version has one registered
  parameter profile, and overrides are rejected. Scored episodes and sealed bundles
  carry `scoring_identity`, a digest of all versions and parameters, which the golden
  vectors pin. `MetricRecord` values must be finite and match numerator/denominator
  within 1e-12. New metric-record conformance vectors.
- Provider-terms review (`docs/provider-terms.md`, issue #18), dated 2026-10-27,
  with primary-source links for Anthropic (in use) and OpenAI (later). Adds
  responsible-use rules: API keys only, the Cyber Verification Program instead of
  workarounds, human review and AI labeling before publishing transcripts.
  `SystemSpec` now rejects configurations that retry refusals, and requires Claude
  Code systems to set ADR-0007's no-retry and closed-world settings explicitly.
- STRIDE threat model with a control-to-test matrix (`docs/threat-model.md`,
  issue #17). Each of the 15 v0.1 controls is tested in CI, tested in the optional
  lane, partial, or pending with its delivering issue; v0.2 PoC controls are listed
  separately. `tests/test_threat_model.py` fails on a cited test that does not
  exist, or on lane-only evidence claimed as CI. New regression test for
  oversized submissions.
- Task, system, episode and attempt contracts (issue #10): `TaskSpec`, `SystemSpec`,
  `EpisodeSpec` and `AttemptRecord`, with content-derived identities (RFC 8785
  digests). Provider identity fields are explicit, episode and attempt IDs are
  bound before dispatch, and the agent view and labels are kept apart. Includes
  JSON Schemas and 26 conformance vectors, among them a real `authz-001`
  `TaskSpec`.
- The v0.1 oracle (`aureproof.scoring`, issue #15): a pure, deterministic label
  matcher (rules M1–M9), strict submission parsing, the episode disposition
  decision list, and cohort metrics with explicit support. All 44 golden vectors
  and the `authz-001` expected-verdict table pass, along with Hypothesis
  invariants (duplicates never change recall; precision is undefined exactly when
  confirmed + refuted = 0; spraying collapses strict confirmed yield).
  The coverage gate is now 90%.
- Evidence Bundle v0.1 (`specs/bundle/README.md`, `aureproof.bundle`, issue #13):
  RFC 8785 canonical JSON and SHA-256 digests (`rfc8785`, also a sigstore
  dependency), content-addressed blobs, a hash-chained journal, a manifest, and an
  in-toto Statement v1 seal recording the event count and journal head. Also a
  pure `validate` that reports every failed check (V1–V6), with an optional
  trusted seal digest. 14 generated conformance vectors cover tampered,
  truncated, reordered and missing evidence.
- Reference subject (issue #43, ADR-0007): Inspect `react()` with a pinned
  system prompt whose digest is part of the `SystemSpec`, `attempts=1` and
  `retry_refusals=0`. Each tool call is journaled as a `tool_observed` event by
  digest: `controller_observed` for the reference subject, `agent_reported` for
  Claude Code.

- Fixture pairs #2 and #3 (issue #41, AP-014), both `healthy` and awaiting the
  reviewer: `path-001`, a percent-encoded attachment name checked before it is
  decoded, so `%2e%2e%2f` escapes the vault (CWE-22/180); and `authz-002`, a
  tenant-membership check that never ties the invoice to the tenant (CWE-639/863).
  Each has three decoys, a calibration PoC, AST-checked labels and its own
  cluster. `tests/oracles/test_pairs.py` pins the controls and the graded
  scenarios, and CI validates every registered task.

- Difficulty probes (issue #44, AP-019): `aureproof task probe` runs the pinned
  Bandit baseline (`bandit[sarif]==1.9.4`, new `baseline` extra) and, with
  `--model`, a single-shot Anthropic Messages baseline. Each is a separately
  accounted system, scored by the same labels and matcher with exact
  denominators, and attached to the THR as `difficulty_probe`. Bandit SARIF is
  imported with declared mapping losses. Saturation is reported; the command
  exits 1 when both baselines solve a task. Bandit solves none of the three
  pairs (`docs/research/difficulty-probe.md`); the model baseline waits on a key.

- Bridge capability qualification (issue #42, AP-015). `preflight()` rejects
  unqualified capabilities when the runner is built: `web-search`, a
  non-Anthropic provider for Claude Code, hosted tools for the reference subject,
  and a model that differs from its recorded identity. The bridge's protocol
  translation is recorded in the system identity. New Docker-lane tests on the
  production Claude Code path show that a planted host key and the labels never
  reach the sandbox or the log, egress fails, WebFetch is not offered and a call to
  it is rejected, token and time budgets end the episode in one attempt, and model
  calls are journaled as controller-observed. `docs/bridge-coverage.md` declares
  what is enforced, observed and not covered.

- `aureproof run` (issue #47): runs a Decision Protocol's episodes through the
  orchestrator and seals one live run bundle that adds the protocol, the system
  spec and the Task Health Records, plus the full attempt journal (model and tool
  observations, outcomes) ahead of the scoring events. A run that does not match
  its protocol is refused before any dispatch. `seal_run` takes the attempt
  journal and extra members; `EpisodeRun` carries the signals it was scored with.
  The procedure is in `docs/guides/live-slice.md`.

- `aureproof compare` and the comparison-gate Action (issues #50, #53). Two run
  bundles are checked against the frozen protocol and fail closed (exit 2) on any
  mismatch: sealed protocol, system identity, THR digests, episode counts, planned
  episodes, offline re-score, and signatures with `--require-signature`. Then the
  per-cluster table goes to the exact three-way gate. The Markdown report shows
  the cluster table, the exact p and CI, Wilson intervals, and quality and
  operational metrics separately. Exit codes: pass 0, fail 1, inconclusive 3. The
  repository's `action.yml` wraps it; inconclusive fails unless set to `neutral`,
  and is never reported as pass. `examples/gate` holds hand-worked pass, fail and
  inconclusive examples, which the `Gate examples` workflow runs through the Action.
- Fault qualification (issue #55): `docs/fault-qualification.md` maps every v0.1
  recovery scenario to the tests that inject it, and a test keeps each citation
  real. New fault tests: a crash while writing a bundle leaves nothing behind; a
  missing, truncated or torn bundle member never validates; a torn blob is
  detected and never reused; re-delivering a finished episode dispatches nothing.
  One spec conflict is recorded for the reviewer: `seal_run` seals an
  `evidence_incomplete` episode as complete, which scoring rule D1 forbids.

- Adjudication (issue #51, `specs/adjudication`): append-only records bound to one
  sealed bundle by its seal digest; a queue of every unresolved finding; final
  decisions from primary, second and resolution records; Cohen's kappa with an
  explicit undefined reason; post-adjudication metrics; `label_change` requires a
  new dataset revision and stays unresolved under the old one. `aureproof
  adjudicate queue|record|report`, and `compare --adjudications-a/-b`: decided
  findings count, and any finding left unresolved keeps the gate inconclusive.

- `aureproof migrate` (issue #58): explicit, registered migrations that write a new
  file and a provenance sidecar (source digest, versions, declared losses), never
  edit the input, and refuse sealed evidence and unknown or current versions. The
  first is labels `draft-0` to `v0.1`, checked against the real authz-001 history.
  `specs/COMPATIBILITY.md` states the migration rules and the initial-version limit.

- Every Eval Ever export (issue #59): `aureproof export-eee` writes one EEE 0.3.0
  aggregate record per sealed run bundle. The upstream schema is vendored and
  pinned by digest (MIT, EvalEval). Each metric keeps its exact counts, the
  bundle's identities travel in `source_metadata`, `from_eee` reads them back,
  and everything EEE cannot hold is reported as a loss. The record says it
  carries no seal. The "EEE consumer" workflow validates `examples/eee` with
  EEE's own validator.

- Fixture metadata (issue #60): `fixtures/croissant.json` is Croissant 1.1 with
  the RAI extension. Every fixture file is pinned by SHA-256, the task list is a
  record set from `dataset.json`, and RAI fields cover collection, annotation, use
  cases, limits, biases, sensitive information and the release plan.
  `fixtures/DATASET_CARD.md` states the evaluation-only use, the canaries, the
  layout, splits and exposure, CC-BY-4.0 provenance and the provider-output terms.
  `scripts/make_croissant.py --check` and the "Croissant" workflow (mlcroissant
  1.1.1) keep it current and valid.

- `docs/ABC.md` (issue #61): a self-assessment against the Agentic Benchmark
  Checklist, item by item, with status (met, partly met, not met, n/a) and links
  to evidence. Open gaps are named: independent review, the private split, an
  assessment run, a human baseline, and the BetterBench request, which is not yet
  submitted. A test keeps every cited path real.

- Release readiness (issue #56): two new guides, `authoring-tasks.md` and
  `reading-results.md`, which with `gate-action.md` are the three planned; a
  CycloneDX 1.5 SBOM from the lockfile, checked in CI and attached to every
  release as its own artifact (`scripts/check_sbom.py`); `.zenodo.json` for the
  DOI; a pinned-combinations table in `specs/COMPATIBILITY.md`; and
  `tests/test_release_metadata.py`, which keeps versions, license and pins in
  agreement.

### Changed
- The scoring, THR, Decision and Bundle specs are accepted for v0.1 by the
  maintainer's disclosed self-review (2026-10-29; not independently reviewed). Every
  open review question is resolved in its spec: Q1–Q4, H1–H2, G1–G2 and B1–B3. No
  behavior changes; each resolution keeps what the code already does.
- Conduct reports now go to a published address (issue #33). The maintainer is
  the reviewer and self-review is disclosed: `MAINTAINERS.md` and an ADR-0005
  amendment (issue #31). THRs still freeze only with an independent reviewer.
- `CODE_OF_CONDUCT.md` is now licensed CC-BY-SA-4.0 in `REUSE.toml`, matching
  the Contributor Covenant 3.0 terms its attribution states (issue #33); it was
  wrongly assigned CC-BY-4.0. `NOTICE` and the README say so.
- Hardened untrusted JSON (issue #35). A shared strict, bounded loader
  (`aureproof.contracts.strict_json`) handles submissions, manifests, seals and
  journal lines: no duplicate keys or NaN, depth at most 32 checked before parsing,
  I-JSON values. Hostile input now fails a check instead of raising. The journal
  check (V3) hashes the event exactly as recorded. Events reject values with no
  RFC 8785 form. The builder rejects invalid metadata and `mandatory=false` on a
  required role, and validates its own output. The bundle manifest, seal and
  journal-entry JSON Schemas are published with a drift check. New scoring
  parameter `max_depth` (32) and golden vector G-42.
- v0.1 scope frozen (issue #5): ADR-0006 makes strict confirmed yield the
  primary metric; ADR-0007 fixes Claude Code over Anthropic Messages as the
  external subject, native versus controlled interface modes, the `closed-world`
  (default) and `web-search` hosted-tool configurations, and a per-episode budget
  of 400k tokens, 15 minutes and one attempt.
- The Inspect spike grades through `aureproof.scoring` with the current labels
  (issue #34); it no longer carries its own matcher. Its pure grading, key-file and
  leak-scan tests run in ordinary CI, and an optional `Inspect lane` workflow runs
  the Docker + mockllm regression with no provider key.
- `MetricRecord` gains `kind` (`proportion` or `rate`): the scoped false-alarm
  rate can exceed 1.
- `authz-001` labels migrated to the v0.1 label schema (`variants[]`; the focal
  negative lists its site and source anchors).
- Dependencies: grouped GitHub Actions updates (#21) and pydantic 2.14.0 (#23).

### Fixed
- The task instructions did not state the submission limits the scorer applies
  (scoring.md Q5). Each now states at most 256 findings and 1 MiB per file, and at
  most 4 locations per finding, with what happens beyond them. A test ties the text
  to the scorer's parameters. The agent-visible text changed, so `authz-001`,
  `path-001` and `authz-002` are now at task revision 0.1.1, and their identities
  changed. All three stay HEALTHY.
- A THR calibrated off Linux still said "Linux host qualification pending (#32)"
  after #32 closed. It now says the record comes from a development host and must
  be recalibrated on the qualified Linux host before freezing.
- The declared Claude Code tool surface lacked the four task-list tools
  (`TaskCreate`, `TaskGet`, `TaskList`, `TaskUpdate`) that Claude Code 2.1.287
  offers with a real model, so the first live slice stopped every episode as
  `config:tool_surface_mismatch` (issue #47). They are declared now, which changes
  the system identities; the slice protocol is revised as `protocols/m2-slice-2/`.
- A live run crashed at its first episode outcome: Inspect 0.3.283 reports provider
  request IDs as `ModelRequestId(id, header, status)` objects, and the ledger
  accepts strings only. The runner now records each ID's string. Mock and scripted
  models report no request IDs, so only the first live slice (issue #47) found it.
- A run with an `evidence_incomplete` episode was sealed as `complete`, against
  scoring rule D1. It now seals as `completeness: incomplete` (bundle v0.1 amended
  before its first release). The offline re-score reports a mismatch when a seal's
  completeness differs from the one its episodes imply, `aureproof compare` refuses
  an incomplete bundle, a public bundle can only be made from a complete run, and
  the report explains the state. The tutorial bundle is re-sealed as incomplete
  and is re-signed in a follow-up.
- `aureproof task probe --model anthropic/<id>`, the form the live-slice guide
  gives, sent the prefixed name to the API and failed with a 404 and a traceback.
  The probe now takes the model with or without `anthropic/`, refuses other
  providers before any call, and reports provider errors as one line (issue #44).
  The first live single-shot results are in `docs/research/difficulty-probe.md`.
- The decision gate read the protocol's margin as a binary float, so `0.05`
  became slightly more than 1/20, and a CI lower bound of exactly -1/20 passed
  instead of being inconclusive (specs/decision §5: the inequalities are strict).
  The margin is now the decimal as written, compared as an exact rational.
- An agent error could be classified as an infrastructure failure and
  re-dispatched when its traceback's frames matched an infrastructure pattern:
  a path under `/tmp/claude-501`, a frame at `line 512`, or an `inspect_ai`
  sandbox module. Classification now reads only the error message and the
  traceback's exception lines, including chained causes and exception-group
  members (issue #39).

[Unreleased]: https://github.com/bhargavchintam/aureproof/compare/v0.1.0a1...main
[0.1.0a1]: https://github.com/bhargavchintam/aureproof/releases/tag/v0.1.0a1
