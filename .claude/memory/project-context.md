# Powehi — Project Context (autonomous dev anchor)

> Source of truth for the `powehi-dev-v1` cron loop: current state + phase checklist.
> Full architecture: `docs/prd.md`. Agent system: `docs/orchestration.md`.

## What this is
E2EE zero-knowledge web messenger. The server NEVER sees plaintext. Rust hexagonal
backend + React 19 / WASM frontend + 3-tier multi-region infra. Protocols: MLS
(RFC 9420), OPAQUE (RFC 9807), Web Push (RFC 8291).

## Non-negotiables (NEVER violate — these gate every commit)
- Server NEVER sees plaintext message content.
- No homegrown crypto. Only `openmls`, `opaque-ke`, RustCrypto (rule: crypto-libraries-pinned).
- Crypto code MUST pass the `crypto-reviewer` agent before commit.
- Architectural / new-metadata changes MUST pass `threat-model-checker`.
- Backend handlers MUST pass `security-auditor`.
- No plaintext logging of content / PII / ciphertext (rule: no-plaintext-logging).
- Every layer has a test gate (rule: testing-conventions).

## Phase status
All 6 phases in `docs/phases/phase-{1..6}/STATUS.md` show every DoD item checked
(`[x]`) as of cycle 425/426 — confirmed by grepping each STATUS.md fresh, not from
memory. There is no phase-checklist "next item" left to pull from; FEATURE-mode work
now comes from each cycle's "Next cycle candidates" list below (review-agent-flagged
follow-ups, prd.md drift, scoping tasks) rather than an unchecked phase DoD box.

## Current state (2026-09-06, cycle 444 — FEATURE: close cycle 443's candidate #5, declare `additionalLabels` in `monitoring.serviceMonitor`/`monitoring.prometheusRule` values.schema.json, commit 0ffca0f)

- Mode selection: counter 443→444, 444 % 5 != 0 → FEATURE.
- CI check: `gh run list --limit 3` green on `main` (cycle 443's push
  `completed`/`success` on both `CI — Rust` and `CI — Infra`).
  `gh issue list --state open`: empty. Clean working tree at session
  start. Checked for real, actionable gaps beyond the carried-candidates
  list before picking one: grepped `crates/` for `unimplemented!()`/
  `TODO`/`FIXME` (all hits are `#[cfg(test)]` mock structs in
  `invite.rs`/`region.rs`, not production code — nothing actionable);
  confirmed all six `docs/phases/phase-{1..6}/STATUS.md` still show
  zero unchecked `[ ]` items (grep count 0 on all six, re-derived fresh
  not from memory).
- Picked cycle 443's candidate #5 (only genuinely actionable, non-blocked
  item left): `values.schema.json`'s `monitoring.serviceMonitor` and
  `monitoring.prometheusRule` objects didn't declare `additionalLabels`
  as a schema property even though both `values.yaml` (empty default)
  and the three overlay files (`release: kube-prometheus-stack`) set it
  — a typo there would validate cleanly and only fail silently at
  runtime (Prometheus Operator's selector/ruleSelector just wouldn't
  match, so scraping/alerting silently doesn't happen) instead of
  failing loud in CI.
- **Fix**: added `additionalLabels: {"type": "object", "additionalProperties":
  {"type": "string"}, "description": "..."}` to both `serviceMonitor` and
  `prometheusRule` in `infra/helm/powehi/values.schema.json`. Pure
  schema-only diff — no template, `values.yaml`, or overlay file touched.
- **Validated locally**: `helm lint` clean on base chart + all three
  overlays (`values-prod-eu.yaml`/`values-prod-ap.yaml`/
  `values-staging.yaml`) with the new schema in place; `helm template`
  → `conftest test -p infra/policy --combine` 7/7 passed on all three
  overlays (0 failures, no regression from the schema-only change, as
  expected since schema doesn't affect rendered output).
- **security-auditor: PASS.** Confirmed the diff is additive-only (no
  `required` touched, no `additionalProperties: false` added/removed, no
  pattern/enum loosened), confirmed via `helm lint` that both the current
  empty-object default and the overlays' `{release: kube-prometheus-stack}`
  value validate cleanly under the new schema, and **ran the actual
  negative case**: `--set monitoring.prometheusRule.additionalLabels.release=123`
  now fails schema validation (`got number, want string`) — confirms the
  original nit (typo silently passing) is genuinely closed, not just
  theoretically addressed. No attack surface: labels are Kubernetes
  metadata only, no secrets/PII/ciphertext ever flow through this field.
  Noted two optional non-blocking nits (label-value pattern/length regex,
  `propertyNames` constraint on keys) — correctly flagged as marginal
  payoff (can't catch a *valid but wrong* value like `kube-prometheus-stak`
  either way) and not applied this cycle.
- No `.rs` file touched — `crypto-reviewer`/`threat-model-checker`
  correctly don't apply; backend build/test gate doesn't apply either
  (same routing precedent as cycles 442/443).
- Committed `0ffca0f` (`fix(infra): declare additionalLabels in
  monitoring.serviceMonitor/prometheusRule schema`), pushed.
- Target dir hygiene: not checked (FEATURE mode); `du -sh target` was
  17G at session start, under the 20G stabilization-mode prune threshold.
- Trimmed this file's tail: dropped cycle-438-and-older "Previous state"
  sections (kept 440-443) to keep the file from growing unbounded —
  older cycle detail is still in git history / GitHub commit messages if
  ever needed.
- **Next cycle candidates (carried/updated):**
  1. Carried: host disk risk from other `~/codespace/*` projects — not
     actionable from this repo.
  2. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  3. Carried, still explicitly BLOCKED: wiring
     `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal` into a real
     caller needs F3 (incl. the `IpHash` extension) and the
     HMAC-vs-plain-SHA256 gate resolved first — do not wire without
     re-reading both prd.md sections.
  4. **Downgraded to done:** cycle 443's candidate #5 (schema didn't
     declare `additionalLabels`) is now closed.
  5. Carried, minor, optional (security-auditor nit, not applied):
     if staging and prod-eu (same `region_id=eu-frankfurt`) ever get
     scraped by the same Prometheus instance, `sum by (region_id)` can't
     distinguish their alerts. Not urgent since they're currently
     separate clusters — would need an `env` label or
     `enforcedNamespaceLabel` only if that topology changes.
  6. New, minor, optional (this cycle's own security-auditor nit, not
     applied): `additionalLabels` schema now types values as strings but
     doesn't constrain label-key/value syntax (DNS-1123-ish pattern,
     63-char max) — would catch malformed-but-schema-valid labels in CI.
     Marginal payoff (can't catch valid-but-wrong values like a
     misspelled release name either way); not worth a dedicated cycle.
  7. **The carried-candidates pool is now thin** (mostly non-actionable/
     policy-gated/blocked plus marginal-payoff nits) — a future FEATURE
     cycle should consider scoping a fresh, more substantial item
     directly from prd.md rather than continuing to mine security-auditor
     nits one small schema tweak at a time.

## Previous state (2026-09-06, cycle 443 — FEATURE: enable the media-orphan-sweep PrometheusRule in prod-eu/prod-ap/staging overlays (closes cycle 442's candidate #5), commit 87398b2)

- Mode selection: counter 442→443, 443 % 5 != 0 → FEATURE.
- CI check: `gh run list --limit 5` green on `main` (cycle 442's push
  `completed`/`success` on both `CI — Rust` and the now-present
  `CI — Infra` job). `gh issue list --state open`: empty. Clean working
  tree at session start (no inherited uncommitted work this time).
- Picked cycle 442's candidate #5 (the only genuinely actionable item;
  #1/#2/#4 remain non-actionable-from-this-repo/policy-gated/BLOCKED as
  before): CI's existing `ci-infra.yml` `helm-validate` job already loops
  `helm lint` + `helm template | kubeconform` + `helm template | conftest`
  over `values-prod-eu.yaml`/`values-prod-ap.yaml`/`values-staging.yaml`,
  but none of those three overlays set `monitoring.prometheusRule.enabled`,
  so the new PrometheusRule template (cycle 442) was never actually
  rendered/validated by CI, and a real kube-prometheus-stack install would
  render it without the `additionalLabels.release` its `ruleSelector`
  needs.
- **Fix**: added a `monitoring.prometheusRule` block to all three overlay
  files, mirroring the existing (already-enabled, already-reviewed)
  `monitoring.serviceMonitor` block's shape exactly —
  `enabled: true`, `window: "1h"`, `additionalLabels: {release:
  kube-prometheus-stack}` — same value in all three files, same pattern
  the `serviceMonitor` block in the same file already uses. Pure
  values-file diff, zero template/schema/code changes (those already
  landed cycle 442).
- **Validated locally before delegating review** (not just trusting the
  template renders): `helm lint` clean on all three overlays;
  `helm template ... | grep -c "kind: PrometheusRule"` → 1 for each
  overlay (previously 0 — confirms this closes the actual gap);
  `conftest verify -p infra/policy` (88/88) and `helm template ... |
  conftest test - -p infra/policy --combine` (7/7 per overlay, 0
  failures) — `conftest` happened to be installed locally this session
  (`kubeconform` still wasn't, same gap as prior infra cycles) so this ran
  for real instead of only being deferred to CI.
- **security-auditor: PASS, no required fixes.** Independently re-derived
  rather than trusting this session's own claims: diffed rendered
  manifests at HEAD vs. working tree (73 added lines, 0 removed/modified,
  all originating from `templates/prometheusrule.yaml` — confirms
  no other resource/limits/NetworkPolicy path was touched), confirmed
  both underlying counters carry only the `region_id` label (schema-bound
  enum, no user data), byte-compared all six `release:` lines for exact
  match, confirmed `window: "1h"` and the rendered `for: 0m` both satisfy
  their respective duration-pattern schemas (values.schema.json and the
  real PrometheusRule CRD from the datreeio catalog CI actually fetches),
  and explicitly reasoned about whether staging should get this alert at
  all — concluded **yes, arguably required**: `values-staging.yaml` sets
  `region: eu-frankfurt`, the same region as prod-eu, and the file's own
  cycle-424 comment already documents that a shared bucket between the
  two would let staging's orphan sweep delete prod-eu's live media — the
  owner-mismatch alert is the detection control for exactly that
  misconfiguration, so gating it to prod-only would blind the one
  environment where the risk is documented as live. Two non-blocking
  nits, not applied this cycle (correctly out of scope for a two-line
  enablement diff): (a) if staging and prod-eu ever scrape into one
  Prometheus, `sum by (region_id)` alone can't tell their alerts apart
  (both `region_id="eu-frankfurt"`) — would need an `env` label or
  `enforcedNamespaceLabel` if that topology ever happens; (b)
  `values.schema.json`'s `prometheusRule` object doesn't declare
  `additionalLabels` (same pre-existing omission as `serviceMonitor`) —
  a typo in the release-label value fails silently at runtime, not in CI.
- No `.rs` file touched — pure Helm values diff, so `crypto-reviewer`/
  `threat-model-checker` correctly don't apply (same routing precedent as
  cycle 442's template-authoring commit) and the backend build/test gate
  doesn't apply either; not re-run this cycle.
- Committed `87398b2` (`feat(infra): enable media-orphan-sweep
  PrometheusRule in prod/staging overlays`), pushed. Confirm `CI — Infra`
  green in a future session if not already done by the time this is read.
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates (carried/updated):**
  1. Carried: host disk risk from other `~/codespace/*` projects — not
     actionable from this repo.
  2. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  3. Carried, still explicitly BLOCKED: wiring
     `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal` into a real
     caller needs F3 (incl. the `IpHash` extension) and the
     HMAC-vs-plain-SHA256 gate resolved first — do not wire without
     re-reading both prd.md sections.
  4. **Downgraded to done:** cycle 442's candidate #5 (CI never rendering
     the PrometheusRule template) is now closed — all three overlays
     enable it and CI's existing `ci-infra.yml` loop will render/validate
     it on every future push that touches `infra/helm/**`.
  5. **New, minor, optional (security-auditor nit, not applied this
     cycle):** `values.schema.json`'s `monitoring.prometheusRule` object
     (and `serviceMonitor`, pre-existing) doesn't declare
     `additionalLabels` as a schema property, so a typo in
     `release: kube-prometheus-stack` would validate cleanly and only
     fail silently at runtime (Prometheus Operator's `ruleSelector`
     simply wouldn't pick up the rule) instead of failing in CI. Cheap
     one-line schema addition if a future cycle touches this file again;
     not worth a dedicated cycle.
  6. **New, minor, optional (security-auditor nit, not applied this
     cycle):** if staging and prod-eu (same `region_id=eu-frankfurt`)
     ever get scraped by the same Prometheus instance, `sum by
     (region_id)` can't distinguish their alerts. Not urgent since they're
     currently separate clusters — would need an `env` label or
     `enforcedNamespaceLabel` only if that topology changes.

## Previous state (2026-09-05, cycle 442 — FEATURE: wire the R2 orphan-sweep owner-mismatch/ratio-guard Prometheus counters to an actual PrometheusRule (closes cycle 436's carried candidate #3), commit pending)

- Mode selection: counter 441→442, 442 % 5 != 0 → FEATURE.
- CI check: `gh run list --limit 5` green on `main` (cycle 441's push
  `completed`/`success` on both `CI — Rust` and `CI — Live-backend E2E`).
  `gh issue list --state open`: empty. Clean working tree at session start.
- Cycle 441's own "Next cycle candidates" list was explicitly thin (its
  #6 said the pool needed looking beyond the carried list). Of the
  carried candidates, #1 (host disk) and #2 (PQ hybrid) and #4 (F3-blocked
  abuse-signal wiring) are non-actionable-from-this-repo/policy-gated as
  before. #3 (R2 orphan-sweep owner-mismatch/ratio-guard metrics need an
  actual alert rule, carried since cycle 436) turned out to be genuinely
  actionable from this repo after all: `infra/helm/powehi/` already has a
  `servicemonitor.yaml` template and Prometheus Operator wiring, but no
  `PrometheusRule` template existed yet — this wasn't purely an
  ops/infra-lead-external task, it was a missing Helm template in this
  chart. Delegated to `infra-lead`.
- **Fix**: new `infra/helm/powehi/templates/prometheusrule.yaml` (first
  `PrometheusRule` in this chart), gated by
  `.Values.monitoring.prometheusRule.enabled` (default `false`, same
  precedent as `serviceMonitor`), using the existing
  `powehi.fullname`/`powehi.labels` helpers. Two alerts, group
  `powehi.media-orphan-sweep`:
  - `PowehiMediaOrphanSweepOwnerMismatch` (severity `critical`) on
    `sum by (region_id) (increase(media_orphan_sweep_owner_mismatch_total[1h])) > 0`.
  - `PowehiMediaOrphanSweepRatioGuard` (severity `warning`) on
    `sum by (region_id) (increase(media_orphan_sweep_ratio_guard_total[1h])) > 0`.
  Both `for: 0m` — deliberate, not an oversight: both counters track
  conditions that never self-resolve (every subsequent 6-hourly sweep
  re-triggers them once broken per the cycle-436 doc comments), so
  "any increase in the window" is already a low-noise, correct signal
  with no need for alertmanager debounce. Annotations cite prd.md
  §9.4.3 and use `{{ $labels.region_id }}` templating so on-call has
  context without reading the source. Added
  `monitoring.prometheusRule.{enabled,window,additionalLabels}` to
  `values.yaml` (mirroring the `serviceMonitor` block's style/doc-comment
  pattern) and declared `monitoring.serviceMonitor`/`monitoring.prometheusRule`
  in `values.schema.json` (previously `monitoring` was entirely
  undeclared there — also newly schema-enforced: `window` must match a
  Prometheus duration pattern, since a malformed value makes Prometheus
  reject the whole rule *group*, silently dropping both alerts).
- **security-auditor: PASS-with-nits, addressed in-session** (infra
  observability config, additive-only, no new server-visible metadata —
  both counters already existed and were already reviewed in cycle 436,
  so per routing rules only `security-auditor` applies here, not
  `crypto-reviewer`/`threat-model-checker`). Confirmed no plaintext/PII/
  secret leakage, `region_id` is the same bounded operator enum already
  scraped elsewhere, confirmed the `{{ "{{" }}...{{ "}}" }}` Helm-escaping
  renders a correct literal Alertmanager template var. Required fixes,
  applied: (1) `window` needed the duration-pattern schema constraint
  (malformed value → silent whole-group drop); (2) both `expr`s needed
  `sum by (region_id)` — without it, multiple replicas in the same region
  would each fire their own alert for the same underlying event instead
  of one alert per region; (3) a stale region-enum comment (actual enum
  is `eu-frankfurt`/`ap-seoul`/`ap-tokyo`/`""`, comment only listed two).
  Left as explicitly out-of-scope for a future cycle (correctly, per this
  cycle's chart-only mandate): (a) CI overlay files (`values-*.yaml`)
  don't enable the rule yet, so `kubeconform` never exercises this
  template in CI; (b) enabling in a real kube-prometheus-stack install
  needs `additionalLabels.release: kube-prometheus-stack` (or whatever
  that install's `ruleSelector` requires) set by the operator — chart
  correctly leaves this to the environment's `values-prod-*.yaml`, not
  hardcoded.
- **Validation, re-run independently in this session** (not just
  trusting the subagent's self-report): `helm lint infra/helm/powehi`
  clean at both default and `--set monitoring.prometheusRule.enabled=true`;
  `helm template ... --set region=eu-frankfurt` with the flag left
  default-false renders **zero** `kind: PrometheusRule` occurrences
  (correctly omitted); with the flag enabled, `helm template` output
  parses cleanly via `yaml.safe_load_all` (16 docs) and
  `--show-only templates/prometheusrule.yaml` shows both alert exprs
  correctly wrapped in `sum by (region_id)(...)`; `values.schema.json`
  is valid JSON (`json.load` clean); **`conftest test` against the full
  rendered manifest with the flag enabled, using this repo's own
  `infra/policy/` OPA suite: 112/112 tests passed, 0 failures** (deny-all
  NetworkPolicy / resource-limits / no-`:latest`/ runAsNonRoot / no-literal-
  secrets policies all still hold with the new resource present).
  `kubeconform`/`tflint` not installed in this environment — same gap as
  prior infra cycles, not newly introduced.
- No `.rs` file touched — Helm-only change, so the backend build/test
  gate (`cargo build`/`test`/`clippy`/`fmt`) doesn't apply; not re-run
  this cycle since nothing in `crates/` changed.
- Committing `infra/helm/powehi/templates/prometheusrule.yaml`,
  `infra/helm/powehi/values.yaml`, `infra/helm/powehi/values.schema.json`
  as a `feat(infra):` commit, pushing. Confirm CI green in a future
  session if not already done by the time this is read (CI's Helm/infra
  validation job, if any, is the relevant one to check — not the Rust job).
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates (carried/updated):**
  1. Carried: host disk risk from other `~/codespace/*` projects — not
     actionable from this repo.
  2. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  3. **Downgraded to done, with a documented residual:** the R2
     orphan-sweep owner-mismatch/ratio-guard alert rule is now wired in
     the chart itself. Residual (not urgent, correctly out of scope this
     cycle): no `values-prod-*.yaml`/CI overlay actually flips
     `monitoring.prometheusRule.enabled=true` yet, and a real
     kube-prometheus-stack install will need `additionalLabels.release`
     (or equivalent) set to match its `ruleSelector` — an ops/environment-
     config task, not a further chart-code task.
  4. Carried, still explicitly BLOCKED: wiring
     `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal` into a real
     caller needs F3 (incl. the `IpHash` extension) and the
     HMAC-vs-plain-SHA256 gate resolved first — do not wire without
     re-reading both prd.md sections.
  5. **New, minor:** CI has no job that renders this chart with
     `monitoring.prometheusRule.enabled=true` (or `serviceMonitor.enabled=true`
     for that matter — same gap predates this cycle), so a future Helm
     template regression in either optional resource wouldn't be caught
     by CI until an operator actually flips the flag in a real
     environment. A genuine `ci-pipeline-author` follow-up, not urgent.

## Previous state (2026-09-05, cycle 441 — FEATURE: close the CommitLedger id-collision hole (cycle 440's next-cycle candidate #6), commit 969a304)

- Mode selection: counter 440→441, 441 % 5 != 0 → FEATURE.
- CI check: `gh run list --limit 3` green on `main` (cycle 440's push both
  `CI — Rust` and `CI — Live-backend E2E` `completed`/`success`).
  `gh issue list --state open`: empty.
- Clean working tree at session start (no inherited uncommitted work this
  time). Picked cycle 440's next-cycle candidate #6 — the only genuinely
  actionable item on the list (others are either not-actionable-from-this-repo
  disk risk, a human/crypto-lead policy call, an infra-lead/ops alerting
  task, or explicitly BLOCKED pending F3/HMAC gate).
- **Fix** (`crates/adapters/outbound/powehi-postgres/src/commit_ledger.rs`):
  `PgCommitLedger::commit_epoch_and_save`'s Commit-envelope INSERT used
  `ON CONFLICT (id) DO NOTHING` inside the same transaction as the epoch
  CAS. Both current callers always mint a fresh UUIDv4 id, so the conflict
  branch is unreachable today — but if it ever fired (e.g. a future caller
  reusing an id as an idempotency key), the transaction would still
  `tx.commit()`, durably advancing the epoch while silently discarding the
  intended envelope: the exact "epoch consumed, envelope missing" wedge
  bug class this ledger exists to close, just via a no-op insert instead of
  a separate failed statement. Now checks `insert_result.rows_affected()
  == 0` after the insert and, if so, explicitly `tx.rollback()`s and
  returns `Err(DomainError::AlreadyExists(commit_envelope.id.to_string()))`
  instead of committing — a whole-unit-of-work rollback, not a partial fix.
  Added `commit_epoch_and_save_rejects_and_rolls_back_on_envelope_id_collision`
  (`crates/adapters/outbound/powehi-postgres/tests/pg_security_it.rs`,
  `#[ignore]`'d like the rest of that file since Docker isn't available in
  this environment — will run in CI's Docker job), pre-seeding a colliding
  row and asserting both the epoch rollback and that exactly the
  pre-existing envelope row (no second row, no mutation) survives.
- **All three required review agents run in-session** (touches MLS
  Commit-ledger/epoch logic, so all three routing triggers apply):
  - **crypto-reviewer: PASS**, one required doc follow-up. Verified
    `rows_affected() == 0` is a sound conflict signal by reading the
    `envelopes` migration directly (`id UUID PRIMARY KEY` is the only
    unique constraint, no trigger/rule/RLS/partitioning that could
    otherwise suppress a row) — a single-row INSERT can only yield 0 rows
    via the `ON CONFLICT (id)` arbiter; any other constraint violation
    raises 23505 into the existing `Err` arm, not this one. Confirmed
    rollback leaves zero partial writes (event-bus publish/fan-out only
    happens after `Ok`, downstream of this call). Confirmed this
    strengthens RFC 9420 §12.4's "exactly one valid Commit per epoch"
    invariant rather than just fixing an availability bug — a wedge here
    would have permanently blocked key-schedule ratcheting for the group.
    Confirmed `AlreadyExists` (409/non-retryable) is the correct variant
    vs. `Internal` (which is in gRPC's *retryable* set — would have caused
    cross-region peers to retry a deterministically-failing CAS forever).
  - **threat-model-checker: GREEN**, no required prd.md edit — confirmed
    strictly hardening across all threat-model rows (T3 malicious-operator
    row strengthened: the "epoch consumed ⟺ envelope stored" invariant in
    §4A.5 now holds literally, not modulo the no-op-insert hole; all
    others unchanged), confirmed no new server-visible metadata (the
    `AlreadyExists(id)` payload is discarded by both inbound adapters
    before reaching a client), confirmed non-retryable so no cross-region
    retry amplification. Judged §4A.5's existing text doesn't need editing
    since it never claimed the no-op path was safe and no caller contract
    changed.
  - **security-auditor: PASS**, no required fixes — independently
    confirmed zero plaintext/PII/ciphertext in the new code path (error
    carries only a server-minted UUID), zero new `unwrap()`/`expect()` in
    lib code, correct 409/`AlreadyExists` mapping on both REST and gRPC
    (not leaking as a generic 500), no new SQL-injection surface (INSERT
    unchanged, still fully parameterized), and that this narrows rather
    than widens the trust boundary (old code committed on the 0-rows case;
    new code rejects it).
  - **Shared required fix, applied**: all three reviewers independently
    flagged the same gap — the `CommitLedger` port trait doc
    (`crates/ports/powehi-port-outbound/src/commit_ledger.rs`) documented
    only the `Ok(None)` CAS-loss contract, not the new
    `Err(AlreadyExists)` id-collision contract, even though this is a
    port-level behavioral contract binding every implementation and the
    in-memory test fakes. Added a doc block spelling out the rule: id
    collision = whole unit of work rolled back, epoch NOT consumed, never
    treated as "already done".
  - **Non-blocking nit, applied anyway (cheap)**: crypto-reviewer noted
    the new test asserted epoch-rollback but not that no second `envelopes`
    row was created — added a `COUNT(*) = 1` assertion (pre-seeded row
    only) to pin the full invariant, not just half of it.
- Build/test gate (repeated after the doc/test fixes): `cargo build
  --workspace --all-targets` (clean), `cargo test --workspace` (all green,
  0 failures — `cargo nextest` still not installed in this environment,
  used the documented `cargo test --workspace` fallback), `cargo clippy
  --workspace --all-targets -- -D warnings` (clean), `cargo fmt --all
  --check` (clean), `cargo deny check` (advisories/bans/licenses/sources
  all ok — zero dependency changes, pure code diff). New Postgres
  integration test is `#[ignore]`'d — no Docker in this environment,
  will run in CI's Docker job like its siblings in the same file.
- Committed `969a304` (`fix(mls): reject commit envelope id collisions
  instead of silently committing`), pushed. CI triggered on push, confirm
  green before trusting this cycle's claim in a future session if not
  already done by the time this is read.
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates (carried/updated):**
  1. Carried: host disk risk from other `~/codespace/*` projects — not
     actionable from this repo.
  2. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  3. Carried: R2 orphan-sweep owner-mismatch/ratio-guard metrics
     (cycle 436) still need an actual Alertmanager/Grafana rule wired —
     infra-lead/ops task, not a routine backend cycle.
  4. Carried, still explicitly BLOCKED: wiring
     `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal` into a real
     caller needs F3 (incl. the `IpHash` extension) and the
     HMAC-vs-plain-SHA256 gate resolved first — do not wire without
     re-reading both prd.md sections.
  5. **Downgraded to done:** the `CommitLedger` id-collision hole (cycle
     440's candidate #6) is now closed — id collision is a hard,
     whole-transaction-rolled-back error, not a silent no-op success. No
     further action expected on this specific item.
  6. **New, minor, optional:** none of the three reviewers found anything
     else outstanding on this file. The candidate pool is now thin — the
     next FEATURE cycle may need to look beyond this cycle's carried list
     (e.g. re-reading prd.md for drift, or scoping the PQ-hybrid/F3
     prerequisites enough to unblock them) rather than finding another
     quick follow-up.

## Previous state (2026-09-05, cycle 440 — STABILIZATION: finished inherited cycle-439 work (CommitLedger unit-of-work closing the epoch wedge), verified+reviewed+committed, commit 1e78b81)

- Mode selection: counter 439→440, 440 % 5 == 0 → STABILIZATION.
- CI check: `gh run list --limit 5` green on `main` (cycle 438's push all
  `success`, one `cancelled` run superseded by a rerun — not a real
  failure). `gh issue list --state open`: empty.
- **Session start found a large uncommitted working tree again** (same
  recurring pattern as cycles 429/433/434/438 — a prior cycle's work was
  never committed/its own memory entry never written, here likely
  cycle 439): a fully-formed, well-documented, well-tested feature was
  already implemented that closes exactly next-cycle candidate #6 from
  cycle 438's memory (the CAS+envelope-save non-atomicity accepted
  risk). New narrow outbound port `CommitLedger::commit_epoch_and_save`
  (`powehi-port-outbound/src/commit_ledger.rs`) + Postgres adapter
  `PgCommitLedger` (`powehi-postgres/src/commit_ledger.rs`) run the
  epoch CAS UPDATE and the Commit-envelope INSERT in one `sqlx`
  transaction, replacing the old two-separate-port-calls sequence at
  both `messaging_service.rs::send_commit` and
  `powehi-grpc/server.rs::forward_commit`. The old
  `mls_commit_epoch_stall_total` counter (cycle 438's observability-only
  mitigation) was removed since the failure mode it tracked is now
  structurally impossible. Treated as real in-progress work to verify
  and land per the standing "investigate unfamiliar state before
  overwriting" discipline — this is finishing previously-started
  architectural work, not starting a new feature, so doing it in a
  STABILIZATION cycle is consistent with "no new features."
- Verified from scratch (not trusting the diff's self-documentation):
  read every changed/new file in full, confirmed the CAS SQL is
  byte-identical to the already-reviewed `advance_epoch`, confirmed the
  envelope's `epoch` field is always adapter-stamped from the CAS's own
  return value (never caller-supplied), confirmed explicit
  `tx.rollback()` on CAS-loss.
- **All three required review agents run in-session** (MLS epoch/
  concurrency logic + new architectural port + gRPC handler — all three
  routing triggers apply):
  - **crypto-reviewer: PASS.** CAS still atomic/race-free under Postgres
    READ COMMITTED (EvalPlanQual re-checks `WHERE epoch=$2` against the
    post-commit row on lock contention, so a loser correctly sees
    `Ok(None)`, never double-advances). Wrapping the CAS in a longer-held
    transaction is strictly safer, not racier. Error semantics correctly
    changed so a client-visible failure now provably means the epoch is
    untouched (safe to retry with the same `expected_epoch`), closing
    the old ambiguous-retry class of bug. Envelope epoch-stamping
    verified correct with both a unit test and a Postgres integration
    test that deliberately sets a wrong input epoch. One non-blocking
    style nit: insert-failure path relied on `Transaction::drop`'s
    best-effort rollback instead of an explicit one (asymmetric with the
    CAS-loss branch) — flagged as low-severity, not RFC 9420-breaking.
  - **threat-model-checker: GREEN, no required fixes.** No new
    plaintext/metadata exposure (§3.3 unaffected — pure write-atomicity
    change). mTLS peer-region + membership checks in `forward_commit`
    confirmed to still execute *before* the new port call, unmoved by
    the refactor. Counter removal confirmed safe — grepped clean, no
    Alertmanager/Grafana rule was ever wired to it (per cycle 438's own
    "미착수" note), so no live detection control was lost. The
    two-table `CommitLedger` port judged an acceptable narrow exception
    to hexagonal port boundaries given its doc comment explicitly
    disclaims generalizing beyond this one cross-aggregate invariant.
    prd.md §4A.5's "epoch wedge — CLOSED (cycle 439)" text verified
    accurate with no overstated guarantees.
  - **security-auditor: PASS.** SQL parameter binding, the `u64→i64`
    epoch range guard (`InvalidInput`/400, not `Internal`/500, checked
    before any query), zero plaintext/PII logging introduced, zero
    dangling `metrics::`/`mls_commit_epoch_stall_total` references after
    the dependency removal (independently grepped + rebuilt), zero
    `unwrap()`/`expect()` in non-test lib code, and the `forward_commit`
    authz ordering (mTLS + membership before the ledger call) all
    independently re-verified — not just trusted from the crypto-review
    pass. Same non-blocking rollback-style nit as crypto-reviewer.
  - **Fix applied for the shared nit** (both independent reviewers
    flagged the same thing, cheap to fix): `commit_ledger.rs`'s
    insert-failure path now calls `tx.rollback()` explicitly before
    returning the mapped error, matching the CAS-loss branch's style —
    functionally identical to the prior `Drop`-based rollback, purely an
    auditability improvement.
- Build/test gate (repeated after the nit-fix): `cargo build --workspace
  --all-targets` (clean), `cargo test --workspace` (all green, 0
  failures across every crate), `cargo clippy --workspace --all-targets
  -- -D warnings` (clean), `cargo fmt --all --check` (clean), `cargo
  deny check` (advisories/bans/licenses/sources all ok — `metrics`
  removal from `powehi-grpc`/`powehi-application` `Cargo.toml`s is a
  pure subtraction, no new external crate). `cargo audit`: 0 advisories
  across 664 crates. `gh issue list --state open`: empty (checked
  above).
- Committed `1e78b81` (`feat(mls): make epoch CAS + Commit-envelope save
  one atomic unit of work`), pushed. CI triggered on push, confirm green
  before trusting this cycle's claim in a future session if not already
  done by the time this is read.
- Target dir hygiene: `target/` at 17G (below the 20G prune threshold,
  no pruning needed this cycle) — pruned only 0-byte `.rmeta` stubs.
  Host disk is still tight (6.9 GiB free / 97% full on the 228 GiB
  volume) — same standing non-actionable-from-this-repo risk carried
  since cycle 434 (other `~/codespace/*` projects dominate usage).
- **Next cycle candidates (carried/updated):**
  1. Carried: host disk risk from other `~/codespace/*` projects — not
     actionable from this repo. Still at 97% full / 6.9 GiB free.
  2. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  3. Carried: R2 orphan-sweep owner-mismatch/ratio-guard metrics
     (cycle 436) still need an actual Alertmanager/Grafana rule wired —
     infra-lead/ops task, not a routine backend cycle.
  4. Carried, still explicitly BLOCKED: wiring
     `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal` into a real
     caller needs F3 (incl. the `IpHash` extension) and the
     HMAC-vs-plain-SHA256 gate resolved first — do not wire without
     re-reading both prd.md sections.
  5. **Downgraded to done:** the epoch-CAS/envelope-save non-atomicity
     (candidate #6 as of cycle 438) is now closed via `CommitLedger` —
     no further action expected on this specific item. The
     `mls_commit_epoch_stall_total` counter it required is correctly
     removed (tracked failure mode is gone), so candidate #5 (wiring an
     alert to that counter) is also moot/dropped.
  6. **New, minor, optional:** the `PgCommitLedger` envelope INSERT
     still uses `ON CONFLICT (id) DO NOTHING` (copied from the
     pre-existing `PgEnvelopeRepository::save`) — inert today since both
     callers always generate a fresh UUIDv4 per attempt, but
     crypto-reviewer flagged that *if* `id` were ever client-supplied as
     an idempotency key, a conflicting existing row would let the
     transaction commit having advanced the epoch while silently NOT
     inserting the intended envelope — structurally the same bug class
     this cycle just closed, just via `ON CONFLICT DO NOTHING` instead of
     a separate write. Not a regression (pre-existing pattern, not
     introduced this cycle) and not urgent (no current caller does this)
     — worth a one-line comment or `DO UPDATE ... WHERE false` swap if a
     future cycle touches this file again, not worth a dedicated cycle
     on its own.

