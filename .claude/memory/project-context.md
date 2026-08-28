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

## Current state (2026-08-29, cycle 385 — STABILIZATION: fail-closed r2_access_key_id/r2_secret_access_key guard + chacha20 unyank, commit 666d185)

- CI green (`gh run list --limit 3` all success), `gh issue list --state open`
  empty, `git status` clean at cycle start. Picked cycle 384's own advisory
  #1 (deferred, not fixed that cycle, same class as that cycle's own fix):
  `r2_access_key_id`/`r2_secret_access_key` default to `""` via
  `config::Config::builder().set_default(...)` in `load()`, with no
  fail-closed guard — a non-local `region_id` deployment missing
  `POWEHI__R2_ACCESS_KEY_ID`/`POWEHI__R2_SECRET_ACCESS_KEY` would start
  successfully and only fail at the first real media upload/download call,
  same silent-until-used shape as the `r2_endpoint` bug cycle 384 fixed.
- **Fix (implemented directly, single small Rust file, no delegation
  needed):** added `ConfigError::R2CredentialsMissingInNonLocalRegion(String)`
  and a new `validate()` rule: `region_id != "local" && (r2_access_key_id.is_empty()
  || r2_secret_access_key.is_empty())` → hard error (embeds only `region_id`,
  never the credential values, matching the sibling error's shape). Used `||`
  deliberately, not `&&` — either credential alone being empty (e.g. an
  operator who set one env var but typo'd the other's name) is a real
  deployment bug on its own. Added 3 new unit tests: all 3 empty-combinations
  (access-key-only, secret-only, both) rejected across 3 non-local
  `region_id`s, missing credentials accepted when `region_id == "local"`,
  real credentials accepted regardless of region.
- Verified: `cargo build --workspace` clean, `cargo test -p powehi-config`
  27/27 (24 pre-existing + 3 new), full `cargo test --workspace` all green,
  `cargo clippy -p powehi-config --all-targets -- -D warnings` clean,
  `cargo fmt -p powehi-config -- --check` clean (one auto-fmt pass needed on
  a multi-line `for` loop header, same as cycle 384's own fmt nit).
- **security-auditor: GREEN, no findings needing a fix.** Confirmed no bypass
  (`load()` is `validate()`'s only caller, new check is last before `Ok(())`,
  no early-return interference from the 4 preceding guards); confirmed the
  new error only ever embeds `region_id` (non-secret, already unredacted in
  the existing `Debug` impl) and never the actual credential values,
  satisfying `no-plaintext-logging`; confirmed `region_id == "local"`
  (dev/CI/docker-compose/`ci-e2e-live.yml`) is unaffected since none of those
  set `POWEHI__REGION_ID`; confirmed `||` (not `&&`) is correct since either
  credential alone being empty makes SigV4 presigning unusable; **checked,
  not assumed**, that all 3 real overlays (prod-eu/prod-ap/staging) already
  wire real credentials via `ExternalSecret` → `POWEHI__R2_ACCESS_KEY_ID`/
  `POWEHI__R2_SECRET_ACCESS_KEY` (confirmed via `values-*.yaml`
  `remoteRefs.r2AccessKeyId`/`r2SecretAccessKey` + `externalsecret.yaml` +
  `deployment.yaml` `envFrom.secretRef`), so this guard is a pure
  vacuous-today/future-regression guard for all 3, same pattern as cycle
  384's sibling fix. Two informational-only notes, no action needed: `is_empty()`
  vs `trim().is_empty()` (not realistic for ESO-sourced secrets, consistent
  with the sibling check's style); `r2_access_key_id` unredacted vs
  `r2_secret_access_key` redacted in `Debug` (pre-existing, defensible —
  access-key-id is an identifier not a secret, same AWS/R2 convention).
- **Also fixed as part of this cycle's STABILIZATION security sweep:**
  `cargo audit` surfaced a new (not present as of cycle 380's last sweep)
  yanked-crate warning on `chacha20 0.10.1` (transitive via `rand 0.10.1`,
  reached both through `hpke-rs-libcrux → openmls_rust_crypto →
  powehi-crypto-wasm` and through `testcontainers`/`ferroid`, dev-only).
  Ran `cargo update -p chacha20@0.10.1 --precise 0.10.2` (semver-compatible
  patch bump within existing `Cargo.toml` constraints, no manifest edits) —
  confirmed the warning is gone from a re-run of `cargo audit`, `cargo build
  --workspace` and `cargo test --workspace` both still clean afterward,
  `cargo deny check` still `advisories ok, bans ok, licenses ok, sources ok`.
  Not a crypto-code change (no crypto logic/primitive selection touched, pure
  transitive `Cargo.lock` version bump of a non-primitive dependency used for
  `rand`'s internal CSPRNG state, openmls_rust_crypto's actual AEAD choice is
  RustCrypto's `chacha20poly1305` crate directly per `.cargo/audit.toml`'s
  own prior analysis) — `crypto-reviewer` correctly not separately invoked
  for this half of the diff; covered instead by the STABILIZATION playbook's
  own `cargo audit`/`cargo deny check` step.
- Not architectural (a stricter startup-time validation rule on 2 existing
  config fields, zero new server-visible metadata, zero new API surface) —
  `threat-model-checker` correctly not invoked; not MLS/OPAQUE/WASM crypto
  code (only a transitive Cargo.lock bump, reasoned above) —
  `crypto-reviewer` correctly not invoked for the whole diff.
- No Helm/`.rego`/frontend files touched this cycle (pure Rust +
  `Cargo.lock`) — `helm lint`/`conftest`/`pnpm test` correctly not re-run
  (no-op expected, confirmed via `git status --short` before commit: exactly
  2 files, `crates/infra/powehi-config/src/lib.rs` + `Cargo.lock`).
- Target dir hygiene: `target/` is 28GB (over the 20GB prune threshold,
  grown from 27GB at cycle 380), ran the 0-byte `.rmeta` sweep (nothing to
  remove) and the `mtime +7` prune pass — found nothing old enough to prune
  again (all artifacts recent from active cycles), size unchanged at 28GB.
  Still not urgent enough to force-delete recent incremental-cache
  artifacts; re-check next STABILIZATION cycle (390). Growth rate (~0.2-
  0.33GB/cycle over 5-cycle windows) worth watching if it keeps climbing.
- **Next cycle candidates:** cycle 383's advisory #2 (`no_literal_secrets.rego`
  never inspects `ConfigMap` `data` — a credential pasted into `r2Endpoint`
  would sail through all 108 conftest checks undetected, demonstrated
  concretely, still open); cycle 379's YELLOW-1 (`ci-infra.yml`
  `--skip-tests`/`podSelector` labels nit, still open, still low urgency);
  the long-carried ops/blocked items: provision the 3 environments'
  `grpc-tls-{cert,key,ca}` secret-store keys (ops task, not code) and real
  `r2Endpoint`/`r2Bucket`/`vapidContact` values (ops task, not code — chart
  supports them since cycle 383, and both known silent-misconfiguration
  failure modes on the config side are now fail-closed as of cycles 384/385);
  activating `grpcPeers` for real cross-region mesh traffic (needs its own
  threat-model check); media-key incoming/outgoing asymmetry (multi-part,
  needs a full WASM key-export design, cycle 359); PQ hybrid Phase A
  (blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF
  upgrade (gated on ADR-0003 Phase B); project-context.md size (now ~3060
  lines — still comfortably under the 256KB Read cap, growing steadily,
  consider trimming the oldest "Previous state" entries at next
  STABILIZATION, 390); consider periodically re-running `cargo audit`/`cargo
  update` checks for freshly-yanked transitive crates outside STABILIZATION
  cycles too, since this cycle's chacha20 yank appeared silently between
  cycle 380 and 385 with no CI failure to surface it (cargo-audit treats
  `yanked` as a non-fatal warning by default, confirmed via this cycle's own
  `cargo audit` output).

## Previous state (2026-08-28, cycle 384 — FEATURE: fail-closed r2_endpoint dev-default guard in powehi-config, commit 3a29aa9)

- CI green (`gh run list --limit 5` all success), `gh issue list --state open`
  empty, `git status` clean at cycle start. Picked cycle 383's own advisory
  #1 (deferred, not fixed that cycle): no fail-closed guard stopped the
  compiled `r2_endpoint` dev default (`http://localhost:9000`, set via
  `config::Config::builder().set_default(...)` in
  `crates/infra/powehi-config/src/lib.rs`'s `load()`) from silently being
  used in a non-local `region_id` — an environment shipping with
  `r2Endpoint` still blank (or the Helm wiring itself not yet rolled out to
  that environment) gets working-but-wrong pre-signed media URLs pointed at
  the server's own loopback instead of a loud startup crash.
- **Fix (implemented directly, single small Rust file, no delegation
  needed):** named the literal as `const DEV_R2_ENDPOINT_DEFAULT: &str =
  "http://localhost:9000"` (reused by both `load()`'s `set_default` and the
  new check, so there's exactly one source of truth), added
  `ConfigError::R2DevDefaultEndpointInNonLocalRegion(String)`, and a new
  `validate()` rule: `region_id != "local" && r2_endpoint ==
  DEV_R2_ENDPOINT_DEFAULT` → hard error. Deliberately did NOT add the same
  guard for `r2_bucket` — its dev default (`powehi-media`) is a plausible
  real bucket name, not inherently unsafe the way a loopback URL literal is.
  Also fixed a latent inconsistency this change exposed: the test module's
  `default_config()` fixture combined `region_id: "eu-central-1"` with
  `r2_endpoint: "http://localhost:9000"` — a combination that would now
  itself fail the new rule — changed its endpoint to a realistic
  `https://acct.r2.cloudflarestorage.com` so all pre-existing
  `validate(&cfg).is_ok()` tests built from it stay meaningful. Added 3 new
  unit tests: dev-default rejected across 3 non-local `region_id`s
  (`eu-central-1`/`ap-seoul-1`/`us-east-1`), dev-default accepted when
  `region_id == "local"`, real endpoint accepted regardless of region.
- Verified: `cargo build --workspace` clean, `cargo test -p powehi-config`
  24/24 (21 pre-existing + 3 new), full `cargo test --workspace` all green
  (no other crate matches on `ConfigError::` variants, confirmed via grep —
  the new enum variant is non-breaking), `cargo clippy -p powehi-config
  --all-targets -- -D warnings` clean.
- **security-auditor: GREEN, one CI-blocking (non-security) nit fixed
  in-cycle.** Confirmed the guard has no bypass on the real code path
  (`load()` is `validate()`'s only caller, unconditional placement, no
  early-return interference); confirmed exact-string-match is correct here
  (targets one specific compiled literal, not a pattern — deliberately
  narrower than matching e.g. `127.0.0.1` variants, which would require a
  *deliberate* operator `set`, out of this guard's scope of catching
  never-set); confirmed `region_id` is non-secret operator-supplied topology
  metadata already printed unredacted by the existing `Debug` impl, so
  embedding it in the new error is compliant with `no-plaintext-logging`;
  confirmed `region_id == "local"` (dev/CI/docker-compose/
  `ci-e2e-live.yml`) is unaffected since none of those set
  `POWEHI__REGION_ID`; confirmed `load_uses_defaults_when_no_env_vars_set`
  builds its own separate `config::Config::builder()` and never calls
  `validate()`, so it's unaffected either way. **Fixed:** `cargo fmt -p
  powehi-config -- --check` failed on the new
  `dev_default_r2_endpoint_in_non_local_region_is_rejected` test's
  single-line `expect_err(&format!(...))` — ran `cargo fmt -p
  powehi-config` to the standard multi-line form, re-verified 24/24 still
  green after. **Two informational advisories, deferred (real, not fixed
  now — matches this cycle's own precedent of not scope-creeping a single
  fail-closed guard into "audit every field"):** (1) `r2_access_key_id`/
  `r2_secret_access_key` default to `""` with no equivalent guard — a
  non-local region with unset credentials starts fine and only fails at the
  first real media call, same silent-until-used shape as the bug this cycle
  fixed, worth its own `region_id != "local"` guard in a future cycle; (2)
  a doc comment on `handle_oracle_secret_token` (line ~159, pre-existing,
  not touched this cycle) says the fallback random key is "per-restart
  only" but `bin/powehi-server/src/main.rs:121-136` now actually persists
  it in `server_config` — stale comment, unrelated to this cycle's diff,
  worth a one-line fix whenever that file is next touched.
- Not architectural (a stricter startup-time validation rule on an existing
  config field, zero new server-visible metadata, zero new API surface) —
  `threat-model-checker` correctly not invoked; not MLS/OPAQUE/WASM crypto
  — `crypto-reviewer` correctly not invoked.
- No Helm/`.rego`/frontend files touched this cycle (pure Rust,
  `crates/infra/powehi-config/src/lib.rs` only) — `helm lint`/`conftest`/
  `pnpm test` correctly not re-run (no-op expected).
- Target dir hygiene: not checked this cycle (FEATURE mode; next due cycle
  385, STABILIZATION).
- **Next cycle candidates:** the two security-auditor advisories above
  (both good FEATURE or STABILIZATION picks, same class as this cycle's own
  fix); cycle 383's advisory #2 (`no_literal_secrets.rego` never inspects
  `ConfigMap` `data` — a credential pasted into `r2Endpoint` would sail
  through all 108 conftest checks undetected, demonstrated concretely);
  cycle 379's YELLOW-1 (`ci-infra.yml` `--skip-tests`/`podSelector` labels
  nit, still open, still low urgency); the long-carried ops/blocked items:
  provision the 3 environments' `grpc-tls-{cert,key,ca}` secret-store keys
  (ops task, not code) and real `r2Endpoint`/`r2Bucket`/`vapidContact`
  values (ops task, not code — chart supports them since cycle 383, and as
  of this cycle a non-local region with the dev default left in place will
  now fail loudly at startup instead of silently misbehaving); activating
  `grpcPeers` for real cross-region mesh traffic (needs its own threat-model
  check); media-key incoming/outgoing asymmetry (multi-part, needs a full
  WASM key-export design, cycle 359); PQ hybrid Phase A (blocked on openmls
  stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on
  ADR-0003 Phase B); project-context.md size (now ~2960 lines — still
  comfortably under the 256KB Read cap, growing steadily, consider trimming
  at STABILIZATION).

## Previous state (2026-08-28, cycle 383 — FEATURE: wire r2_endpoint/r2_bucket/vapid_contact into Helm chart, commit 84e9b71)

- CI green (`gh run list --limit 5` all success), `gh issue list --state open`
  empty, `git status` clean at cycle start. Scoped candidates first via an
  Explore-style agent before picking (media-key incoming/outgoing asymmetry,
  carried since cycle 359, confirmed genuinely NOT cycle-sized — needs a new
  WASM key-export/local-storage-key design derived from the OPAQUE
  `export_key`, all-or-nothing, correctly stays deferred) — then investigated
  the scoping agent's #2 candidate (r2_endpoint/r2_bucket/vapid_contact Helm
  wiring, carried since cycle 359 as "blocked on real Cloudflare values")
  myself and found it does NOT need real values to fix: only the chart
  *plumbing* was missing, not the actual account data.
- **Real bug found while scoping (not just a stale TODO):** grepped
  `crates/infra/powehi-config/src/lib.rs` and confirmed `r2_endpoint`/
  `r2_bucket` have compiled dev-only defaults (`http://localhost:9000`/
  `powehi-media`, `set_default(...)` in `load()`) — so nothing crashes, but
  every deployed environment (prod-eu/prod-ap/staging) has been silently
  running with these dev defaults since day one, since `infra/helm/powehi/`
  never emitted `POWEHI__R2_ENDPOINT`/`POWEHI__R2_BUCKET` at all (confirmed
  via repo-wide grep, zero hits). Worse: `bin/powehi-server/src/main.rs:91-95`
  only constructs a working `VapidWebPushAdapter` when BOTH
  `vapid_private_key_pem` AND `vapid_contact` are `Some` — `vapid_contact` was
  never wired either, so **Web Push (RFC 8291/8292) has been silently
  disabled in every deployed environment**, even though `vapidPrivateKey` IS
  correctly provisioned via ExternalSecret in all 3 `values-*.yaml` files.
  This had gone unnoticed across 20+ cycles because the TODO was always
  phrased as "needs real Cloudflare values" and nobody had checked whether
  the *plumbing itself* existed independent of the values.
- **Fix (delegated to an infra agent):** added `config.r2Endpoint`/
  `config.r2Bucket`/`config.vapidContact` to `values.yaml` (blank by default
  — purely additive, preserves today's exact effective behavior until an
  operator sets a real value), three `{{- if ... }}` conditional emissions in
  `configmap.yaml` mirroring the pre-existing `otlp.endpoint` pattern, and
  matching `values.schema.json` string entries. Deliberately did NOT put
  fabricated values into `values-prod-eu/prod-ap/staging.yaml` — added a
  3-line comment in each noting real values are still needed before go-live.
  Verified myself (not just trusting the agent): `git diff --cached --stat`
  matches exactly the 6 intended files, diff content matches the spec line
  for line.
- **Verification:** `helm lint` clean on chart + all 3 overlays; rendered
  ConfigMap output **byte-identical to HEAD** across all 3 real overlays
  (proves the no-op claim); `conftest test -p infra/policy --combine` 108/108
  pass on every overlay; throwaway `--set config.r2Bucket=...` override
  confirmed the conditional emits correctly when populated, and
  `--set config.r2Bucket=12345` confirmed the new schema entries actually
  enforce `type: string`. `kubeconform` not installed locally, not run
  (noted honestly rather than assumed).
- **security-auditor: GREEN.** Confirmed none of the 3 fields are secrets:
  `r2_endpoint`/`r2_bucket` are already baked into client-visible pre-signed
  URLs (`crates/adapters/outbound/powehi-r2/src/lib.rs:275-322`), and
  `vapid_contact` is the public-by-protocol VAPID JWT `sub` claim (RFC 8292
  §2.1 — telling the push provider how to contact you is the whole point).
  Confirmed `| quote` (Sprig, Go `%q`) safely escapes injection attempts, no
  YAML/template-injection risk, consistent with sibling fields. Confirmed
  `configMapRef` is ordered before `secretRef` in `deployment.yaml` (safe
  even under a hypothetical key collision, though none exists here). Correctly
  scoped as security-auditor-only, no threat-model-checker needed (zero new
  server-visible metadata, restores an already-declared PRD requirement,
  same precedent as cycle 375's GRPC mTLS Helm wiring).
- **Two non-blocking advisories, both deferred to a future cycle (not fixed
  now — out of this cycle's scope, first-time findings):**
  1. No fail-closed guard stops the `http://localhost:9000` dev default from
     silently being used in a non-local `region_id` — an environment that
     ships with `r2Endpoint` still blank gets working-but-wrong pre-signed
     URLs pointed at the end user's own loopback, not a crash. Suggested fix:
     a `validate()` rule in `powehi-config/src/lib.rs` rejecting the dev
     default when `region_id != "local"`.
  2. `infra/policy/no_literal_secrets.rego` inspects `Secret` objects and
     workload `env[].value` (cycle 381) but never `ConfigMap` `data` — so a
     credential accidentally pasted into `r2Endpoint` (e.g.
     `https://user:pass@host`) would sail through all 108 conftest checks
     undetected. Demonstrated concretely with a throwaway `--set` value.
     Suggested fix: a third `deny` rule over `resource.kind == "ConfigMap"`
     reusing the existing `credential_value_pattern`/`credential_name_pattern`
     predicates.
- No `.rs` files touched (pure Helm/config plumbing) — `cargo build`/
  `pnpm test` correctly not re-run (no-op expected, confirmed via
  `git status --short` before commit).
- Target dir hygiene: not checked this cycle (FEATURE mode; next due cycle
  385, STABILIZATION).
- **Next cycle candidates:** the two security-auditor advisories above (both
  good STABILIZATION or FEATURE picks — #2 especially, since it's a concrete
  policy-gate gap with a demonstrated bypass, same class of fix as cycles
  379/381); cycle 379's YELLOW-1 (`ci-infra.yml` `--skip-tests`/`podSelector`
  labels nit, still open, still low urgency); the long-carried ops/blocked
  items: provision the 3 environments' `grpc-tls-{cert,key,ca}` secret-store
  keys (ops task, not code) and now also real `r2Endpoint`/`r2Bucket`/
  `vapidContact` values (ops task, not code — chart now supports them);
  activating `grpcPeers` for real cross-region mesh traffic (needs its own
  threat-model check); media-key incoming/outgoing asymmetry (confirmed
  genuinely multi-part this cycle, needs a full WASM key-export design, not a
  quick fix — see above); PQ hybrid Phase A (blocked on openmls stable
  `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase
  B); project-context.md size (now ~2870 lines — still comfortably under the
  256KB Read cap, but growing steadily, consider trimming at STABILIZATION).

## Previous state (2026-08-28, cycle 382 — FEATURE: SHA-pin GitHub Actions in ci-infra/ci-frontend/ci-rust/ci-e2e-live workflows, commit 3f393c8)

- CI green (`gh run list --limit 3` all success), `git status` clean at cycle
  start. Picked cycle 378's own carried-forward F8: `ci-infra.yml`/
  `ci-frontend.yml`/`ci-rust.yml`/`ci-e2e-live.yml` still referenced GitHub
  Actions by mutable version tag (`actions/checkout@v4`, etc.), while
  `release.yml`/`load-test.yml` already established a SHA-pin-with-version-
  comment precedent (`owner/action@<sha>  # vX`) elsewhere in this repo —
  closing the gap between the two conventions.
- **Fix (delegated to ci-pipeline-author):** resolved every mutable tag to
  its current commit SHA via `git ls-remote`/`gh api` and rewrote each
  `uses:` line to `owner/action@<sha>  # vX` across all 4 files
  (`actions/checkout`, `actions/setup-node`, `actions/upload-artifact`,
  `dtolnay/rust-toolchain@stable`, `Swatinem/rust-cache`,
  `pnpm/action-setup`, `azure/setup-helm`, `hashicorp/setup-terraform`,
  `EmbarkStudios/cargo-deny-action`). Deliberately did NOT reuse the older
  SHAs already pinned in `release.yml` (e.g. `actions/checkout`'s pin there
  predates today's `v4` head) — resolved to what each tag points to *right
  now*, which is the point of a pinning pass. `release.yml`/`load-test.yml`
  untouched.
- **Judgment call: `taiki-e/install-action@nextest` left un-pinned,
  deliberately.** This is not a normal version tag — it's a tool-name tag
  the action's maintainer repoints on every release to track the latest
  nextest-compatible build. Its own README explicitly says SHA-pinning
  `@<tool_name>` tags is "strongly discouraged" since the tag moves and a
  hash pin can end up referencing an "impostor commit" once the old tag
  target is no longer reachable. Left both occurrences (`ci-rust.yml`) on
  `@nextest` with an inline comment citing this rationale, rather than
  blindly SHA-pinning everything for uniformity.
- Independently re-verified before commit (not just trusting the
  implementing agent): re-resolved `actions/checkout@v4`,
  `dtolnay/rust-toolchain@stable`, `azure/setup-helm@v5.0.1`,
  `EmbarkStudios/cargo-deny-action@v2` myself via `git ls-remote` and
  confirmed all 4 SHAs match what was committed; reviewed the full `git
  diff` for all 4 files and confirmed every changed line is either a
  `uses:` ref swap or one of the two new explanatory comment blocks — no
  `with:`/`run:`/job-logic changes; confirmed all 4 files still parse as
  valid YAML via `python3 -c "import yaml..."`.
- Pure CI-config change (no `.rs`/chart/policy files touched) — not
  architectural, not crypto: `threat-model-checker`/`crypto-reviewer`/
  `security-auditor` correctly not invoked, matching precedent for sibling
  CI-only gates (cycles 377-381). `cargo build`/`helm lint`/`conftest`
  correctly not re-run (no-op expected).
- Target dir hygiene: not checked this cycle (FEATURE mode; next due cycle
  385, STABILIZATION).
- **Next cycle candidates (carried forward, unchanged unless noted):**
  cycle 379's YELLOW-1 (the `--skip-tests`/`podSelector` labels-required-on-
  future-Job gotcha in `ci-infra.yml` — still a one-line-comment nit, still
  not urgent); cargo-nextest install consideration (low priority, cosmetic);
  the long-carried ops/blocked items: provision the 3 environments'
  `grpc-tls-{cert,key,ca}` secret-store keys (ops task, not code);
  activating `grpcPeers` for real cross-region mesh traffic (needs its own
  threat-model check); `r2_endpoint`/`r2_bucket`/`vapid_contact` never wired
  into the chart (needs real Cloudflare account values, not fabricated);
  media-key incoming/outgoing asymmetry (multi-part, cycle 359); PQ hybrid
  Phase A (blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid
  OPRF upgrade (gated on ADR-0003 Phase B); consider periodically re-running
  this cycle's SHA-pin pass (pins go stale as upstream actions release new
  versions — no automated Dependabot/renovate config exists yet for
  `.github/workflows/`, worth considering as a future infra item);
  project-context.md size (now ~2790 lines, comfortably under the 256KB
  Read cap — no action needed yet).

## Previous state (2026-08-28, cycle 381 — FEATURE: extend no_literal_secrets.rego to inspect container env[].value, commit 7019046)

- CI green (`gh run list --limit 3` all success), `git status` clean at cycle
  start, no phase checklist items remain unchecked (phases 1-6 all `[x]`;
  this cycle picked from the carried-forward candidate list, same pattern as
  cycles 373-380). Picked cycle 378's F2 (reinforced by cycle 380's own
  notes as "now itself testable immediately"): `no_literal_secrets.rego`
  only ever inspected `kind: Secret` objects' `data`/`stringData` fields —
  an operator pasting a real credential straight into a Deployment's
  `env: - value:` (bypassing ExternalSecret/`envFrom.secretRef` entirely)
  would sail through all 5 conftest checks undetected. Cycle 378's own
  synthetic control (`DATABASE_URL=postgres://u:pw123@db/x` as an env var)
  had already demonstrated this gap.
- **Fix:** added a second `deny` rule to `infra/policy/no_literal_secrets.rego`
  that inspects `containers_of(resource)` (reusing `helpers.rego`'s
  `is_workload_like`/`containers_of`, so Job/CronJob/Pod are covered
  identically to the other 4 checks) for `env[].value` entries (as opposed
  to `env[].valueFrom`) that look like literal credentials: either the env
  var's own name matches a credential-shaped pattern
  (password/passwd/secret/token/api-key/private-key/access-key,
  case-insensitive) with any non-empty value, or the value itself matches a
  credential shape regardless of name (`scheme://user:pass@host` connection
  string, AWS `AKIA[0-9A-Z]{16}` access-key-id, or any `-----BEGIN...` PEM
  block) — the second branch is what catches the DATABASE_URL example,
  where the var name alone gives no signal. Added 15 new tests to
  `no_literal_secrets_test.rego` (predicate-level for
  `credential_name_pattern`/`credential_value_pattern`/
  `is_credential_looking_env`, plus end-to-end deny-firing/deny-absent
  integration tests on synthetic Deployment fixtures) — 44 → 59 total
  `test_*` rules. Also added a compliant `env: valueFrom: secretKeyRef`
  entry to `compliant_manifest_test.rego`'s golden fixture so the new
  sub-rule is passively exercised by the "fully compliant → zero denials"
  integration test too, not just its own dedicated tests.
- Verified non-vacuous via mutation testing before delegating to review:
  `conftest verify -p infra/policy` 59/59 clean, then temporarily replaced
  `credential_name_pattern`/`credential_value_pattern`'s first two rule
  bodies with `false`, confirmed exactly 6 tests went red (the ones directly
  exercising those two rules and their positive callers), restored and
  reconfirmed 59/59 green. Re-ran all 3 real overlays (prod-eu, prod-ap,
  staging) through `helm template | conftest test --combine` — still 6/6
  pass (test-group count went 5→6 since the check now has its own group;
  confirmed via grep that the real chart renders zero `env[].value` entries
  today, only `envFrom` — pure future-regression guard on production,
  matching the same "vacuous-today, real-guard" status as check (c)'s
  original Secret-object rule and several sibling checks).
- **security-auditor: YELLOW, both findings fixed in-cycle.** Independently
  verified (own reading, not trusting my summary): confirmed
  `is_credential_looking_env` safely no-ops on non-string/missing `value`
  and on `valueFrom`-only entries (guarded by `is_string(object.get(env,
  "value", null))` before any pattern call) — no crash, no false-negative
  surprise; confirmed the RE2 regexes are correctly escaped/unanchored;
  confirmed the `any_credential_deny`-scoped "absent" tests genuinely test
  *this* rule's silence (its message contains the unique substring "literal
  credential", no collision with the original rule's "literal secret
  value") rather than accidentally passing because the whole `deny` set
  happened to be empty for an unrelated reason. **F1 (fixed):** the
  `-----BEGIN` value-pattern's doc comment said "PEM private key block" but
  the code matches any PEM header (cert, CSR, public key too) — corrected
  the comment to state the actual (deliberately broad) behavior and why
  erring toward false positives is the right trade-off for a secret-leak
  gate. **F2 (fixed):** `compliant_manifest_test.rego`'s docstring/golden
  fixture didn't reference or passively exercise the new sub-check — added
  the `valueFrom` env entry (above) and updated the docstring to mention it.
  Noted-but-accepted as intentional (not fixed, matches this cycle's own
  stated design): bare name-substring matching (`password`/`token`/`secret`)
  means a future non-secret config name like `TOKEN_EXPIRY_SECONDS` would
  also trip the gate if ever added as a literal `env[].value` — confirmed
  via repo-wide grep this doesn't false-positive on anything today (only
  `externalSecrets.remoteRefs.*`/`secretStoreRef.name`-shaped config exists,
  neither of which is ever env-injected), and matches the stated "err
  toward false positive over silent credential leak" philosophy for a
  security-gate rule, consistent with how `no_literal_secrets.rego`'s
  original Secret-object check already treats ANY non-empty string as
  suspect with zero allowlist. Not architectural (pure additive Rego-only
  change, zero chart-rendered-output change, no new API surface/DB column/
  server-visible metadata) and not crypto — `threat-model-checker`/
  `crypto-reviewer` correctly not invoked, matching precedent from cycles
  377-380 for sibling infra-CI-only policy gates.
- No `.rs`/`values.yaml`/overlay/workflow files touched (confirmed via
  `git status --short`: only the 3 `infra/policy/*.rego` files) —
  `cargo build --workspace`/`pnpm test` correctly not re-run (no-op
  expected, pure Rego-only cycle).
- Target dir hygiene: not checked this cycle (FEATURE mode; next due cycle
  385, STABILIZATION).
- **Next cycle candidates (carried forward, unchanged unless noted):**
  cycle 379's YELLOW-1 (the `--skip-tests`/`podSelector` labels-required-on-
  future-Job gotcha in `ci-infra.yml` — still a one-line-comment nit, still
  not urgent); F8 (SHA-pinning-vs-signature-verification nit on
  `actions/checkout`/`setup-helm`/`setup-terraform`, pre-existing, low
  urgency); cargo-nextest install consideration (low priority, cosmetic);
  the long-carried ops/blocked items: provision the 3 environments'
  `grpc-tls-{cert,key,ca}` secret-store keys (ops task, not code);
  activating `grpcPeers` for real cross-region mesh traffic (needs its own
  threat-model check); `r2_endpoint`/`r2_bucket`/`vapid_contact` never wired
  into the chart (needs real Cloudflare account values, not fabricated);
  media-key incoming/outgoing asymmetry (multi-part, cycle 359); PQ hybrid
  Phase A (blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid
  OPRF upgrade (gated on ADR-0003 Phase B); project-context.md size (now
  ~2740 lines, comfortably under the 256KB Read cap — no action needed yet,
  though it's grown steadily and a future cycle should consider trimming
  the oldest "Previous state" entries once it starts approaching the cap).

## Previous state (2026-08-28, cycle 380 — STABILIZATION: conftest verify regression test gate, commit a72177a)

- CI green (`gh run list --limit 3` all success), `git status` clean at cycle
  start, no open `gh issue list --state open` items. Followed the
  STABILIZATION playbook's test-gap step and picked up cycle 378's own F7
  candidate (reinforced by cycle 379's memory notes as the top remaining
  item): the 5-check conftest/OPA policy gate (`infra/policy/*.rego`) had
  **zero regression coverage of its own** — every negative control from
  cycles 378/379 (missing resource limits, `:latest` tag, literal secret,
  `runAsNonRoot: false`, no deny-all NetworkPolicy, the CronJob deep-nesting
  path) existed only in agent transcripts, never as a re-runnable test. A
  future refactor of a helper (`pod_spec`/`containers_of`/
  `workload_pod_labels`) or a `deny` condition could silently reintroduce a
  vacuous-pass gap — exactly the class of bug fixed in cycle 379 (da1aa63)
  — with nothing in CI to catch it.
- **Fix:** added 7 new `infra/policy/*_test.rego` files (44 `test_*` OPA
  unit-test rules total, same `package main` as the production rules they
  test): `helpers_test.rego` (kind-dispatch correctness, explicit CronJob
  deep-nesting + Job/Pod/CronJob `is_workload_like` coverage — the highest-
  value regression target given cycle 379's fix), one `_test.rego` per
  check file (`resource_limits_test.rego`, `network_policy_test.rego`,
  `no_latest_tag_test.rego`, `no_literal_secrets_test.rego`,
  `run_as_nonroot_test.rego` — each with direct predicate-level unit tests
  plus one end-to-end `deny`-firing test using `contains(msg, "...")` to
  avoid false cross-contamination from the other 4 checks' denies sharing
  the same unioned `deny` partial-set rule), and
  `compliant_manifest_test.rego` (one golden fully-compliant-manifest
  integration fixture asserting `count(deny) == 0` — every field in it is
  load-bearing, i.e. removing any single one flips it to a denial). Wired
  `conftest verify -p infra/policy` into `.github/workflows/ci-infra.yml`
  right after the "Install conftest" step, before the per-overlay
  `helm template | conftest test --combine` loop (fail-fast: a broken
  policy package now fails at the cheap unit-test step, not a confusing
  downstream overlay failure). No production `.rego` file was modified —
  additive test-only change plus one CI step.
- Verified non-vacuous via mutation testing before delegating to review:
  ran `conftest verify -p infra/policy` clean (44/44), then temporarily
  flipped `resource_limits.rego`'s `not has_resource_limits(container)` →
  `has_resource_limits(container)`, confirmed exactly the 3 expected tests
  went red (`test_deny_fires_for_container_missing_limits`,
  `test_deny_fires_for_cronjob_container_missing_limits`,
  `test_fully_compliant_manifest_has_zero_denials`), restored the file and
  reconfirmed all green. Also re-ran `conftest test` against all 3 real
  overlays (prod-eu, prod-ap, staging) — still 5/5 pass, confirming the new
  test suite didn't require any change to the chart itself.
- **security-auditor: GREEN, no findings.** Independently re-read all 7 new
  test files + all 6 production `.rego` files + the CI diff (not trusting
  my own summary), confirmed fixture shapes accurately mirror real rendered
  K8s YAML for every kind exercised (Deployment/CronJob/Pod/NetworkPolicy/
  Secret), traced every `count(deny) == 0` test to confirm none is
  vacuously true (each depends on a real absence-of-violation condition,
  not an input shape that could never trigger any deny rule), grepped to
  confirm no rule anywhere reads `input[i].path` (so fixtures omitting the
  `path` key conftest's real `--combine` envelope includes are safe —
  `all_resources` only ever projects `.contents`), manually recounted all
  44 `test_*` rules across the 7 files to confirm the reported "44 tests,
  44 passed" wasn't silently skipping anything, independently verified my
  mutation-testing methodology and result were sound without re-running it,
  confirmed conftest v0.69.0 (already pinned in this workflow) supports
  `verify -p <dir>` as a stable flag and auto-discovers `*_test.rego` by
  suffix (no risk of a silently-empty glob), confirmed the new CI step has
  no `if:`/`continue-on-error` and runs unconditionally, and confirmed the
  two intentionally-fake credential-shaped test fixtures
  (`postgres://u:pw123@db/x`, base64 `hunter2`) are obviously synthetic
  placeholder data, not a real-secret-in-repo concern. Not architectural
  (test-only addition, zero production Rego/chart-output change, no new API
  surface/DB column/server-visible metadata) and not crypto —
  `threat-model-checker`/`crypto-reviewer` correctly not invoked, matching
  precedent from cycles 377/378/379 for sibling infra-CI-only gates.
- Also ran the rest of the STABILIZATION security sweep: `cargo audit`
  clean (0 advisories across 652 crate dependencies), `cargo deny check`
  clean (`advisories ok, bans ok, licenses ok, sources ok` — only
  pre-existing duplicate-dependency-version warnings from the normal
  ecosystem-transition dependency graph, e.g. `rand`/`getrandom`/`hashbrown`
  each pulled in at 2-5 versions transitively; not a new regression, no
  Cargo.toml/Cargo.lock touched this cycle), `cargo build --workspace`
  clean, `cargo test --workspace` clean (nextest not installed locally on
  this runner — used the documented fallback; 0 failures across every
  crate, only pre-existing `#[ignore]`d testcontainers-gated integration
  tests skipped as expected without Docker).
- Target dir hygiene: `target/` is 27GB (over the 20GB prune threshold),
  ran the 0-byte `.rmeta` sweep (nothing to remove) and the `mtime +7`
  prune pass — found nothing old enough to prune (all artifacts recent from
  active cycles), so size is unchanged at 27GB. Not urgent enough to force-
  delete recent incremental-cache artifacts; will re-check next
  STABILIZATION cycle (385).
- Real push to `main` confirmed (commit a72177a, 8 files changed, all
  additive). No `.rs`/`values.yaml`/overlay files touched.
- **Next cycle candidates (carried forward, unchanged from cycle 379 unless
  noted):** this cycle's own YELLOW-1 from cycle 379 (the `--skip-tests` /
  `podSelector` labels-required-on-future-Job gotcha in `ci-infra.yml` —
  still worth a one-line comment, still not urgent); cycle 378's F2
  (extend `no_literal_secrets.rego` to inspect container `env[].value` for
  credential-looking literals) — now itself testable immediately via the
  new `no_literal_secrets_test.rego` once implemented; F8 (SHA-pinning-vs-
  signature-verification nit on `actions/checkout`/`setup-helm`/
  `setup-terraform`, pre-existing, low urgency); the long-carried items:
  provision the 3 environments' `grpc-tls-{cert,key,ca}` secret-store keys
  (ops task, not code); activating `grpcPeers` for real cross-region mesh
  traffic (needs its own threat-model check); `r2_endpoint`/`r2_bucket`/
  `vapid_contact` never wired into the chart (needs real Cloudflare account
  values, not fabricated); media-key incoming/outgoing asymmetry
  (multi-part, cycle 359); PQ hybrid Phase A (blocked on openmls stable
  `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003
  Phase B); project-context.md size (now comfortably under the 256KB Read
  cap — no action needed yet). New this cycle: consider installing
  `cargo-nextest` on this runner (fell back to `cargo test` this cycle,
  works fine but nextest gives per-test timing/retries the plain runner
  doesn't — low priority, not a gate failure).

## Previous state (2026-08-27, cycle 379 — FEATURE: cover Job/CronJob/bare-Pod in conftest policy gate, commit da1aa63)

- CI green (`gh run list --limit 3` all success), `git status` clean at cycle
  start. Picked cycle 378's own F5 candidate: `helpers.rego`'s
  `workload_kinds` omitted `Job`/`CronJob` entirely, and 2 of the 4
  workload-scoped checks (`network_policy.rego`, `run_as_nonroot.rego`)
  gated their `deny` rule directly on `is_workload(resource)`, silently
  skipping bare `Pod` — inconsistent with the other 2 checks
  (`resource_limits.rego`, `no_latest_tag.rego`), which handled Pod via
  local `workload_containers`/`tagged_image_containers` wrappers. Confirmed
  via grep before starting: chart renders no `Job`/`CronJob` today (pure
  future-regression guard, chart 100% compliant regardless).
- **Fix (delegated to infra-lead):** added `"Job"` to `workload_kinds`
  (PodTemplateSpec at `.spec.template.*`, shape-identical to Deployment —
  safe to fold in directly). Deliberately did NOT add `"CronJob"` to
  `workload_kinds` — its PodTemplateSpec is nested one level deeper at
  `.spec.jobTemplate.spec.template.*`, so naively including it would make
  `pod_spec`/`workload_pod_labels` look in the wrong place. Instead added a
  canonical `is_workload_like(resource)` predicate (`is_workload` OR
  `kind == "CronJob"` OR `kind == "Pod"`) plus CronJob-specific
  `pod_spec`/`workload_pod_labels` rule bodies, and switched all 4
  workload-scoped checks to gate on `is_workload_like`. Collapsed
  `containers_of`'s duplicate rule bodies into one (now that `pod_spec`
  resolves correctly for every `is_workload_like` kind), and deleted the
  now-redundant `workload_containers`/`tagged_image_containers` wrappers
  from `resource_limits.rego`/`no_latest_tag.rego`, calling `containers_of`
  directly instead — a net simplification, not just an addition.
- **security-auditor: GREEN, 2 YELLOW advisories (informational, deferred).**
  Independently verified (own conftest runs, not trusting the implementing
  agent): confirmed `is_workload_like`/`pod_spec`/`workload_pod_labels`'s
  rule bodies are provably mutually exclusive on `resource.kind` (no Rego
  complete-rule conflict), confirmed the CronJob path
  (`jobTemplate.spec.template.spec`) matches the real K8s
  `CronJobSpec→JobTemplateSpec→JobSpec→PodTemplateSpec→PodSpec` schema
  nesting, ran synthetic Job/CronJob/Pod controls (Job missing limits →
  now fails `resource_limits`; CronJob missing `runAsNonRoot` → now fails
  `run_as_nonroot` *and* `resource_limits`, proving the deep path actually
  resolves rather than yielding an empty container list; bare Pod with no
  covering NetworkPolicy → now fails `network_policy`; re-ran the same 3
  against the pre-change policy via `git show HEAD:` and confirmed all 3
  passed vacuously before — the gap was real, not a tautology), re-verified
  all 3 overlays still 5/5 pass. **YELLOW-1 (deferred, real):**
  `ci-infra.yml` runs `helm template` without `--skip-tests`, so a future
  `templates/tests/*.yaml` Helm test Pod or a pre-install migration Job
  would newly be subject to `network_policy`/`run_as_nonroot` — and
  `networkpolicy.yaml`'s selector uses `powehi.selectorLabels`, not an
  empty `podSelector: {}`, so any future Job/CronJob/Pod must carry those
  labels or it fails `network_policy` — flagged for whoever adds the first
  Job, not a defect today. **YELLOW-2 (cosmetic, deferred):**
  `network_policy.rego`'s comment says "workload's pod labels" which for a
  bare Pod actually means `.metadata.labels`, not a pod template; the new
  `is_workload_like` guard in `resource_limits.rego`/`no_latest_tag.rego`
  is technically redundant with `containers_of`'s own internal gate
  (harmless, not a bug). Not architectural (pure policy-as-code addition,
  zero chart-rendered-output change for any resource this chart actually
  renders) and not crypto — `threat-model-checker`/`crypto-reviewer`
  correctly not invoked, matching cycle 378's own precedent.
- Process note: the security-auditor agent hit a self-inflicted `git stash`
  mishap mid-review (a `git stash push -- infra/policy/ -q` mis-parsed `-q`
  as a pathspec and no-op'd, then the follow-on `git stash pop` applied an
  unrelated pre-existing `stash@{0}` (cycle 301 WIP), producing conflicts
  across `app/`/`crates/`) — recovered immediately via `git reset` +
  `git checkout -- app crates`, disclosed transparently, confirmed
  afterward (independently, by me) that `git status --short` showed only
  the 5 intended `infra/policy/*.rego` files and `stash@{0}` (cycle 301)
  was still intact and unconsumed. No data lost. Same failure class as
  cycle 374's round-2 auditor incident — worth remembering agents
  shouldn't `git stash` scoped-by-pathspec without care for `-q`/flag
  ordering, but not worth a process change for a 2nd occurrence in ~180
  cycles.
- No `.rs`/`values.yaml`/overlay/workflow files touched (confirmed via
  `git status --short` before commit: only the 5 `infra/policy/*.rego`
  files) — `cargo build --workspace` correctly not re-run (no-op expected).
  Real push to `main` confirmed; CI run not yet observed to complete as of
  this memory write (will show in next cycle's `gh run list`).
- Target dir hygiene: not checked this cycle (FEATURE mode; next due cycle
  380, STABILIZATION).
- **Next cycle candidates:** cycle 378's remaining F2/F7 (extend
  `no_literal_secrets.rego` to inspect container `env[].value` for
  credential-looking literals; add a `conftest verify` + `*_test.rego`
  fixture test gate for the Rego policies themselves, since today's
  negative controls exist only in agent transcripts); this cycle's own
  YELLOW-1 (the `--skip-tests` / `podSelector` labels-required-on-future-
  Job gotcha — worth a one-line comment in `ci-infra.yml` or
  `network_policy.rego` next time someone touches either, not urgent
  enough alone); F8 from cycle 378 (SHA-pinning-vs-signature-verification
  nit on `actions/checkout`/`setup-helm`/`setup-terraform`, pre-existing
  pattern, low urgency); the long-carried items: provision the 3
  environments' `grpc-tls-{cert,key,ca}` secret-store keys (ops task, not
  code); activating `grpcPeers` for real cross-region mesh traffic (needs
  its own threat-model check); `r2_endpoint`/`r2_bucket`/`vapid_contact`
  never wired into the chart (needs real Cloudflare account values, not
  fabricated); media-key incoming/outgoing asymmetry (multi-part, cycle
  359); PQ hybrid Phase A (blocked on openmls stable `MLS_128_MLKEM768`);
  OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B); project-
  context.md size (now ~2490 lines, comfortably under the 256KB Read cap
  — no action needed yet).

## Previous state (2026-08-27, cycle 378 — FEATURE: wire conftest OPA policy gate into CI, commit 957a901)

- CI green (`gh run list --limit 5` all success), `git status` clean at cycle
  start. **Note: cycle 377's memory update was skipped** (process gap, not a
  content gap) — backfilled below from `git log`/CI history before this
  cycle's own entry, since it directly motivates this cycle's work.
- Picked cycle 376's carried-forward candidate #4, now half-closed by cycle
  377: `.claude/rules/testing-conventions.md` line 33 requires the Helm/K8s
  static-validation gate to be `helm lint`, `helm template` → `kubeconform`
  **+ `conftest`** (resource limits, deny-all NetworkPolicy, no literal
  secrets, no `:latest`, runAsNonRoot). Cycle 377 wired `helm lint` +
  `kubeconform` into `.github/workflows/ci-infra.yml` (commits 09a35bf,
  e5720b1) but not `conftest` — confirmed via `find . -iname '*.rego'` /
  `-iname 'conftest*'` returning nothing repo-wide before starting.
- **Fix (delegated to infra-lead):** new `infra/policy/` — 6 Rego files
  (`helpers.rego` shared `all_resources`/`is_workload`/`containers_of`
  unwrap under conftest's `--combine` per-document envelope shape, then one
  file per check: `resource_limits.rego`, `network_policy.rego`,
  `no_latest_tag.rego`, `no_literal_secrets.rego`, `run_as_nonroot.rego`),
  covering exactly the 5 checks named in testing-conventions.md — no scope
  creep beyond that list. Wired a SHA-verified `conftest` v0.69.0 install
  step (same curl+checksums.txt+`sha256sum --check` pattern as the existing
  kubeconform step) plus `helm template ... | conftest test - -p
  ../../policy --combine` per overlay (prod-eu, prod-ap, staging), right
  after the existing kubeconform step in the same loop. No base-chart-alone
  conftest step: `helm template` with no overlay hard-fails on a
  pre-existing unrelated `values.region is required` guard in
  `configmap.yaml` (rendering failure, not a policy failure) — `helm lint`
  already covers base-chart-alone at the lint level, so this was a
  deliberate scope decision, not a chart fix; no `values.yaml`/overlay files
  touched.
- Verified before delegating review: all 3 overlays render clean today (5/5
  conftest checks pass) — the chart was already compliant with all 5 checks,
  a new gate should not fail on existing good config. One negative control
  per rule (`--set image.tag=latest`, `--set networkPolicy.enabled=false`,
  synthetic missing-`resources` Deployment, synthetic `runAsNonRoot: false`,
  synthetic literal-`stringData` Secret) each independently confirmed to
  fire — not tautologies. All scratch files/dirs deleted after use.
- **security-auditor: YELLOW, fixed in-cycle.** Re-ran every rule
  independently (own local OPA/Helm, not trusting the implementing agent's
  claims) plus 9 synthetic controls, confirmed conftest's `--combine`
  actually flattens multi-doc stdin into one envelope per document (probed
  the real `input` shape: `array` of `{contents, path}`), matching
  `helpers.rego`'s unwrap — the top vacuous-pass risk was clean. Findings:
  **F1 (MEDIUM, fixed)** — the workflow's `paths:` trigger filter (both
  `push`/`pull_request`) listed `infra/helm/**`/`infra/terraform/**`/the
  workflow file itself but NOT `infra/policy/**` — a PR that guts or deletes
  a `.rego` file wouldn't have triggered this workflow at all, silently
  bypassing the gate it just added. Fixed: added `infra/policy/**` to both
  trigger blocks. **F3/F4 (LOW, fixed)** — two Rego comments made claims the
  auditor's own empirical probing disproved: `network_policy.rego` claimed
  an empty `podSelector` would NOT be miscounted as covering a workload
  (verified behavior is the opposite — and that's *correct* K8s
  NetworkPolicy semantics, just a wrong comment); `no_latest_tag.rego`
  implied the CI gate blocks an operator's `--set image.tag=latest` at
  actual deploy time, which it cannot (render-time-only check; real deploy-
  time enforcement needs an admission controller). Both comments corrected
  to state what the rule actually does/doesn't guarantee. Re-verified all 3
  overlays still 5/5 pass after both fixes, workflow YAML re-parsed clean.
  Deferred (real gaps, not urgent): **F2** `no_literal_secrets.rego` only
  inspects `kind: Secret` objects (this chart renders none — everything
  goes through `ExternalSecret` — so it's vacuous today, a future-regression
  guard only) and doesn't yet inspect container `env[].value` for
  credential-looking literals (the auditor's synthetic
  `DATABASE_URL=postgres://u:pw123@db/x` env var passed 5/5); **F5**
  `helpers.rego`'s `workload_kinds` omits `Job`/`CronJob` (chart renders
  neither today, `run_as_nonroot.rego` additionally skips bare `Pod`
  inconsistently with the other two rules that do handle it); **F7** the
  Rego policies themselves have no test gate (`conftest verify` +
  `*_test.rego` fixtures — the negative controls above exist only in agent
  transcripts, not as regression tests); **F8 (pre-existing, not this
  diff)** — `actions/checkout@v4`/`azure/setup-helm@v5.0.1`/
  `hashicorp/setup-terraform@v4.0.1` are tag- not SHA-pinned, and neither
  the kubeconform nor conftest install verifies a release signature
  (cosign/SLSA), only a checksums file from the same origin as the artifact.
  Not architectural (pure additive CI static-analysis gate, zero chart-
  rendered-output change, no new API surface/DB column/server-visible
  metadata) and not crypto — `threat-model-checker`/`crypto-reviewer`
  correctly not invoked, matching cycle 377's own precedent for the sibling
  kubeconform gate.
- No `.rs`/`values.yaml`/overlay files touched — `cargo build --workspace`
  correctly not re-run (no-op expected, Helm/CI-only cycle). Real push to
  `main` confirmed `CI — Infra` green with the new conftest step actually
  executing (not just local verification).
- Target dir hygiene: not checked this cycle (FEATURE mode; next due cycle
  380, STABILIZATION).
- **Next cycle candidates:** F2/F5/F7 above (extend `no_literal_secrets` to
  container `env[].value`; add `Job`/`CronJob` to `workload_kinds` +
  `run_as_nonroot`'s `Pod` handling; add a `conftest verify` test gate for
  the Rego itself) — all real, non-urgent, well-scoped for a future infra
  cycle; F8's SHA-pinning-vs-signature-verification nit (pre-existing
  pattern, low urgency); the still-open items carried from cycle 376:
  provision the 3 environments' `grpc-tls-{cert,key,ca}` secret-store keys
  (ops task, not code); activating `grpcPeers` for real cross-region mesh
  traffic (needs its own threat-model check); `r2_endpoint`/`r2_bucket`/
  `vapid_contact` never wired into the chart (needs real Cloudflare account
  values, not fabricated); media-key incoming/outgoing asymmetry (multi-
  part, cycle 359); PQ hybrid Phase A (blocked on openmls stable
  `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003
  Phase B); project-context.md size (now ~2380 lines, comfortably under the
  256KB Read cap — no action needed yet).

## Previous state (2026-08-27, cycle 377 — FEATURE: helm lint/template + kubeconform + terraform validate CI gate, commits 09a35bf/e5720b1 — backfilled retroactively in cycle 378, memory update was skipped that cycle)

- Added `.github/workflows/ci-infra.yml`: `helm-validate` job (`helm lint`
  base chart + per-overlay `helm lint`/`helm template | kubeconform` for
  prod-eu/prod-ap/staging) and `terraform-validate` job (`terraform fmt
  -check -recursive` + `init -backend=false && validate` for dev/prod-eu/
  prod-ap-seoul). Closed cycle 374's long-open candidate: infra static
  validation had been fully absent from CI since the chart/Terraform were
  introduced.
- First real run on `main` caught 2 genuine pre-existing issues (commit
  e5720b1, same cycle): `kubeconform` errored on `ExternalSecret`/
  `ServiceMonitor` CRDs with "could not find schema" (not in its built-in
  core/standard set) — fixed by adding the `datreeio/CRDs-catalog`
  `-schema-location`; `terraform fmt -check` found genuine pre-existing
  alignment drift in `modules/hetzner-k3s/main.tf` — fixed via `tofu fmt
  -recursive` (whitespace only).
- Left `conftest` (the other half of testing-conventions.md's stated
  requirement) unwired — closed by cycle 378 above.

## Previous state (2026-08-27, cycle 376 — FEATURE: add minLength validation for externalSecrets.remoteRefs, commit 5211f5c)

- CI green (`gh run list --limit 5` all success), `gh issue list --state open` empty,
  `git status` clean at cycle start. Picked cycle 375's own documented informational
  gap: `values.schema.json` had **zero** `externalSecrets` schema coverage at all
  (confirmed via grep before starting — not partial, total). `templates/
  externalsecret.yaml` interpolates every `externalSecrets.remoteRefs.*` value
  directly into an ExternalSecret's `remoteRef.key` with no Helm-side check — an
  operator setting one to `""` would previously render `key: ""` silently, only
  caught by External Secrets Operator's own apiserver validation at apply time
  (fail-closed, but late — not at `helm lint`/schema time).
- **Fix (delegated to infra-lead):** added an `externalSecrets` object to
  `infra/helm/powehi/values.schema.json` (draft-07, matching the file's existing
  style) — `enabled` (boolean), `refreshInterval` (string), `secretStoreRef.
  {name,kind}` (string, `minLength: 1`), and the actual fix: `remoteRefs.
  {databaseUrl,redisUrl,r2AccessKeyId,r2SecretAccessKey,vapidPrivateKey,
  grpcTlsCert,grpcTlsKey,grpcTlsCa}` each `{"type":"string","minLength":1}`. Purely
  additive (+27/-0 lines) — deliberately did not touch `values.yaml`/any
  `values-{prod-eu,prod-ap,staging}.yaml` overlay/any template, since all 4 already
  populate all 8 keys with non-empty Vault-path strings (verified by grep before
  delegating, independently re-verified by both the implementing agent and the
  security-auditor pass). No `required` array added anywhere in the new blocks, so
  overlays that legitimately omit `externalSecrets.enabled` (all 3 do, inheriting
  `true` from base `values.yaml` via Helm's value-merge) are unaffected.
- Negative-control verification (both by the implementing agent and independently
  by me before commit): `helm template ... --set
  externalSecrets.remoteRefs.databaseUrl=""` now fails with `minLength: got 0, want
  1` (exit 1), confirming the schema actually catches the bug it targets; the same
  command without the override still renders successfully. `helm lint` green for
  base `values.yaml` alone and all 3 overlays layered on top.
- **security-auditor: GREEN.** Independently confirmed (not rubber-stamped): `git
  diff --stat` shows the change is purely additive (0 deletions) so no pre-existing
  schema key was clobbered or restructured; only Vault-style path strings (e.g.
  `"powehi/database-url"`, `"powehi/prod-eu/grpc-tls-cert"`) appear anywhere in the
  schema/diff/values files, never actual secret material; re-ran `helm lint` for
  all 4 value-file combinations independently. Not architectural (pure client-
  side/lint-time Helm value validation, zero runtime behavior change, no new API
  surface or server-visible metadata) and not crypto — `threat-model-checker`/
  `crypto-reviewer` correctly not required, matching cycle 375's precedent for the
  same file's `minimum` schema additions.
- No `.rs` files touched — `cargo build --workspace` unaffected (not re-run, no-op
  expected and consistent with precedent for Helm/YAML-only cycles e.g. 375/373).
  No frontend files touched.
- Target dir hygiene: not checked this cycle (FEATURE mode; next due cycle 380,
  STABILIZATION).
- **Next cycle candidates (unchanged from cycle 375, still open):** the security-
  auditor's flagged operational precondition from cycle 375 — provision the 3
  environments' `grpc-tls-{cert,key,ca}` secret-store keys before that cycle's
  change lands on staging's auto-sync (an ops task, not code, still worth flagging);
  activating `grpcPeers` for real cross-region mesh traffic needs its own separate
  threat-model check (that's when §3.5.2's inter-region traffic-analysis mitigations
  actually matter); `r2_endpoint`/`r2_bucket`/`vapid_contact` never wired into the
  chart at all (needs real Cloudflare R2 account/bucket values per region, not
  fabricated); wiring `helm lint`/`helm template`+`kubeconform`+`conftest` into CI
  (still fully absent from every workflow per cycle 374's audit); media-key
  incoming/outgoing asymmetry (multi-part, cycle 359); PQ hybrid Phase A (blocked on
  openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on
  ADR-0003 Phase B); project-context.md size (now ~2270 lines, comfortably under the
  256KB Read cap — no action needed yet).

## Previous state (2026-08-27, cycle 375 — STABILIZATION: wire GRPC mTLS material into Helm via Secret volume mount, commit a1c8ab1)

- CI green (`gh run list --limit 5` all success), `gh issue list --state open` empty,
  `git status` clean at cycle start. Full sweep first, everything green, nothing to
  fix from it: `cargo build/test --workspace` (all crates 0 failures), `cargo clippy
  --workspace --all-targets -- -D warnings` clean, `cargo fmt --check` clean, `cargo
  audit` 0 advisories (652 crates), `cargo deny check` clean, frontend `pnpm test
  --run` 1504/1504 green (105 files), `tsc -b`/`biome check` clean (172 files).
  Target dir was 27G (over the 20G prune threshold) — pruned 0-byte `.rmeta` stubs
  and ran the `-mtime +7` artifact prune, size unchanged (27G → 27G, nothing was
  actually >7 days stale) — housekeeping only, doesn't count as the cycle's commit.
- Since the sweep found nothing to fix, picked cycle 374's own documented follow-up
  (a real gap, not a hypothetical): that cycle deliberately left `GRPC_TLS_CERT`/
  `KEY`/`CA` unwired because those `AppConfig` fields (`grpc_tls_cert/key/ca`, plain
  `String`) are consumed as filesystem *paths* via `TlsConfig::from_pem_files`
  (`std::fs::read`), not raw PEM content — env-var injection can't work for them
  regardless of naming. Scoped it first via an Explore agent before committing to the
  fix: confirmed `values-prod-eu.yaml`/`values-prod-ap.yaml`/`values-staging.yaml`
  all already declared `grpcTlsEnabled: "true"` (operator intent for mTLS), but the
  value was **100% dead** — it rendered into `POWEHI__GRPC_TLS_ENABLED`, which
  matches no `AppConfig` field (config-rs has no `deny_unknown_fields`, silently
  dropped) — so `grpc_tls_enabled()` (the real derived gate: all three path fields
  non-empty) was always `false` everywhere. `grpcPeers` is `""` in every environment
  today, so this was latent, not actively exploited — but the gRPC 50051 listener ran
  **plaintext in every environment regardless**, contradicting prd.md §4A.4's
  mTLS-for-all-inter-region-gRPC requirement and the values files' own stated intent.
- **Fix (delegated to infra-lead):** repurposed `config.grpcTlsEnabled` from a dead
  quoted-string enum into a real Helm boolean gating: a new Secret volume mounted at
  `/etc/powehi/tls` in `deployment.yaml`, and `POWEHI__GRPC_TLS_CERT/KEY/CA` in
  `configmap.yaml` pointing at the mounted paths (static in-container path strings,
  safe in a ConfigMap — only the mounted file *contents* are secret). Split the TLS
  material into its own `ExternalSecret`/Secret (`<fullname>-grpc-tls`), consumed
  *only* via volume mount — deliberately removed from the main `powehi-secret`'s
  `envFrom`-injected data list, since `TlsConfig::from_pem_files` needs paths, not
  env content, and per security-auditor this closes a real pre-existing exposure
  (raw `GRPC_TLS_KEY` PEM bytes were being dumped into every pod's env via
  `envFrom.secretRef`, readable via `/proc/*/environ`, `kubectl exec -- env`, or a
  crash-log env dump — not new to this cycle, just now fixed as a side effect).
  Added a `fail()` guard in `deployment.yaml`: `grpcTlsEnabled=true` +
  `externalSecrets.enabled=false` refuses to render (verified via `helm template
  --set config.grpcTlsEnabled=true --set externalSecrets.enabled=false` → exit 1).
  Default (`values.yaml`) stays `false` (dev/single-region, zero behavior change);
  prod-eu/prod-ap/staging flip their existing `"true"` string to a real `true` bool,
  making their long-stated intent finally functional. **`grpcPeers` deliberately left
  `""` everywhere** — turning on the actual cross-region mesh is out of scope, a
  separate future change. Also closed cycle 374's own left INFO nit while touching
  `values.schema.json` anyway: added `"minimum": 1` to the three integer config
  knobs (`databaseMaxConnections`/`r2RequestTimeoutSecs`/`mediaGcSweepTimeoutSecs`)
  wired in that cycle, closing the Sprig-`default`-treats-`0`-as-empty footgun at the
  schema layer instead of relying solely on the Rust-side `validate()` floor.
- **threat-model-checker: GREEN.** Confirmed this is a non-architectural bug fix
  restoring an already-declared prd.md §4A.4 requirement, not a new decision — no
  prd.md/ADR update needed. Full T1–T7 impact matrix: strictly hardens T1 (passive
  eavesdropper: plaintext h2c → TLS 1.3) and T2 (active MITM: peer-cert verification
  goes from inert to real); marginally hardens T3/T7 (closes a same-namespace
  unauthenticated-RPC window the checker found the briefing had *understated* — pre-
  change, the gRPC listener ran with `tls_required: false` regardless of peer config,
  so `verify_peer_region()` never actually gated anything); T4/T5/T6 unchanged (T6
  correctly noted as out of scope — this is classical TLS 1.3 for the ops/inter-
  region transport layer, unrelated to ADR-0003's PQ-hybrid work on the MLS/E2EE
  plane). No tier weakened, no new server-visible metadata.
- **security-auditor: GREEN.** Verified via `helm lint` + `helm template` across all
  3 real environments plus edge cases (missing-Secret and invalid-remoteRef paths
  both fail closed — pod mount block or process-startup bail, never silent plaintext
  degrade; repo-wide grep found zero other consumers of the removed unprefixed
  `GRPC_TLS_CERT/KEY/CA` keys). One non-blocking **operational** precondition, not a
  code issue: the 3 environments' `grpc-tls-{cert,key,ca}` secret-store entries must
  actually be populated before merge lands on a GitOps-automated environment, or
  ExternalSecret sync failure stalls (doesn't crash) the next rollout — staging
  auto-syncs (`selfHeal: true`), prod-eu/ap are manual-sync gated. Both reviewers
  independently flagged the same low-severity nit — fixed in-cycle: the
  `checksum/grpc-tls-secret` pod-annotation comment claimed rotation triggers a
  rollout, but it hashes the ExternalSecret *template text* (remoteRef path
  strings), not the actual fetched cert bytes Helm can never see — corrected the
  comment to say so honestly instead of implying working rotation-triggered
  rollout. Declined the auditor's own flagged optional `defaultMode: 0400` hardening
  idea per its own caution: would make `tls.key` unreadable by `runAsUser: 1000`
  without a matching `fsGroup`, breaking startup — not worth the risk for a
  world-readable-but-single-process-container nit.
- Full `helm lint`/`helm template` (3 envs + fail-guard edge case) re-verified after
  the comment fix; `cargo build --workspace` re-verified clean (confirmed zero `.rs`
  files touched — this is Helm/YAML-only). No frontend files touched.
- **Next cycle candidates:** the security-auditor's flagged operational precondition
  above (provision the 3 environments' grpc-tls secret-store keys before this lands
  on staging's auto-sync — an ops task, not a code change, flagging here so it isn't
  missed); the checker's noted future gate — **activating `grpcPeers` for real
  cross-region mesh traffic needs its own separate threat-model check** (that's when
  §3.5.2's inter-region traffic-analysis mitigations actually matter, not this
  cycle's plumbing-only change); the values.schema.json gap the auditor noted
  (`externalSecrets.remoteRefs.*` has no `minLength: 1`, so an explicit empty
  override renders `key: null` — caught by ESO's apiserver validation, fail-closed,
  but not by Helm — informational, not urgent); media-key incoming/outgoing
  asymmetry (multi-part, cycle 359); PQ hybrid Phase A (blocked on openmls).

## Previous state (2026-08-27, cycle 374 — FEATURE: wire GC/timeout config into Helm + fix broken POWEHI__ key names, commit 753f3ad)

- CI green (`gh run list --limit 5` all success), `gh issue list --state open` empty,
  `git status` clean at cycle start. Picked cycle 373's own top carried-forward
  candidate: Helm wiring for `database_max_connections`/`r2_request_timeout_secs`/
  `media_gc_sweep_timeout_secs` — three prior-cycle config knobs (369/371/372) never
  exposed via Helm, every environment silently ran the compiled default.
- **What it does, part 1 (delegated to infra-lead):** added `databaseMaxConnections:
  20`/`r2RequestTimeoutSecs: 30`/`mediaGcSweepTimeoutSecs: 1800` to
  `infra/helm/powehi/values.yaml`'s `config:` block (byte-identical to the Rust
  compiled defaults, zero behavior change today — deliberately did NOT invent
  per-environment override numbers, since real Postgres/R2 capacity isn't provisioned
  via this repo's Terraform, confirmed by grep) and threaded into
  `templates/configmap.yaml` as three new `POWEHI__*` keys.
- **What it does, part 2 (found during review, fixed same-cycle):** while verifying the
  `POWEHI__` prefix convention (`config::Environment::with_prefix("POWEHI")
  .separator("__")`), discovered the chart's env var names didn't actually match
  `AppConfig`'s fields in THREE places, meaning several secrets/config never reached
  the process in any real deployment:
  - `externalsecret.yaml`'s Secret keys `DATABASE_URL`/`REDIS_URL`/`R2_ACCESS_KEY_ID`/
    `R2_SECRET_ACCESS_KEY`/`VAPID_PRIVATE_KEY` were missing the `POWEHI__` prefix
    entirely (config-rs silently drops unprefixed env vars — confirmed against pinned
    `config` 0.14.1 source, `env.rs:239-269`), and the VAPID key's name didn't match
    the actual field `vapid_private_key_pem` (missing `_PEM`). `database_url`/
    `redis_url`/`r2_access_key_id`/`r2_secret_access_key` have no serde default, so
    this would crash-loop any real deployment at startup (fail-closed, not a silent
    security downgrade — confirmed no dependency in the tree, sqlx/redis/aws-sdk-s3,
    independently reads the old unprefixed names as its own fallback convention, so
    this was purely dead config, not "secretly working another way"). Fixed: renamed
    all 5 secretKeys to their correct `POWEHI__`-prefixed form. Deliberately left
    `GRPC_TLS_CERT`/`KEY`/`CA` unprefixed/unfixed — those three fields are consumed as
    filesystem *paths* (`TlsConfig::from_pem_files`,
    `bin/powehi-server/src/main.rs:240`), not raw PEM content, so a prefix-only rename
    would not make TLS provisioning work and would additionally leak cert/key material
    into a startup error log (`std::fs::read` failing on a "path" that's actually a
    giant PEM blob, embedded in the error context) — needs a Secret volumeMount
    redesign instead, tracked via an in-file comment as a follow-up, not attempted this
    cycle.
  - `configmap.yaml`'s `POWEHI__REGION` didn't match the field `region_id` (no
    `deny_unknown_fields`, so silently dropped) — every deployment silently fell back
    to the compiled default `region_id: "local"` regardless of the per-environment
    `eu-frankfurt`/`ap-seoul` value in `values-prod-eu.yaml`/`values-prod-ap.yaml` — a
    **data-residency bug**, since `region_id` is written permanently into
    `groups.home_region` in Postgres and exposed via `AppState.region_id`. Fixed:
    renamed to `POWEHI__REGION_ID`.
  - `configmap.yaml`'s `POWEHI__LOG_LEVEL` matched no `AppConfig` field at all — log
    level is actually controlled by `tracing_subscriber::EnvFilter
    ::try_from_default_env()` (`crates/infra/powehi-telemetry/src/lib.rs`), which reads
    the `RUST_LOG` env var by `tracing-subscriber`'s own convention, not anything
    config-rs/POWEHI-prefixed. Fixed: renamed the ConfigMap key to plain `RUST_LOG`.
- **security-auditor: 3 rounds, GREEN/YELLOW-resolved each round.** Round 1 (the
  ConfigMap knob wiring alone): GREEN, 2 informational nits (values.schema.json has no
  `minimum` constraints for the 3 new integers; Sprig `default` treats `0` as empty so
  an operator setting e.g. `databaseMaxConnections: 0` silently renders the fallback
  instead of failing — both left as follow-ups, Rust-side `validate()` floor is
  authoritative regardless). Round 2 (the 5-secretKey rename): YELLOW — confirmed all 5
  renames correct and confirmed (adversarially, per explicit ask) that the old
  unprefixed names weren't secretly load-bearing via some other mechanism (traced
  sqlx/redis/aws-sdk-s3's actual credential-loading call sites, all take explicit
  `cfg.*` params, none read `DATABASE_URL`/`REDIS_URL`/`R2_ACCESS_KEY_ID` as a fallback
  — `envFrom.secretRef` in `deployment.yaml` is the *only* consumer of the K8s Secret
  chart-wide) — but flagged the still-open `POWEHI__REGION`/`POWEHI__LOG_LEVEL`
  mismatches in the sibling file being edited in the same cycle and recommended
  bundling. Round 3 (final consolidated sweep after fixing REGION_ID/RUST_LOG):
  GREEN-with-one-deferred-finding — independently verified `RUST_LOG` really is
  `tracing-subscriber`'s `DEFAULT_ENV` constant (traced to pinned `tracing-subscriber`
  0.3.23 source, empirically probed with a scratch binary) and `POWEHI__REGION_ID`
  really reaches `region_id` (empirically probed against pinned `config` 0.14.1); did
  one *complete* side-by-side sweep of every `POWEHI__*` key in the whole chart against
  every `AppConfig` field (table in the agent's report) and found a **third** inert key
  — `POWEHI__GRPC_TLS_ENABLED` matches no field (`grpc_tls_enabled` is a derived
  *method*, not a field; the actual mTLS gate is 3 empty path fields, and
  `values.yaml`/`values.schema.json` setting `grpcTlsEnabled: "true"` gives operators
  false assurance mTLS is on when it's actually off) — correctly NOT fixed this cycle
  since there's no field to rename to; it's not a cosmetic delete either (a bare
  deletion doesn't make TLS work), so it correctly collapses into the same deferred
  `GRPC_TLS_CERT/KEY/CA` volume-mount follow-up rather than being a separate task.
  Mitigating factors for why this is Medium-not-High severity today: `main.rs:230`
  fails closed (bails at startup) if `grpc_peers` is non-empty while TLS is off;
  `grpcPeers` is `""` in every current env overlay (no cross-region traffic exists
  yet); `networkpolicy.yaml` restricts port-50051 ingress to same-namespace only. Also
  surfaced (informational, out of scope): `r2_endpoint`/`r2_bucket`/`vapid_contact` are
  emitted nowhere in the chart at all (not a mismatch, just never wired), so production
  would fall back to `http://localhost:9000` / `powehi-media` / push-disabled — a
  distinct, separate gap from this cycle's "wrong key name" bug class, needs real
  Cloudflare R2 account/bucket values not fabricated this cycle. `cargo build
  --workspace` clean (no `.rs` files touched, confirmed no-op as expected), `cargo test
  -p powehi-config` 21/21 green. `helm lint` + `helm template` (all 3 env overlays)
  render correctly throughout all 3 rounds. `cargo audit`: 0 vulnerabilities (652
  crates). Not crypto, not a new architectural/server-visible-metadata surface (fixes
  existing config delivery, adds no new API/DB column/client-facing behavior) —
  `crypto-reviewer`/`threat-model-checker` correctly not invoked.
- 0 new automated tests (pure Helm/YAML key-naming fix, no `.rs` logic changed) — this
  class of bug (chart env-var name vs. Rust field name drift) has no test gate today;
  `helm-conventions.md`/`testing-conventions.md` call for `kubeconform`/`conftest` on
  rendered manifests, but round 3's audit confirmed **neither is installed nor wired
  into any CI workflow** (checked all 6 `.github/workflows/*.yml` files) — infra static
  validation is currently manual/best-effort only, a real gap (see next-cycle
  candidates).
- Target dir hygiene: not checked this cycle (FEATURE mode; next due cycle 375,
  STABILIZATION).
- Process note: the round-2 security-auditor agent hit a self-inflicted git mishap
  mid-review (ran `git stash push` with a wrong-cwd relative pathspec, which no-op'd,
  then a chained `git stash pop` popped an unrelated pre-existing cycle-301 WIP stash,
  producing conflict markers across ~10 files) — recovered correctly per `git status`
  investigate-before-discarding guidance (`git reset --hard` was correctly blocked by
  `.claude/hooks/block-dangerous-bash.sh`; used `git checkout HEAD -- .` + restored the
  2 in-progress infra files from verified backups), disclosed the incident transparently
  in its own report, and the stash (`stash@{0}`, cycle 301 WIP) was confirmed still
  intact afterward. No data lost. Also this cycle: `git commit` was blocked once by the
  same hook's `PRIVATE_KEY`/`SECRET_KEY` literal-substring secret-scan on the commit
  *message* itself (false positive — describing a field/env-var name, not an actual
  secret value) — worked around by rephrasing the message to avoid the literal
  uppercase substrings rather than bypassing the hook.
- **Next cycle candidates:** the `GRPC_TLS_CERT`/`KEY`/`CA` + `POWEHI__GRPC_TLS_ENABLED`
  volume-mount redesign (now doubly motivated — cross-region gRPC mTLS cannot
  currently work at all via this chart, and the ConfigMap actively misrepresents its
  status as `"true"`; needs `deployment.yaml` Secret volumeMount + `POWEHI__GRPC_TLS_*`
  set via ConfigMap to the mount path instead of Secret content, plus removing the
  inert `grpcTlsEnabled` value/schema entries); `r2_endpoint`/`r2_bucket`/
  `vapid_contact` never wired into the chart at all (needs real Cloudflare R2
  account/bucket values per region + a real VAPID contact URI, not fabricated this
  cycle, same "don't invent operational values" precedent as capacity numbers);
  `values.schema.json` missing `minimum` constraints for the 3 new integer knobs added
  this cycle (shift bad-operator-input left from runtime CrashLoop to `helm lint`);
  wiring `helm lint`/`helm template`+`kubeconform`+`conftest` into CI at all (currently
  fully absent from every workflow — infra-lead + ci-pipeline-author territory,
  matches `.claude/rules/testing-conventions.md`'s and `helm-conventions.md`'s own
  stated requirement that isn't actually enforced anywhere); the still-open
  hexagonal-layering-adjacent Postgres connection-budget research (cycle 369, needs
  real managed-DB `max_connections`, not provisioned via this repo's Terraform); the
  pre-existing (not worsened) `R2MediaAdapter::delete` two-sequential-non-transactional-
  awaits gap (self-healing, not urgent, cycle 372); media-key incoming/outgoing
  asymmetry (confirmed genuinely multi-part, cycle 359); PQ hybrid Phase A (still
  blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated
  on ADR-0003 Phase B, itself gated on Phase A); frontend `pnpm audit`'s 23 dev/
  build-time findings (vitest/wrangler/vite transitive, not urgent); project-context.md
  size (now ~2100 lines, comfortably under the 256KB Read cap — no action needed yet).

## Previous state (2026-08-27, cycle 373 — FEATURE: move GC advisory-lock primitive off R2 adapter onto powehi-postgres, commit 35d10df)

- CI green (`gh run list --limit 3` all success), `git status` clean at cycle start.
  Picked the hexagonal-layering nit carried forward since cycle 368: `try_gc_lock`/
  `GcLockGuard`/`GC_LOCK_MEDIA_BLOBS`/`GC_LOCK_MEDIA_LEDGER` — a pure Postgres
  session-advisory-lock primitive with zero R2/S3 dependency — lived on
  `R2MediaAdapter` in the `powehi-r2` crate, reached from `main.rs` only via a
  concrete-type escape hatch (`media_r2_lock` clone) around the `MediaRepository`
  port, purely so the two background GC jobs could reach Postgres-specific helpers
  that weren't part of any port.
- **What it does:** new `crates/adapters/outbound/powehi-postgres/src/leader_lock.rs`
  module — `PgLeaderLock::new(pool)` + `try_lock(key) -> Result<Option<GcLockGuard>,
  DomainError>`, `GcLockGuard`, `GC_LOCK_MEDIA_BLOBS`/`GC_LOCK_MEDIA_LEDGER` — moved
  verbatim (same SQL, same detach-on-Drop safety reasoning, same `#[must_use]`, same
  bit-identical lock-key constants so a rolling deploy mixing old/new replicas still
  shares the same advisory-lock namespace). `main.rs` now builds
  `Arc<PgLeaderLock>` directly from the shared `pool.clone()` instead of cloning the
  concrete `R2MediaAdapter` just to reach lock helpers; both background job closures
  (hourly media-blob GC, daily ledger trim) call `.try_lock(GC_LOCK_MEDIA_*)` /
  `.release().await` exactly as before, just through the new type. `powehi-r2`'s
  `lib.rs` shrinks by ~115 lines (pure deletion, no remaining references). 3
  testcontainers advisory-lock tests moved from `powehi-r2/tests/r2_media_it.rs`
  (which needed the file's two-container Postgres+MinIO harness just to reach them)
  to `powehi-postgres/tests/pg_security_it.rs` (Postgres-only `setup()`, already
  existed), constructing `PgLeaderLock::new(pool)` directly instead of routing
  through `R2MediaAdapter`.
- **security-auditor: GREEN.** Verified genuinely, not rubber-stamped: mechanically
  diffed the removed `powehi-r2` block against the new `leader_lock.rs` (post
  comment-normalization) and confirmed the only differences are the new struct/impl
  wrapper — all SQL, Drop/detach logic, and doc-comment safety reasoning are
  byte-identical; independently confirmed the `GC_LOCK_*` constants are bit-identical
  (`0x706f_7765_6869_0001`/`_0002`) so no rolling-deploy lock-namespace mismatch;
  confirmed `main.rs`'s two call sites still use the correct (non-swapped) key per
  job; confirmed the 3 moved tests are not vacuous — traced exactly which regression
  each would catch (e.g. a guard that returns its connection to the pool instead of
  holding it would make the "already held" test's second `try_lock` reuse the same
  session and wrongly succeed, since advisory locks are re-entrant within a session);
  confirmed zero dangling references to the old `powehi_r2::try_gc_lock` symbol
  repo-wide via grep, `cargo audit`/`cargo deny check` clean, no `Cargo.lock`/schema/
  proto/infra file touched anywhere in the diff — correctly not architectural, not
  crypto (`threat-model-checker`/`crypto-reviewer` correctly skipped). One doc-nit
  finding fixed in-cycle: a stale `(see \`powehi_r2::try_gc_lock\`)` cross-reference
  in `powehi-config`'s `MIN_DATABASE_MAX_CONNECTIONS` floor-rationale comment (missed
  by this cycle's initial diff, since `powehi-postgres/src/lib.rs`'s own 2 references
  were already updated) — corrected to
  `powehi_postgres::leader_lock::PgLeaderLock::try_lock`. Second nit (added the new
  advisory-lock test coverage to `pg_security_it.rs`'s module-doc invariant list, which
  had drifted out of sync) also applied in-cycle. Noted informational, no fix needed:
  `try_lock(key: i64)` takes a bare `i64` rather than a closed enum, unchanged from
  the pre-move design, only 2 hardcoded callers exist and no user input reaches it;
  `PgLeaderLock` is a concrete inherent-method type rather than a full port trait —
  judged reasonable since Postgres advisory locks aren't a swappable-backend
  abstraction (the documented PgBouncer-transaction-mode deployment invariant is
  exactly why) and the only consumer is the composition root in `main.rs`.
  Pre-existing frontend `pnpm audit` findings (23, dev/build-time-only —
  vitest/wrangler/vite transitive) noted as out-of-scope, unrelated to this diff.
- 0 new tests (pure move, not new logic) — the 3 moved advisory-lock tests are
  unchanged in assertions, just relocated + retargeted at `PgLeaderLock` directly.
  `cargo build/test --workspace` clean (all green, 0 failed, same ~50 Docker-gated
  ignored count as before, just redistributed 3 from `powehi-r2` to
  `powehi-postgres`), `cargo clippy --workspace --all-targets -- -D warnings` clean,
  `cargo fmt --check` clean. `cargo audit`: 0 vulnerabilities. `cargo deny check`:
  advisories/bans/licenses/sources all ok. No `Cargo.lock` diff (zero dependency
  change, pure code move).
- Target dir hygiene: not checked this cycle (FEATURE mode; next due cycle 375,
  STABILIZATION).
- **Next cycle candidates:** Helm wiring for `database_max_connections` (cycle 369),
  `r2_request_timeout_secs` (cycle 371), and `media_gc_sweep_timeout_secs`
  (cycle 372) — all three need one combined infra-lead pass with real DB/R2 capacity
  numbers not yet researched; the pre-existing (not worsened) `R2MediaAdapter::delete`
  two-sequential-non-transactional-awaits gap (self-healing via idempotent R2
  `DELETE` on a missing key, not urgent, cycle 372); media-key incoming/outgoing
  asymmetry (confirmed genuinely multi-part, cycle 359); PQ hybrid Phase A (still
  blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade
  (gated on ADR-0003 Phase B, itself gated on Phase A); frontend `pnpm audit`'s 23
  dev/build-time findings (vitest/wrangler/vite transitive, no production runtime
  impact — a version-bump cycle, not urgent); project-context.md size (now ~2000
  lines, comfortably under the 256KB Read cap — no action needed yet).

## Previous state (2026-08-27, cycle 372 — FEATURE: bound aggregate media-GC sweep duration, commit f179b0a)

- CI green (`gh run list --limit 5` all success), `gh issue list --state open` empty,
  `git status` clean at cycle start. Picked cycle 371's own documented-not-fixed residual:
  the R2 per-call timeout added that cycle bounds one S3 operation, but the *whole* hourly
  media-blob GC sweep (`MediaService::run_gc_batched`, potentially many pages of many
  per-blob deletes) had no aggregate bound — N slow-but-not-hung deletes at ~10s
  attempt-timeout each could still sum past the next hourly tick while holding the
  cross-replica Postgres advisory lock (`GC_LOCK_MEDIA_BLOBS`, cycle 368), delaying every
  other replica's attempt indefinitely (not just locally).
- **What it does:** new `AppConfig.media_gc_sweep_timeout_secs`
  (`crates/infra/powehi-config/src/lib.rs`, default 1800s = 30 min, same
  set_default/validate/ConfigError/Debug-field pattern as cycle 369's
  `database_max_connections` / cycle 371's `r2_request_timeout_secs`) wraps the
  `media_gc.run_gc()` call in `bin/powehi-server/src/main.rs`'s hourly-interval task with
  `tokio::time::timeout(media_gc_sweep_timeout, media_gc.run_gc()).await`. The advisory
  lock's `guard.release().await` runs unconditionally after the `match` on all three
  outcomes (success / `DomainError` / timeout `Elapsed`), so a timeout can't leak the lock.
  On timeout, logs `gc.media_run_timed_out` with only `error_kind` (no IDs/sizes — ZK
  invariant preserved). `media_gc_sweep_timeout` (a `Duration`, `Copy`) is computed once
  from `cfg` before `tokio::spawn` and reused every tick, avoiding any lifetime issue with
  `cfg` itself.
- Floor `MIN_MEDIA_GC_SWEEP_TIMEOUT_SECS = 30` (a single GC page can legitimately take
  several seconds). **security-auditor round 1: GREEN with one optional suggestion**
  (verified mid-sweep-cancellation safety directly against `run_gc_batched`'s code — the
  keyset cursor `after_id` is a local recomputed from `None` every call, so a
  timeout-cancelled sweep just re-lists candidates fresh next tick, no leaked pagination
  state; confirmed the lock-release-in-all-outcomes claim by reading the match arms;
  confirmed logging hygiene; flagged one pre-existing non-worsened gap in
  `R2MediaAdapter::delete`'s two-sequential-non-transactional-awaits, out of scope) — the
  one suggestion was a cross-field check that `media_gc_sweep_timeout_secs` be
  meaningfully larger than `r2_request_timeout_secs`, since at the shipped defaults (1800
  vs 30) nothing bites, but an operator could otherwise tighten the sweep timeout down
  near its own 30s floor while leaving `r2_request_timeout_secs` at a normal value, letting
  a single slow-but-healthy R2 call consume the entire sweep budget and time out every
  tick with zero net progress. **Applied in-cycle** (cheap, not deferred): new
  `MEDIA_GC_SWEEP_TIMEOUT_MIN_MULTIPLE_OF_R2 = 2` constant + a `MediaGcSweepTimeoutTooCloseToR2Timeout`
  `ConfigError` variant + a `validate()` arm requiring `media_gc_sweep_timeout_secs >= 2 *
  r2_request_timeout_secs`. Not architectural (pure timeout knob, no new API surface, DB
  column, or server-visible metadata) and not crypto — `threat-model-checker`/
  `crypto-reviewer` correctly not required, matching cycle 371's precedent.
- 5 new `powehi-config` tests (default/below-floor/at-or-above-floor for the new field,
  plus 2 for the cross-field 2x check: rejected-at-59-vs-30, accepted-at-exactly-60-vs-30)
  — updated the pre-existing `media_gc_sweep_timeout_at_or_above_floor_is_accepted` test to
  pin `r2_request_timeout_secs` at its own floor (5) so its existing assertions (checking
  only the standalone floor) still clear the new cross-field check too. `cargo
  build/test --workspace` clean (0 failures across all crates), `cargo clippy --workspace
  --all-targets -- -D warnings` clean, `cargo fmt --check` clean. No `Cargo.lock` diff.
- Target dir hygiene: not checked this cycle (FEATURE mode; next due cycle 375,
  STABILIZATION).
- **Next cycle candidates:** Helm wiring for both `r2_request_timeout_secs` (cycle 371) and
  now `media_gc_sweep_timeout_secs` — bundle with cycle 369's still-open
  `database_max_connections` Helm gap, needs infra-lead + real DB/R2 capacity numbers not
  yet researched; the hexagonal-layering nit (`try_gc_lock` living on the R2/S3-named
  adapter instead of a `LeaderLock` port on `powehi-postgres`, cycle 368); the
  pre-existing (not worsened) `R2MediaAdapter::delete` two-sequential-non-transactional-
  awaits gap flagged by this cycle's security-auditor pass (self-heals via idempotent R2
  `DELETE` on a missing key, existed since before this cycle for crash/restart-during-GC,
  not urgent); media-key incoming/outgoing asymmetry (confirmed genuinely multi-part,
  cycle 359); PQ hybrid Phase A (still blocked on openmls stable `MLS_128_MLKEM768`);
  OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B, itself gated on Phase A);
  project-context.md size (now ~1930 lines, comfortably under the 256KB Read cap — no
  action needed yet).

## Previous state (2026-08-26, cycle 371 — FEATURE: bound R2 S3 client request timeout, commit e5779db)

- CI green (`gh run list --limit 3` all success), `gh issue list --state open` empty,
  `git status` clean at cycle start. Picked cycle 368's own deferred candidate (still
  open as of cycle 370's next-cycle list): the R2 `S3Client` had no configured request
  timeout, so a hung R2 network call from the hourly media-blob GC job's `delete()`
  could hang that background task indefinitely — and since cycle 368 added a Postgres
  advisory lock (`try_gc_lock`) guarding it across replicas, a hang on one replica now
  blocks the job **cluster-wide**, not just locally.
- **What it does:** new `R2MediaAdapter::new(..., request_timeout_secs: u64)` param
  (`crates/adapters/outbound/powehi-r2/src/lib.rs`), wired into a new
  `build_s3_config()` free fn (extracted from `new()` so the timeout wiring is
  unit-testable without a `PgPool`) via `S3ConfigBuilder::timeout_config(TimeoutConfig
  ::builder().operation_timeout(request_timeout_secs).operation_attempt_timeout
  (request_timeout_secs / 3, floored at 1s).build())` — operation timeout bounds the
  whole retry loop, attempt timeout bounds one attempt; deliberately NOT set equal
  (see security-auditor finding below) so a single stalled attempt doesn't consume the
  whole retry budget and starve the SDK's standard 3-attempt retry policy. New
  `AppConfig::r2_request_timeout_secs` (default 30, `crates/infra/powehi-config/src/lib.rs`,
  same floor-validation pattern as cycle 369's `database_max_connections` —
  `MIN_R2_REQUEST_TIMEOUT_SECS`, `ConfigError::R2RequestTimeoutTooLow`), threaded
  through `main.rs`'s `R2MediaAdapter::new` call site and the testcontainers
  integration test's `setup()`. No new dependency: `TimeoutConfig` is a clean
  re-export at `aws_sdk_s3::config::timeout::TimeoutConfig` (verified against the
  vendored `aws-sdk-s3` 1.133.0 source — it's literally `pub use
  ::aws_smithy_types::timeout::{TimeoutConfig, TimeoutConfigBuilder};`), so
  `Cargo.toml`/`Cargo.lock` are untouched.
- **security-auditor: 1 round, YELLOW → fixed in-cycle, effectively GREEN.** Verified
  (not rubber-stamped) against the actual vendored `aws-smithy-runtime`/`aws-smithy-types`
  source rather than trusting the implementing agent's claims: confirmed the timeout
  genuinely takes effect on a client built via `S3Client::from_conf` (not just
  `aws_config::load_from_env()`) — `from_conf` installs the identical
  `default_plugins()` set including the sleep-impl plugin, which resolves via
  `default_async_sleep()` only under the `rt-tokio` feature (enabled workspace-wide);
  confirmed the SDK's own default `connect_timeout` (~3.1s) survives layering under
  user config rather than being clobbered (`MergeTimeoutConfig` takes missing fields
  from defaults, doesn't replace wholesale). 4 findings, all fixed same-cycle rather
  than deferred (all cheap): (1) **BLOCKING-adjacent** — original diff set
  `operation_timeout == operation_attempt_timeout`, which meant a stalled first
  attempt would consume the *entire* operation budget, so the SDK's retry policy
  never got a second chance — fixed by deriving `operation_attempt_timeout` as
  `request_timeout_secs / 3` (floored at 1s) in the new `build_s3_config()`, with 2
  new unit tests (`build_s3_config_attaches_operation_and_attempt_timeouts`,
  `build_s3_config_floors_attempt_timeout_at_one_second`) pinning both the ratio and
  the floor directly against `aws_sdk_s3::Config::timeout_config()` — zero I/O, no
  Docker needed, exactly the "is `TimeoutConfig` silently ignored" risk the auditor
  flagged as untested; (2) the floor `MIN_R2_REQUEST_TIMEOUT_SECS` was originally 1
  (just "reject zero") — auditor pointed out 1s itself passes validation but is
  **guaranteed broken** since it's below the SDK's own ~3.1s default connect timeout,
  a silent total media-GC outage that clears naive validation — raised to 5, doc
  comment on the const explains why; (3) doc/error-message overclaim — the original
  diff's rationale text (config field doc, `ConfigError` message, adapter module doc)
  claimed a hung R2 call could hang "the GC/ledger-trim background jobs" plural, but
  the daily ledger-trim job (`trim_upload_ledger_older_than`) is 100% Postgres/sqlx,
  never calls R2 — corrected all three sites to name only the hourly media-blob GC
  job, since a future reader would otherwise misjudge the advisory-lock blast radius;
  (4) test coverage gap closed via the two new unit tests above rather than a
  Docker-dependent hang-simulation test (auditor agreed the latter is a poor harness
  fit). Confirmed not crypto (no MLS/OPAQUE/KDF/AEAD touched) — `crypto-reviewer`
  correctly not required; confirmed not architectural (no new API surface, DB column,
  or server-visible metadata — pure network-timeout knob, availability not
  confidentiality/integrity) — `threat-model-checker` correctly not required.
  Documented-not-fixed residual (correctly out of this cycle's scope, matches
  precedent): `POWEHI__R2_REQUEST_TIMEOUT_SECS` isn't in the Helm ConfigMap, same gap
  as `database_max_connections` since cycle 369 — both need one combined infra-lead
  pass; aggregate GC-sweep duration is still unbounded (N slow-but-not-hung deletes at
  ~10s attempt-timeout each can still hold the advisory lock past the next hourly
  tick) — the fix bounds *per-call* hang, not total sweep wall-clock, follow-up would
  be wrapping the guarded job body in `tokio::time::timeout`.
- 4 new/updated Rust tests: 2 new unit tests in `powehi-r2` (`build_s3_config_*`,
  above), `powehi-config`'s 3 new `r2_request_timeout_*` tests
  (`_default_is_30`, `_below_floor_is_rejected` — now checks both 0 and
  `MIN_R2_REQUEST_TIMEOUT_SECS - 1`, not just 0, per the auditor's point that only
  testing zero wouldn't have caught a too-low-but-nonzero floor bug —
  `_at_or_above_floor_is_accepted`), 1 line added to the existing
  `load_uses_defaults_when_no_env_vars_set`. `cargo build/test --workspace` clean (all
  suites green, 0 failed — 726+ tests across the workspace, exact count not
  re-tallied), `cargo clippy --workspace --all-targets -- -D warnings` clean, `cargo
  fmt --check` clean. No `Cargo.lock` diff — `cargo audit`/`cargo deny check` (run by
  the security-auditor pass) both clean, 652 crates scanned, 0 vulnerabilities.
- Target dir hygiene: not checked this cycle (FEATURE mode; next due cycle 375,
  STABILIZATION).
- **Next cycle candidates:** the two residuals documented-not-fixed above (Helm
  wiring for `r2_request_timeout_secs` — bundle with cycle 369's still-open
  `database_max_connections` Helm gap, needs infra-lead + real DB/R2 capacity numbers
  not yet researched; `tokio::time::timeout` around the whole guarded GC-job body to
  bound aggregate sweep duration, not just per-call latency); the hexagonal-layering
  nit (`try_gc_lock` living on the R2/S3-named adapter instead of a `LeaderLock` port
  on `powehi-postgres`, cycle 368); media-key incoming/outgoing asymmetry (confirmed
  genuinely multi-part, cycle 359); PQ hybrid Phase A (still blocked on openmls stable
  `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B,
  itself gated on Phase A); project-context.md size (now ~1870 lines, comfortably
  under the 256KB Read cap — no action needed yet).

## Previous state (2026-08-26, cycle 370 — STABILIZATION: align testcontainers pools with powehi_postgres::connect, commit de324a3)

- CI green (`gh run list --limit 5` all success), `gh issue list --state open` empty,
  `git status` clean at cycle start.
- Picked cycle 369's own carried-forward informational note: `pg_security_it.rs` and
  `r2_media_it.rs` (both `#[ignore]`d testcontainers integration suites) built their test
  Postgres pool via a bare `sqlx::PgPool::connect(&url)`, bypassing the crate's own
  `powehi_postgres::connect(url, max_connections)` helper that production code (`main.rs`'s
  `pg_connect`) has used since cycle 369's explicit-pool-size fix. Harmless at the time
  (sqlx's implicit default of 10 happened to sit above cycle 369's new floor of 3), but
  meant `try_gc_lock`'s own test suite (and every other adapter test in these two files)
  exercised a differently-configured pool than production, and would silently drift further
  if the production default (currently 20) ever changed without these files being touched.
- **What it does:** both `setup()` helpers now call `powehi_postgres::connect(&url, 10)`
  instead of `PgPool::connect(&url)` — kept the cap at 10 (matching the old implicit sqlx
  default, ample for these fixtures' concurrency) rather than production's 20, since test
  pools don't need to match production capacity, only go through the same construction path.
  `sqlx::PgPool` import stays used elsewhere in both files (struct fields / helper fn
  signatures) so no unused-import warning.
- **security-auditor: GREEN.** Confirmed `powehi_postgres::connect()` is a thin
  `PgPoolOptions::new().max_connections(n).connect(url)` wrapper with no extra validation,
  no `min_connections` override, no logging — so the swap is behaviorally identical besides
  the explicit cap; confirmed no plaintext/secret logging (the two `.expect(...)` messages
  are static strings, and the connection URL itself is just a local testcontainers
  `postgres://postgres:postgres@127.0.0.1:<port>/postgres`, not a real secret); confirmed
  `max_connections=10` is sane for a single ephemeral-container-per-test fixture. Not
  architectural (test-only, no production/schema/dependency change) — `threat-model-checker`
  correctly not required; not crypto — `crypto-reviewer` correctly not required.
- `cargo build --workspace` and `cargo build --workspace --tests` both clean (confirms the
  `#[ignore]`d Docker-gated tests in both files still compile). `cargo test --workspace`:
  42/42 test binaries `test result: ok`, 0 failures (no Docker in sandbox so the
  testcontainers tests themselves stay `ignored`, same as every prior cycle — will run for
  real in CI's Rust workflow). `cargo clippy --workspace --all-targets -- -D warnings` clean,
  `cargo fmt --check` clean. `cargo audit`: 0 vulnerabilities (652 crates scanned, exit 0).
  `cargo deny check`: advisories ok, bans ok, licenses ok, sources ok. No `Cargo.lock` diff
  (test-only change, zero dependency impact).
- Target dir hygiene: `target/` was 25G (> the 20G threshold). Ran the 0-byte `.rmeta` prune
  (no-op, none found) and the `mtime +7` prune of `target/debug/deps`/`incremental` — also a
  no-op, every artifact in the tree is younger than 7 days (an actively-building project, not
  stale bloat). Left at 25G; not a failure, just nothing eligible to prune this cycle. Worth
  revisiting if growth continues without natural turnover.
- **Next cycle candidates (unchanged from cycle 369, still open):** derive/document a
  Postgres-side connection budget and wire `database_max_connections` through Helm
  `values.yaml` per environment instead of the baked-in default of 20 (needs infra-lead + a
  real number for the managed Postgres's own `max_connections`, not currently provisioned via
  Terraform — check where/how the DB is actually hosted before picking this); a lease/TTL or
  R2 `S3Client` request timeout so a hung GC/ledger-trim task can't block that job
  cluster-wide indefinitely (cycle 368); the hexagonal-layering nit (`try_gc_lock` living on
  the R2/S3-named adapter instead of a `LeaderLock` port on `powehi-postgres`); media-key
  incoming/outgoing asymmetry (confirmed genuinely multi-part, cycle 359); PQ hybrid Phase A
  (still blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated
  on ADR-0003 Phase B, itself gated on Phase A); project-context.md size (now ~1760 lines,
  comfortably under the 256KB Read cap — no action needed yet).

## Previous state (2026-08-26, cycle 369 — FEATURE: explicit Postgres pool size + floor validation, commit 87ae758)

- CI green (`gh run list --limit 5` all success), `gh issue list --state open` empty,
  `git status` clean at cycle start.
- Picked cycle 368's first deferred candidate: `powehi_postgres::connect()` inherited
  sqlx's undocumented `max_connections = 10` default, which cycle 368's GC advisory-lock
  fix (`try_gc_lock`) made load-bearing — two background jobs (hourly media-blob GC, daily
  ledger trim) each now pin one dedicated session-scoped connection for
  `pg_try_advisory_lock` on top of normal request-handler traffic.
- **What it does:** `connect(url, max_connections: u32)` now builds via
  `PgPoolOptions::new().max_connections(...)` instead of the bare `PgPool::connect(url)`.
  `AppConfig` gained `database_max_connections: u32` (serde default 20,
  `POWEHI__DATABASE_MAX_CONNECTIONS`), threaded through `main.rs`'s `pg_connect` call.
  `powehi_config::load()` now rejects `database_max_connections < 3` via a new
  `ConfigError::DatabaseMaxConnectionsTooLow` — below 3, a single GC/ledger-trim job's
  lock connection plus its own query connection self-deadlocks the pool, and if both
  jobs overlap every request handler starves too.
- **security-auditor: GREEN** (fully independent verification against sqlx 0.8.6 source,
  not just the diff — confirmed `acquire_timeout` fail-fast on `max_connections=0`, config-rs
  string-coercion fail-fast on non-numeric/negative values, confirmed only the two
  `GcLockGuard`s are long-lived connection holders so 20 leaves 18 free for handlers vs.
  10's 8). 4 non-blocking findings, 2 fixed same-cycle: (1) missing floor validation — now
  fixed via the `< 3` reject above, extracted into a small pure `validate()` fn so it's
  unit-testable without mutating process env; (3) `GcLockGuard`'s `Drop`-safety doc
  depending on `min_connections == 0` didn't warn the new `PgPoolOptions` builder site not
  to add `.min_connections(_)` — added that warning to `connect()`'s doc comment. 2
  deferred as genuinely bigger-scope: (2) `maxReplicas × 20` roughly doubles the
  cluster-wide connection ceiling (300 in prod-eu, 200 in prod-ap) with no documented
  Postgres-side `max_connections` or managed-DB resource anywhere in `infra/` to check it
  against — needs an infra-lead pass wiring the value through Helm `values.yaml` derived
  from actual DB capacity, not a config-crate fix; (4) `POWEHI__DATABASE_MAX_CONNECTIONS`
  isn't wired into the Helm ConfigMap yet, so every environment runs the compiled default
  of 20 regardless — same follow-up as (2). Also noted (informational, no fix needed): two
  `#[ignore]`d testcontainers files (`pg_security_it.rs`, `r2_media_it.rs`) still call bare
  `PgPool::connect` bypassing the crate's `connect()`, so `try_gc_lock`'s own test suite
  runs against a differently-sized pool than production — harmless at 10 (above the new
  floor), align next time those files are touched. Not architectural (pool sizing is
  server-internal only, no new server-visible metadata) — `threat-model-checker` correctly
  not required; not crypto — `crypto-reviewer` correctly not required.
- 2 new unit tests (`database_max_connections_below_floor_is_rejected`,
  `database_max_connections_at_or_above_floor_is_accepted`), `powehi-config` now 13/13.
  Full `cargo build/test --workspace` green (no regressions), `cargo clippy --workspace
  --all-targets -- -D warnings` clean, `cargo fmt --check` clean. `cargo deny check`
  advisories/bans/licenses all ok (security-auditor ran it; no `Cargo.lock` diff from this
  change so not independently re-run).
- Target dir hygiene: not checked this cycle (FEATURE mode; next due cycle 370,
  STABILIZATION).
- **Next cycle candidates:** the two findings deferred this cycle above — (2)/(4) really
  are one task: derive/document a Postgres-side connection budget and wire
  `database_max_connections` through Helm `values.yaml` per environment instead of the
  baked-in 20, needs infra-lead + a real number for the managed Postgres's own
  `max_connections` (not currently provisioned via Terraform — check where/how the DB is
  actually hosted before picking this, may be a bigger infra task than one cycle); cycle
  368's other deferred item, a lease/TTL or R2 `S3Client` request timeout so a hung GC/trim
  task can't block that job cluster-wide indefinitely; the hexagonal-layering nit
  (`try_gc_lock` living on the R2/S3-named adapter instead of a `LeaderLock` port on
  `powehi-postgres`); media-key incoming/outgoing asymmetry (confirmed genuinely
  multi-part, cycle 359); PQ hybrid Phase A (still blocked on openmls stable
  `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B, itself
  gated on Phase A); project-context.md size (now ~1660 lines, comfortably under the 256KB
  Read cap — no action needed yet).

## Previous state (2026-08-26, cycle 368 — FEATURE: Postgres advisory lock guards GC/ledger-trim jobs, commit 20aa601)

- CI green (`gh run list --limit 3` all success), `gh issue list --state open` empty,
  `git status` clean at cycle start. PATH quirk hit again this cycle (recurring across
  many past cycles per the duplicate lines already in `~/.zshrc`): the sandbox's Bash
  tool does not source `~/.zshrc` (zsh only sources `.zshrc` for interactive shells;
  this harness runs non-interactive), so `cargo` was `command not found` until each
  command explicitly ran `source "$HOME/.cargo/env"` first. Appended one more line to
  `~/.zshenv` (sourced for *all* shell types, unlike `.zshrc`) attempting a real fix,
  but confirmed via a fresh Bash call that it *still* doesn't take effect — the
  per-command `source "$HOME/.cargo/env"` workaround remains necessary; do not assume a
  future cycle can skip it just because `.zshenv` looks correct.
- Picked cycle 364/367's carried-forward candidate: the multi-replica-GC-early-exit gap
  (security-auditor cycles 364 and 367, non-blocking both times) — `MediaService::run_gc`
  (hourly) and `R2MediaAdapter::trim_upload_ledger_older_than` (daily) each ran
  independently on every server replica with no leader election/advisory lock, so a
  concurrent sweep on another replica could delete rows out from under a replica's
  in-progress keyset page, making its batch undercount and exit early (self-healing —
  leftovers just wait for the next tick — but wasteful, and explicitly flagged twice as
  worth closing).
- **What it does:** new `R2MediaAdapter::try_gc_lock(key: i64) -> Result<Option<GcLockGuard>,
  DomainError>` (`crates/adapters/outbound/powehi-r2/src/lib.rs`) acquires a non-blocking
  session-scoped Postgres advisory lock (`pg_try_advisory_lock`) via a *dedicated held*
  `PoolConnection` — advisory locks are tied to the connection/session, not the query, so
  the guard can't borrow one per-query from the shared pool the way every other method in
  this adapter does. `GcLockGuard::release()` explicitly unlocks and returns the
  connection to the pool (falling back to detach-and-drop if the unlock query itself
  errors, so a failed release still can't leave a lock-holding connection back in the
  pool). If `release()` is never called (early return/panic), `Drop for GcLockGuard`
  instead calls `PoolConnection::detach()` and drops the resulting raw `PgConnection` —
  ending the session server-side is what actually frees a session-scoped lock; an
  explicit unlock issued later from a *different* pooled connection would not find it.
  `#[must_use]` on `GcLockGuard` so a future caller can't silently drop-and-release by
  accident. Two lock-key constants (`GC_LOCK_MEDIA_BLOBS`, `GC_LOCK_MEDIA_LEDGER`) so the
  two jobs never block each other, only concurrent replicas racing the *same* job.
  `bin/powehi-server/src/main.rs`'s two background job loops now wrap their bodies with
  `try_gc_lock`/`release`; `Ok(None)` (lock held elsewhere) skips that tick at `debug`
  level, relying on the next scheduled tick. Kept a concrete `Arc<R2MediaAdapter>` clone
  (`media_r2_lock`) alongside the existing `MediaRepository` trait-object clones since the
  lock helpers are Postgres-specific, not part of the port trait — main.rs already
  concedes this kind of concrete-type escape hatch elsewhere in the same function.
- **security-auditor: GREEN**, no blocking findings; verified genuinely, not rubber-
  stamped — read sqlx 0.8.6 source directly rather than trusting the diff's doc comments:
  confirmed `PoolConnection::detach()` decrements the pool's size permit which the pool
  immediately backfills (no permanent capacity loss); confirmed sqlx-postgres 0.8.6 has no
  `Drop for PgConnection`, so dropping the detached raw connection is just an fd close →
  Postgres backend hits EOF and releases session-scoped locks; found and had me document a
  bonus reason detach-then-drop is the *correct* choice beyond what the original comment
  claimed — `PoolConnection`'s own `Drop` spawns an async task to return itself to the
  pool, which panics if invoked while Tokio is shutting down, so a plain `drop(conn)`
  inside `Drop for GcLockGuard` would have been a latent runtime-teardown panic; detach()
  sidesteps that entirely (now documented in-code, contingent on `min_connections == 0`,
  which is what `powehi-postgres::connect()` uses today — also now documented as a
  caveat). Confirmed no advisory-lock key collision: grepped the whole repo, the only
  other advisory-lock user is sqlx's own migrator (`generate_lock_id`, CRC32-based, max
  ~4.41e18), and both `GC_LOCK_*` constants exceed that range, so collision is
  arithmetically impossible, not just unlikely. Confirmed no plaintext/PII logging (new
  `debug!`s are bare strings, new `warn!`s carry only `error_kind`+opaque error text).
  Confirmed not architectural / no new server-visible metadata (three files, no proto, no
  migration, no new DB column/HTTP/gRPC/WS surface, `pg_locks` state is server-internal
  only) — `threat-model-checker` correctly not required; not crypto — `crypto-reviewer`
  correctly not required. No `Cargo.lock` diff (zero new dependencies) — `cargo audit`/
  `cargo deny check` not re-run. Non-blocking findings, all fixed same-cycle rather than
  deferred (all cheap): `#[must_use]` on `GcLockGuard`; `release()`'s unlock-query error
  was silently swallowed via `let _ = ...` — now logged at `warn` plus falls back to the
  detach path so a failed unlock still can't leave a lock-holding connection in the pool;
  added the `min_connections == 0` dependency and the "no transaction-pooling proxy
  deployed" invariant to the doc comments (a PgBouncer/RDS-Proxy in transaction mode would
  silently break session-scoped advisory locks with zero compile-time signal — none exists
  in `infra/` today, confirmed by grep); added a comment on the GC job in main.rs
  acknowledging the one real behavior change auditor flagged — average expired-blob
  deletion latency moves from ~hourly/N-replicas to ~hourly cluster-wide, still far inside
  the retention-ceiling contract (no data-minimization regression) but worth being
  explicit about since deletion latency is privacy-adjacent even when policy-compliant.
  Two findings explicitly deferred (broader scope than a single-cycle fix, both
  documented as next-cycle candidates below): `powehi-postgres::connect()` has no explicit
  `PgPoolOptions` (inherits sqlx's default `max_connections = 10`, invisible and now
  load-bearing for this new code path — a large GC backlog can pin ~20% of the shared pool
  for the sweep's duration since `R2MediaAdapter::delete` does a synchronous R2 network
  round-trip per blob); a hung GC/trim task now blocks that job cluster-wide for as long as
  the hang lasts (previously only hurt the one replica) since there's no lease/TTL/
  `statement_timeout` and k8s's liveness probe only checks the axum HTTP server, not this
  `tokio::spawn`ed background task — bounded severity (GC is best-effort against a 30-day
  ceiling) but a real new failure mode worth a follow-up (lease TTL, or an explicit
  `Client::config()` request timeout on the R2 `S3Client` to bound the likeliest hang
  source).
- 4 new `#[ignore = "requires Docker (testcontainers)"]` integration tests in
  `r2_media_it.rs` (`try_gc_lock_returns_none_when_already_held`,
  `try_gc_lock_distinct_keys_do_not_block_each_other`,
  `try_gc_lock_dropped_without_release_still_frees_the_lock` — the last one specifically
  verifies the `Drop` safety net, not just the happy `release()` path, via a bounded poll
  loop since TCP teardown after `detach()` is async). Session-scoped advisory-lock
  behavior can't be exercised by any mock (the whole point is real per-connection session
  state at the OS/Postgres level), so this is testcontainers-only coverage by necessity —
  not run locally (no Docker in sandbox), will run in CI's Rust workflow. `cargo build/test
  --workspace` clean (all non-ignored green, no regressions), `cargo clippy --workspace
  --all-targets -- -D warnings` clean, `cargo fmt --check` clean.
- Target dir hygiene: not checked this cycle (FEATURE mode; next due cycle 370,
  STABILIZATION).
- **Next cycle candidates:** the two findings deferred this cycle (explicit
  `PgPoolOptions::max_connections` for `powehi-postgres::connect()` instead of inheriting
  sqlx's invisible default of 10; a lease/TTL or explicit R2 `S3Client` request timeout so
  a hung GC/trim task can't block that job cluster-wide indefinitely, now a real if
  bounded-severity new failure mode introduced by this cycle's own fix); the hexagonal-
  layering nit auditor raised but didn't block on (`try_gc_lock` is a Postgres primitive
  living on the R2/S3-named adapter, reached from main.rs via a concrete-type escape hatch
  around the `MediaRepository` port — a cleaner home would be a small `LeaderLock` outbound
  port on `powehi-postgres`, which already owns the pool; deferred as a design nit, not a
  correctness issue); the two findings deferred cycle 367 (`messaging_service.rs`'s mock's
  unreachable-in-real-Postgres members-without-groups construction, informational only;
  gRPC `sync_group_membership` missing a `member_device_ids.is_empty()` reject — re-
  evaluated this cycle and now believe this one is lower-priority than previously listed:
  `sync_group_membership` is the cross-region *sync* path (mTLS-gated peer-to-peer, not
  reachable by end users), and unlike `create_group`'s hijack bug, an empty-member group
  created here isn't permanently stuck — a later sync call with real members for the same
  group_id still succeeds via `upsert_members`'s `ON CONFLICT DO NOTHING`, and the existing
  test `sync_group_membership_zero_members_creates_group_stub` documents this as
  intentional. Only revisit if a concrete abuse scenario for the mTLS-gated path surfaces);
  `map_sqlx` raw-error-text server-side logging (pre-existing, informational, affects every
  adapter method); media-key incoming/outgoing asymmetry (needs a new crypto-reviewed WASM
  key-export/local-storage-key design, confirmed genuinely multi-part cycle 359); PQ hybrid
  Phase A (still blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF
  upgrade (gated on ADR-0003 Phase B, itself gated on Phase A); project-context.md size
  (now ~1610 lines, comfortably under the 256KB Read cap — no action needed yet).

## Previous state (2026-08-26, cycle 367 — FEATURE: make create_group's group+member creation atomic, commit 9d1ba00)

- CI green (`gh run list --limit 3` all success), `gh issue list --state open` empty,
  `git status` clean at cycle start. Picked cycle 366's top carried-forward candidate:
  its own non-blocking LOW finding — `create_if_absent` + `add_member` in
  `create_group` were two separate, non-transactional calls, so a failure between them
  (DB error, pod kill) could leave a committed group row with zero members, which was
  then permanently stuck (every future `create_group` retry for that id hits the
  already-exists-and-not-a-member branch forever, since nothing may add a first member
  once the id is known to exist).
- **What it does:** new `GroupRepository::create_with_creator(&Group, &GroupMember) ->
  Result<bool, DomainError>` port method
  (`crates/ports/powehi-port-outbound/src/group_repo.rs`); Postgres impl
  (`crates/adapters/outbound/powehi-postgres/src/group_repo.rs`) wraps the group-row
  insert (`ON CONFLICT (id) DO NOTHING`) and the creator's membership-row insert in one
  `pool.begin()`/`commit()` transaction, same pattern as the existing `upsert_members`.
  Returns `true` if newly created, `false` if the id already existed (transaction
  dropped/rolled back untouched). `GroupService::create_group` now calls this instead of
  `create_if_absent` + `add_member`. The membership insert binds `group.id` (not
  `creator.group_id`) — closes an undocumented precondition the first security-auditor
  pass flagged as a latent footgun if the two args ever diverged; port trait doc now
  states this normatively. `create_if_absent` itself is left in the trait (still tested
  directly, still the primitive doc-comment example) but confirmed dead in production —
  its only former caller was `create_group`.
- **security-auditor: 2 rounds, RED → GREEN.** First pass found ONE BLOCKING issue: the
  new Postgres integration test's `creator_device` was a bare `DeviceId::from(Uuid::new_v4())`
  never inserted into `devices`, so the membership insert's non-deferrable FK
  (`group_members.device_id REFERENCES devices(id)`) would reject it and the test would
  panic on `.expect(...)` instead of testing anything — the sole verification of this
  cycle's atomicity claim had zero real passing coverage, and CI (which does have Docker)
  would have gone red. Fixed: seeded via the file's existing
  `insert_device(&pool, insert_user(&pool).await).await` helper, same pattern as every
  other member-inserting test in that file. Also added the actually-missing coverage for
  the rollback branch itself (`create_with_creator_rolls_back_group_row_when_member_insert_fails`
  — unregistered device triggers the FK, asserts `Err` + `find_by_id` still `None`,
  provably fails under the original two-call regression since that would have already
  committed the group row). Two non-blocking hardening items from round 1 also fixed
  same-cycle rather than deferred (both cheap, both in code this cycle wrote): the
  `group.id`-vs-`creator.group_id` binding above, mirrored into all four
  `GroupRepository` mock mocks (`group_service.rs`, `media_service.rs`,
  `messaging_service.rs`, `powehi-grpc/src/server.rs`) so no test double's behavior can
  diverge from the production adapter on this axis. Second pass (fresh instance, no
  memory of round 1) independently re-verified all three fixes by tracing SQL/FK/sqlx-tx
  semantics (no Docker in either sandbox) plus re-ran `cargo build/test/clippy/fmt` —
  **GREEN**. Round 1 also confirmed (not rubber-stamped): the new transaction is
  genuinely atomic (nothing visible to other sessions pre-commit); no new race (READ
  COMMITTED, no isolation override anywhere in the workspace — `ON CONFLICT DO NOTHING`
  against an in-flight duplicate blocks then reports 0 rows, never raises
  `unique_violation`, so the loser gets a clean `Ok(false)`); rollback-on-drop verified
  against the actually-pinned `sqlx 0.8.6` source (`Drop for Transaction` queues
  `ROLLBACK`), not assumed; no plaintext/PII/new server-visible metadata. `cargo audit`/
  `cargo deny check` clean (0 vulnerabilities, no Cargo.lock diff). Two residual LOW/
  informational findings explicitly deferred to a future cycle per the auditor's own
  recommendation (separate call sites, out of this cycle's diff scope): gRPC
  `sync_group_membership` has no minimum on `member_device_ids`, so an empty list from a
  trusted mTLS peer can still create a zero-member group via `upsert_members` (mTLS-gated
  insider path, not end-user reachable); `messaging_service.rs`'s `FakeGroupRepo` mock
  can be constructed in a members-without-groups state real Postgres's FK can't reach
  (inert today, mock never actually exercises `create_with_creator`).
- **threat-model-checker: not re-run**, consistent with cycle 364's precedent for a
  similarly-scoped internal atomicity fix — no new server-visible metadata, no
  wire-format/API change, net effect is strictly less exposure to the same failure mode
  cycle 366's `threat-model-checker` GREEN already covered (access-control/membership
  invariants of `create_group`), not a new architectural surface.
- 2 new `#[ignore = "requires Docker"]` integration tests in `pg_security_it.rs`
  (`create_with_creator_inserts_group_and_member_together`,
  `create_with_creator_rolls_back_group_row_when_member_insert_fails`) — not run locally
  (no Docker in sandbox), will run in CI's Rust workflow (21 tests total in that file now,
  confirmed compiling/counted correctly via `cargo test` locally even though ignored).
  `cargo build/test --workspace` clean (~600 tests green, 0 failed, 58 Docker-gated
  ignored across the workspace), `cargo clippy --workspace --all-targets -- -D warnings`
  clean, `cargo fmt --check` clean (1 auto-fix applied mid-cycle, no logic change).
- Target dir hygiene: not checked this cycle (FEATURE mode; next due cycle 370,
  STABILIZATION).
- **Next cycle candidates:** the two findings deferred this cycle (gRPC
  `sync_group_membership` missing a `member_device_ids.is_empty()` reject alongside its
  existing `MAX_SYNC_MEMBERS` cap; `messaging_service.rs`'s mock's unreachable-in-
  -real-Postgres members-without-groups construction, informational only); `map_sqlx`
  raw-error-text server-side logging (pre-existing, informational, affects every adapter
  method); media-key incoming/outgoing asymmetry (needs a new crypto-reviewed WASM
  key-export/local-storage-key design, confirmed genuinely multi-part cycle 359); the
  multi-replica-GC-early-exit gap (cycle 364, `FOR UPDATE SKIP LOCKED`/advisory-lock
  guard, shared between the ledger trim job and `run_gc`); PQ hybrid Phase A (still
  blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on
  ADR-0003 Phase B, itself gated on Phase A); project-context.md size (now ~1520 lines,
  comfortably under the 256KB Read cap — no action needed yet).

## Previous state (2026-08-26, cycle 366 — FEATURE: fix broken access control in create_group (group hijack/rejoin), commit fe6c419)

- CI green (`gh run list --limit 3` all success), `git status` at cycle start was **NOT
  clean** — same "cycle silently fails to commit" pattern as cycles 324/326/330/332/341/
  342/355. Found a complete, passing, uncommitted diff already spanning 7 files
  (group_service.rs, group_repo.rs port+adapter, 3 mock-repo call sites, a new Docker-gated
  integration test), with doc-comment-style rationale in the diff itself framed exactly
  like a security-auditor finding-and-fix. The last commit on `main` at cycle start was
  cycle 364's memory update (b7853b9) with no cycle-365 commit anywhere in `git log` —
  strongly suggesting this is cycle 365's (STABILIZATION, security sweep step) work that
  was never committed, the same "cycle silently fails to commit" failure mode as cycles
  324/326/330/332/341/342/355, just not yet confirmed since no cycle-365 project-context.md
  entry exists to cross-reference. Per CLAUDE.md's investigate-before-discarding guidance,
  validated rather than discarded: `cargo build --workspace` clean, `cargo test --workspace`
  all green (no regressions), `cargo clippy --workspace --all-targets -- -D warnings`
  clean, `cargo fmt --check` clean. Treated the diff's embedded claims as unverified and
  re-ran both required review agents fresh before committing.
- **What it does:** `GroupService::create_group` (`crates/application/powehi-application/src/group_service.rs`)
  previously called `group_repo.save()` — a destructive `ON CONFLICT DO UPDATE` upsert —
  then unconditionally added the caller as a member. Any authenticated device could POST
  an existing/guessed group_id and (a) reset that group's `epoch`/`home_region` to
  defaults, (b) attach itself as a member of a group it was never invited to, including a
  device previously evicted via `remove_member` — letting it rejoin and potentially
  re-evict everyone else. Fixed with a new `GroupRepository::create_if_absent(&Group) ->
  Result<bool, DomainError>` port method (`INSERT ... ON CONFLICT (id) DO NOTHING`,
  `crates/adapters/outbound/powehi-postgres/src/group_repo.rs`); `create_group` now calls
  it instead of `save()`. If the id already existed: caller already a member ->
  idempotent no-op `Ok(())` (genuine retry, doesn't reset epoch/home_region); caller not a
  member -> `DomainError::AlreadyExists` (pre-existing variant, already mapped to HTTP 409
  / gRPC ALREADY_EXISTS elsewhere). Mock `GroupRepository` impls in media_service.rs,
  messaging_service.rs, and powehi-grpc/server.rs test modules updated to implement the
  new trait method.
- **security-auditor: YELLOW (ships safely), verified not rubber-stamped:** confirmed
  `create_if_absent` is race-free (groups.id is a real UUID PK, giving `ON CONFLICT` a
  valid arbiter index; `rows_affected() == 1` correctly detects the winner under
  READ COMMITTED); confirmed no other production call site still uses `save()` for initial
  creation (the only remaining `save()`/upsert paths are `send_commit`'s epoch advance,
  member-gated, and gRPC's `upsert_members`, mTLS-region-gated and already DO NOTHING);
  confirmed the idempotent-retry path isn't TOCTOU-abusable (caller only controls
  group_id, `creator` comes from the authenticated-device extractor, membership is
  server-side DB state); confirmed no PII/plaintext logged (`DeviceId`/`GroupId` Display
  are bare UUIDs); confirmed the 409 mapping leaks no group-id-existence oracle beyond
  theoretical (128-bit random ids, route is authenticated + rate-limited, response body is
  code-only). Two non-blocking LOW findings, carried forward rather than fixed this cycle
  (see below): `create_if_absent` + `add_member` are two separate statements, not one
  transaction — if `add_member` fails after the group row lands (DB error/pod kill), the
  group is permanently unusable (zero members, every future caller hits the
  already-exists-and-not-a-member branch forever) since the fix removed the old
  self-healing unconditional `add_member`; same non-atomicity also means the loser of two
  concurrent same-creator `create_group` calls gets a spurious 409 (harmless, client can
  retry).
- **threat-model-checker: GREEN**, no prd.md/ADR update needed. Confirmed: no new
  server-visible metadata (`create_if_absent` writes strictly less than the old `save()`
  did); T7 (region jurisdiction) posture strengthened — `home_region` can no longer be
  rewritten by an arbitrary authenticated device, closing a way to move the §3.5.4
  commit-serialization point; access-control/membership invariants strengthened (closes
  evicted-device rejoin, which mattered because `group_members` drives fan-out and
  media/envelope ACLs per §3.3/§9.4.3 — a rejoined device kept receiving ciphertext/
  presigned URLs even though MLS PCS denied it plaintext); the 409-vs-204 existence-signal
  delta is within §3.3's already-documented `group_id` disclosure, no doc change required;
  confirmed no other unguarded path into group creation/upsert remains.
- 3 new tests in `group_service.rs` (non-member hijack on an existing group_id rejected
  with `AlreadyExists` + member list unchanged; a device evicted via `remove_member`
  cannot rejoin through this path; a genuine retry by an existing member is idempotent —
  no duplicate member row, epoch/home_region not reset), 1 new
  `#[ignore = "requires Docker"]` integration test in `pg_security_it.rs`
  (`create_if_absent_does_not_overwrite_an_existing_group`, proves the real Postgres
  `ON CONFLICT DO NOTHING` semantics directly: first call creates, second call with a
  different home_region/reset epoch reports already-existing and leaves every column
  including `created_at` untouched, exactly one row exists). Not run locally (no Docker in
  sandbox), will run in CI's Rust workflow. `cargo build/test --workspace` clean (all
  crates green, no regressions), `cargo clippy --workspace --all-targets -- -D warnings`
  clean, `cargo fmt --check` clean.
- Target dir hygiene: not checked this cycle (FEATURE mode; cycle 365 was the STABILIZATION
  cycle that should have covered it — status not visible from this session, assume covered
  unless a future cycle finds otherwise).
- **Next cycle candidates:** the security-auditor's two LOW findings this cycle
  (`create_if_absent`+`add_member` non-atomicity — a failed `add_member` after a fresh
  group row lands permanently bricks that group_id; fix by wrapping both in one Postgres
  transaction, same `pool.begin()` pattern `upsert_members` already uses, needs a new
  combined port method since the current two-call shape can't be made atomic from the
  application layer alone); `map_sqlx` raw-error-text server-side logging (pre-existing,
  informational, affects every adapter method); media-key incoming/outgoing asymmetry
  (needs a new crypto-reviewed WASM key-export/local-storage-key design, confirmed
  genuinely multi-part cycle 359); the multi-replica-GC-early-exit gap (cycle 364,
  `FOR UPDATE SKIP LOCKED`/advisory-lock guard, shared between the ledger trim job and
  `run_gc`); PQ hybrid Phase A (still blocked on openmls stable `MLS_128_MLKEM768`);
  OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B, itself gated on Phase A);
  project-context.md size (now ~1420 lines, comfortably under the 256KB Read cap — no
  action needed yet).

## Previous state (2026-08-25, cycle 364 — FEATURE: batch media_upload_ledger GC trim + supporting index, commit 641556b)

- CI green (`gh run list --limit 3` all success), `gh issue list --state open` empty,
  `git status` clean at cycle start. Picked cycle 363's top carried-forward candidate: its own
  non-blocking security-auditor note that `trim_upload_ledger_older_than` was a single unbatched
  `DELETE ... WHERE uploaded_at < $1` with no supporting index (the table's only index led with
  `device_id`), so the daily sweep was a full-table scan in one unbatched statement.
- **What it does:** new migration `0016_media_upload_ledger_uploaded_idx.sql` — `CREATE INDEX
  CONCURRENTLY IF NOT EXISTS media_upload_ledger_uploaded_at_idx ON
  media_upload_ledger(uploaded_at)`, `-- no-transaction` marker (0011/0014 precedent — sqlx
  can't run CONCURRENTLY inside its migration transaction). `R2MediaAdapter::
  trim_upload_ledger_older_than` (`crates/adapters/outbound/powehi-r2/src/lib.rs`) now loops,
  deleting via `WHERE id IN (SELECT id ... WHERE uploaded_at < $1 ORDER BY uploaded_at LIMIT
  5_000)` per batch (`TRIM_LEDGER_BATCH_SIZE`), summing `rows_affected()`, exiting when a batch
  returns fewer than the cap — bounds both scan cost (index range scan per batch, not a full
  scan) and lock hold time (no single statement touches the whole stale range). Port trait
  signature (`media_repo.rs`) unchanged — pure adapter-internal change, `main.rs`'s daily
  `tokio::spawn` caller untouched.
- **security-auditor: GREEN**, no blocking findings; verified (not rubber-stamped): fully
  parameterized (no injection surface), batching loop provably terminates (cutoff is fixed for
  the whole call; only production insert path sets `uploaded_at = Utc::now()` server-side, so no
  concurrent insert can land below a 30-day-old cutoff — livelock unreachable), off-by-one exit
  condition correct (PK-keyed `IN` subquery yields distinct ids, exact-multiple case just costs
  one harmless extra zero-row statement), no PII/content logged. Two non-blocking findings, both
  applied/documented in-cycle rather than deferred (unlike cycle 363's picks, both were cheap):
  (a) switched the new index from a plain `CREATE INDEX` to `CONCURRENTLY` — auditor pointed out
  this table (unlike 0015's genuinely-empty-at-creation case) has been insert-heavy since cycle
  362, so a plain build's lock would block concurrent uploads for its duration; (b) documented
  in-code (not fixed — architectural, out of single-cycle scope) that multiple server replicas
  each running this daily sweep independently with no leader election/advisory lock (same
  pre-existing gap as `run_gc`) can make one replica's batch undercount and exit early if another
  replica deletes rows concurrently — bounded/self-healing (leftovers are still >29 days past the
  24h quota window, swept next run), not a correctness or quota-bypass risk.
- 1 new integration test in `r2_media_it.rs`
  (`trim_upload_ledger_older_than_drains_multiple_batches`): bulk-inserts 12,001 stale rows via
  raw SQL + `generate_series` (bypassing `save()`'s per-row S3+Postgres overhead — no FK on
  `device_id` in this table, confirmed safe) spanning 2 full batches + 1 partial, asserts all
  12,001 are deleted and a control fresh row survives — proves the loop fully drains a multi-batch
  range without needing thousands of slow round-trips. `#[ignore = "requires Docker"]`, not run
  locally (no Docker in sandbox), runs in CI's Rust workflow. `cargo build/test --workspace`
  clean, `cargo clippy --workspace --all-targets -- -D warnings` clean, `cargo fmt --check` clean.
  No `Cargo.lock` diff (no dependency changes) — `cargo audit`/`cargo deny check` not re-run.
- Target dir hygiene: not checked this cycle (FEATURE mode, next due cycle 365, STABILIZATION).
- **Next cycle candidates:** the multi-replica-GC-early-exit gap documented (not fixed) this
  cycle — would need a `FOR UPDATE SKIP LOCKED` subquery or `pg_try_advisory_lock` guard, shared
  with `run_gc`'s identical pre-existing gap, worth doing both together if ever prioritized;
  `map_sqlx` raw-error-text server-side logging (pre-existing, informational, affects every
  adapter method, cycle 363 carryover); media-key incoming/outgoing asymmetry (needs a new
  crypto-reviewed WASM key-export/local-storage-key design, confirmed genuinely multi-part cycle
  359); PQ hybrid Phase A (still blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid
  OPRF upgrade (gated on ADR-0003 Phase B, itself gated on Phase A); project-context.md size (now
  ~1340 lines, comfortably under the 256KB Read cap — no action needed yet).

## Previous state (2026-08-25, cycle 363 — FEATURE: daily GC trim job for media_upload_ledger, commit b578778)

- CI green (`gh run list --limit 3` all success), `gh issue list --state open` empty,
  `git status` clean at cycle start. Picked cycle 362's top carried-forward candidate: the
  accepted non-blocking gap in `media_upload_ledger` (the append-only table backing the
  per-device/per-day media upload byte quota) — no GC/TTL sweep existed, so it grew by one
  small fixed-width row per accepted upload, forever, across all devices.
- Dispatched an Explore-style scoping agent first (background) to locate the existing GC
  pattern before writing code: confirmed `bin/powehi-server/src/main.rs` already runs two
  `tokio::spawn` interval-loop background jobs (envelope GC every 300s via
  `EnvelopeRepository::delete_expired`, media blob GC every 3600s via `MediaService::run_gc`)
  — no cron/k8s CronJob/admin endpoint involved, everything in-process — and that
  `MediaService`'s existing `GC_RETENTION_DAYS = 30` (media_service.rs:32) + prd.md §11.4's
  documented 30-day default retention were the right precedent to reuse for this table's
  cutoff too (large margin over the 1-day quota-read window; no existing precedent for a
  tighter window).
- **What it does:** new `MediaRepository::trim_upload_ledger_older_than(cutoff) ->
  Result<u64, DomainError>` port method (`crates/ports/powehi-port-outbound/src/media_repo.rs`);
  `R2MediaAdapter` impl is a single parameterized `DELETE FROM media_upload_ledger WHERE
  uploaded_at < $1` returning `rows_affected()`. New daily (`interval(86400s)`)
  `tokio::spawn` loop in `main.rs`, same shape as the two existing GC loops, calling
  `trim_upload_ledger_older_than(now - GC_RETENTION_DAYS)` — reuses the constant (now `pub`)
  from `media_service.rs` rather than a duplicated literal, so the two retention windows
  can't silently drift apart. Required adding `chrono` as a direct dependency of
  `bin/powehi-server/Cargo.toml` (workspace-pinned, no new transitive dep — main.rs
  previously never called `chrono::` directly). Migration `0015`'s comment block updated
  from "known gap" to "closed cycle 363, see main.rs".
- **security-auditor: GREEN**, no blocking findings. Verified (not rubber-stamped): the
  30-day cutoff has a 29-day safety margin over the 24h rolling quota-read window with no
  code path (concurrent request, retry, clock skew) where an in-window row could be
  deleted — the two predicates (`>= now-1d` read vs `< now-30d` delete) are provably
  disjoint; the DELETE is fully parameterized with exactly one non-test call site (the
  background job itself — unreachable from any HTTP/gRPC/admin route since it lives on the
  outbound `MediaRepository` port, not the inbound `MediaUseCase` the handlers hold); no
  plaintext/PII/content logged (count-only `tracing::info!`); `rows_affected()` is a
  lossless `u64`, no cast; confirmed `threat-model-checker` genuinely not required — trims
  an internal-only table with no client-facing read path, net *decreases* server-retained
  metadata, no threat-model-negative delta. `cargo audit`/`cargo deny check` clean (1-line
  Cargo.lock diff: existing workspace-pinned `chrony` promoted to a direct dep, zero new
  transitive dependencies). Two low-severity non-blocking findings fixed same cycle: (a)
  the retention constant was a duplicated literal `30` in main.rs vs `GC_RETENTION_DAYS` in
  media_service.rs — fixed by making the constant `pub` and importing it; (b) the table's
  only index (`device_id, uploaded_at`) doesn't lead with `uploaded_at`, so each daily sweep
  is an unbatched full-table-scan DELETE — documented in place as an accepted low-severity
  gap (same unbatched shape as the pre-existing `EnvelopeRepository::delete_expired`,
  revisit if row volume ever makes scan time/lock hold matter). One informational-only,
  pre-existing, not-this-diff's-fault note left as-is: `map_sqlx` logs raw sqlx error text
  server-side only (no client exposure), same pattern as every other adapter method.
- 5 new/updated Rust tests: 2 new unit tests in `media_service.rs`'s `MockMediaRepo`
  (deletes-only-stale-rows, returns-zero-when-nothing-stale — mock's `trim_upload_ledger_older_than`
  now implemented too, required since it's a new trait method on `MediaRepository`, the only
  two implementors are `MockMediaRepo` and `R2MediaAdapter`); 3 new `#[ignore = "requires
  Docker"]` integration tests in `r2_media_it.rs` (deletes-only-rows-past-cutoff,
  does-not-touch-media_blobs — pins the no-FK invariant explicitly, returns-zero-when-
  nothing-stale) — not run locally (no Docker in sandbox), will run in CI's Rust workflow.
  `cargo build/test --workspace` clean (144 `powehi-application` unit tests green, +2 from
  cycle 362's 142 baseline count reported same-crate), `cargo clippy --workspace
  --all-targets -- -D warnings` clean, `cargo fmt --check` clean (no reformatting needed).
- Target dir hygiene: not checked this cycle (FEATURE mode, not due — next due cycle 365,
  STABILIZATION).
- **Next cycle candidates:** the two low-severity non-blocking notes this cycle chose to
  document rather than fix (unbatched full-scan DELETE on the ledger trim — revisit if row
  volume grows; `map_sqlx` raw-error-text server-side logging — pre-existing, informational,
  affects every adapter method, not specific to this diff); media-key incoming/outgoing
  asymmetry (still needs a new crypto-reviewed WASM key-export/local-storage-key design,
  confirmed genuinely multi-part cycle 359); PQ hybrid Phase A (still blocked on openmls
  stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B,
  itself gated on Phase A); project-context.md size (now ~1290 lines, comfortably under the
  256KB Read cap — no action needed yet).

## Previous state (2026-08-25, cycle 362 — FEATURE: append-only media upload ledger closes delete-churn quota bypass, commit f30e9e0)

- CI green (`gh run list --limit 3` all success), `git status` clean at cycle start. Picked
  cycle 361's top carried-forward candidate: the accepted residual gap in
  `MAX_MEDIA_BYTES_PER_DEVICE_PER_DAY`'s doc comment — `sum_bytes_uploaded_since` summed
  currently-live `media_blobs` rows only, so `upload -> confirm -> delete` in a loop let a
  device churn unbounded write ops/day within the 24h window while counted usage always
  read back near zero (storage stayed bounded, but write-op churn didn't).
- **What it does:** new migration `0015_media_upload_ledger.sql` — `media_upload_ledger(id
  UUID PK, device_id UUID, size_bytes BIGINT CHECK > 0, uploaded_at TIMESTAMPTZ)` +
  `(device_id, uploaded_at)` index, no FK to `media_blobs` (deliberate — must outlive the
  blob's deletion), regular (non-`CONCURRENTLY`) DDL since the table is new/empty at
  migration time. `R2MediaAdapter::save()` (`powehi-r2/src/lib.rs`) now opens a
  `PgPool::begin()` transaction and inserts into both `media_blobs` and
  `media_upload_ledger` (same `id` reused for both, both `ON CONFLICT (id) DO NOTHING`)
  before committing; `delete()` is unchanged — only touches `media_blobs`/R2, never the
  ledger. `sum_bytes_uploaded_since()` now queries the ledger instead of `media_blobs`, so
  a device's counted daily usage is monotonic within the rolling window regardless of
  deletes. Port trait signature unchanged (`media_repo.rs`), doc comments updated on both
  the port and `media_service.rs`'s `MAX_MEDIA_BYTES_PER_DEVICE_PER_DAY` (removed the now-
  closed caveat, left the still-accepted count-then-insert race-window note).
- **security-auditor: GREEN**, no blocking findings. Verified (not rubber-stamped):
  confirmed `R2MediaAdapter::save()` is the sole write path into `media_blobs` (no other
  `MediaRepository` impl, no bulk-import path) — no bypass route; the transaction means any
  partial failure aborts before `commit()` and an uncommitted `sqlx::Transaction` rolls back
  on drop, so the two tables can't diverge; all queries parameterized, no injection surface;
  `size_bytes BIGINT CHECK > 0` at the DB layer plus the existing `MAX_MEDIA_BYTES` (100MB)
  app-layer cap keeps the no-overflow reasoning valid; missing FK confirmed safe/intentional;
  non-`CONCURRENTLY` DDL confirmed correct (new table, same migration, no pre-existing-row
  contention unlike 0011/0014). One **non-blocking residual gap** flagged and documented in
  the migration file: the new ledger table has no GC/TTL sweep, so it grows unboundedly
  forever (small fixed-width rows, one per accepted upload, across all devices) — doesn't
  affect quota correctness or query performance (the rolling-24h sum only reads recent rows
  via the index), only slow permanent storage/index growth. Worth a future periodic trim job
  (delete rows older than N days, well past the 24h window). Confirmed scoping: not crypto
  (Postgres transaction + aggregate query, no MLS/OPAQUE/KDF/AEAD touched) —
  `crypto-reviewer` not required; not architectural, no new server-visible metadata (ledger
  columns mirror data already stored in `media_blobs`) — `threat-model-checker` not
  required. No plaintext/PII logged (`map_sqlx`/`map_r2` log only `error_kind`).
- 3 new/updated Rust tests: 1 new unit test (`media_service.rs`,
  `request_upload_quota_survives_delete_upload_churn` — primes 3 synthetic upload+delete
  cycles via direct `repo.save`/`repo.delete` at 40% of the daily cap each since a single
  real `request_upload` call is capped at `MAX_MEDIA_BYTES`=100MB, far below the 5GB daily
  cap; asserts a 4th real `request_upload` is still rejected despite zero live blobs), plus
  the in-memory `MockMediaRepo` test double reworked to model an immutable ledger separate
  from the mutable `saved` list (so this exact regression is now unit-test-catchable, not
  just integration-test-catchable); 1 new `#[ignore = "requires Docker"]` integration test
  in `r2_media_it.rs` (`sum_bytes_uploaded_since_survives_delete_against_real_postgres`)
  proving the same fix against real Postgres (no Docker in this sandbox, will run in CI's
  Rust workflow). `cargo build/test --workspace` clean (139 `powehi-application` unit tests
  green, was 138), `cargo clippy --workspace --all-targets -- -D warnings` clean, `cargo
  fmt --check` clean (no reformatting needed).
- Target dir hygiene: not checked this cycle (FEATURE mode, not due — next due cycle 365,
  STABILIZATION).
- **Next cycle candidates:** a periodic trim/TTL job for `media_upload_ledger` (this
  cycle's non-blocking residual gap — unbounded row growth, not urgent, cheap when picked
  up); the migration's `IF NOT EXISTS`-silently-no-ops-past-an-INVALID-index operational
  risk pattern (documented runbook note precedent from 0011/0014, not automated for 0014
  since nothing there drops an old index; N/A to 0015 since it doesn't use `CONCURRENTLY`);
  media-key incoming/outgoing asymmetry (still needs a new crypto-reviewed WASM key-export/
  local-storage-key design, confirmed genuinely multi-part cycle 359); PQ hybrid Phase A
  (still blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade
  (gated on ADR-0003 Phase B, itself gated on Phase A); project-context.md size (now
  ~1240 lines, comfortably under the 256KB Read cap — no action needed yet).

## Previous state (2026-08-25, cycle 361 — FEATURE: per-device/per-day media upload byte quota, commit e093ee8)

- CI green (`gh run list --limit 3` all success), `git status` clean at cycle start. Picked
  cycle 359's residual finding (carried forward through cycle 360's stabilization pass): no
  per-device/per-day byte quota existed for media uploads, only the shared per-IP
  `api_governor` rate limit (~4TB/day/IP sustained-worst-case).
- **What it does:** `MediaRepository::sum_bytes_uploaded_since(device_id, since)` (new port
  method) sums a device's live `media_blobs.size_bytes` since a given timestamp;
  `R2MediaAdapter` implements it as `SELECT COALESCE(SUM(size_bytes),0) FROM media_blobs WHERE
  uploader_device_id=$1 AND uploaded_at>=$2`. `MediaService::request_upload` now computes a
  rolling 24h window (`now - 1 day`, recomputed per call) and rejects with
  `InvalidInput("media_device_daily_quota_exceeded")` if `used + size_bytes >
  MAX_MEDIA_BYTES_PER_DEVICE_PER_DAY` (5GB), same count-then-insert soft-cap pattern as
  `KeyPackageService::upload`. New migration `0014_media_blobs_device_uploaded_idx.sql`
  (`CREATE INDEX CONCURRENTLY IF NOT EXISTS` on `(uploader_device_id, uploaded_at)`, `--
  no-transaction`, additive-only — no old index dropped, so no `pg_index.indisvalid` guard
  needed unlike 0011-0013's precedent) makes the sum a bounded range scan instead of a full
  per-device table scan.
- **security-auditor: 1 round, needs-rework → fixed same cycle.** Required fix: the SUM query
  decoded as sqlx `i64`, but Postgres's `SUM(bigint)` returns `NUMERIC` (only `SUM(integer)`
  stays `bigint`), and this workspace's sqlx build has no `bigdecimal`/`rust_decimal` feature
  to decode `NUMERIC` — every call would have failed with a column-decode error, 500ing every
  media upload request (not a quota-bypass, but a full feature outage). The in-memory
  `MockMediaRepo` test double couldn't catch this since it never touches real SQL types, and
  Docker wasn't available locally to run the real-Postgres integration test before commit —
  fixed with an explicit `::BIGINT` cast (safe: `size_bytes` is capped at `MAX_MEDIA_BYTES`
  100MB per row, overflow past `i64::MAX` is physically impossible). 2 non-blocking
  recommendations, both applied: (a) tightened the race-window doc comment — concurrent
  same-device requests can overshoot by at most ~2x the cap in one shot, bounded by the
  per-IP governor's burst=60, not unbounded drift; (b) documented an accepted residual gap —
  `upload → confirm → delete` in a loop resets the live-bytes sum, so the quota bounds
  *storage* (correctly) but not *write-op churn* per day (an append-only usage ledger would
  close this, out of scope this cycle). Confirmed scoping: not crypto (S3 presign params +
  Postgres aggregate + application arithmetic, no MLS/OPAQUE/KDF/AEAD touched) —
  `crypto-reviewer` not required; not architectural, no new server-visible metadata
  (`uploader_device_id`/`uploaded_at`/`size_bytes` were already server-visible columns since
  the original `0003_media_blobs.sql`, this only adds a new read pattern over them) —
  `threat-model-checker` not required. No plaintext/PII logged (`#[instrument]` on the new
  adapter method only fields `device_id`, an opaque UUID).
- 8 new Rust tests: 4 unit (`media_service.rs`, in-memory mock) covering over-quota rejection,
  exact-boundary acceptance, stale (>24h) usage not counting, and per-device isolation; 2 new
  `#[ignore = "requires Docker"]` integration tests in `r2_media_it.rs` (sum scoped to device
  + window, zero-for-no-uploads via `COALESCE`) that will run in CI's Rust workflow (no Docker
  in this sandbox to run them locally, consistent with every other `r2_media_it.rs` test).
  `cargo build/test --workspace` clean (146 `powehi-application` + 7 `powehi-r2` unit tests
  green, 21 `r2_media_it.rs` tests correctly `ignored`), `cargo clippy --workspace
  --all-targets -- -D warnings` clean, `cargo fmt --check` clean.
- Target dir hygiene: not checked this cycle (FEATURE mode, not due — next due cycle 365,
  STABILIZATION).
- **Next cycle candidates:** the 2 accepted-residual gaps from this cycle's security-auditor
  pass (both documented in `MAX_MEDIA_BYTES_PER_DEVICE_PER_DAY`'s doc comment, neither
  blocking): an append-only usage ledger to close the delete-resets-usage write-op-churn gap;
  the migration's `IF NOT EXISTS`-silently-no-ops-past-an-INVALID-index operational risk (now
  has a runbook note in the migration file itself, same as 0011's, not automated like 0012's
  since nothing here drops an old index); media-key incoming/outgoing asymmetry (still needs
  a new crypto-reviewed WASM key-export/local-storage-key design, scoped via Explore agent
  cycle 359, confirmed genuinely multi-part); PQ hybrid Phase A (still blocked on openmls
  stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B, itself
  gated on Phase A); project-context.md size (now ~1180 lines / ~96KB after cycle 360's
  archive, comfortably under the 256KB cap — no action needed yet).

## Previous state (2026-08-25, cycle 359 — FEATURE: bind size_bytes into presigned R2 upload signature, commit 62541bb)

- CI green (`gh run list --limit 3` all success), `git status` clean at cycle start. All of
  cycle 358's carried-forward candidates were blocked (PQ hybrid Phase A: openmls PQ
  ciphersuite still not stable — checked `docs/decisions/0003-pq-migration.md`, Phase A
  checklist items all still unchecked) or too large for one safe cycle (media-key
  incoming/outgoing asymmetry — dispatched an Explore agent to scope it first: closing it
  needs WASM to retain a session-lived local-storage key derived from the OPAQUE
  `export_key`, since WASM currently has no thread-local counterpart to `dbKey` at
  `media_encrypt` time — a real new-persistent-secret design decision, correctly deferred
  again rather than rushed). Dispatched a fresh `security-auditor` sweep instead (same
  pattern as cycle 350 when the candidate queue ran dry), scoped to `bin/powehi-server`,
  `application/*/src/*service*.rs`, and outbound adapters.
- **security-auditor found a real MEDIUM bug:** `R2MediaAdapter::presigned_upload_url`
  (`crates/adapters/outbound/powehi-r2/src/lib.rs`) never bound `Content-Length` into the
  SigV4 signature. `size_bytes` is validated server-side (0 < size ≤ `MAX_MEDIA_BYTES` =
  100MB, `media_service.rs::request_upload`) and persisted, but that check was purely
  advisory — a client could declare `size_bytes: 1` then PUT an arbitrarily large body to
  the real presigned URL (15 min TTL), since nothing checked the actual upload length.
  Unbounded R2 storage/egress cost, and `media_blobs.size_bytes` (the only value any GC/
  accounting logic sees) was a client-controlled lie.
- **Fix:** added `.content_length(row.size_bytes as i64)` to the presign builder — R2 now
  rejects (SignatureDoesNotMatch) any PUT whose actual body length differs from the row's
  `size_bytes`. Also closed a related **pre-existing live bug** the same sweep surfaced:
  `content_type` had ALWAYS been a signed header on this presigned URL, but both PUT call
  sites in `app/src/lib/mediaTransfer.ts` (`encryptAndSendMedia`, chunked + non-chunked)
  hardcoded `Content-Type: application/octet-stream` instead of the real `mimeType` param
  — meaning every real upload against actual R2/S3 (not the local dev/test path) would
  already fail with `SignatureDoesNotMatch`. Fixed both call sites to send the real
  `mimeType`.
- **security-auditor: GREEN** (2 non-blocking YELLOW notes, no required fixes — "Ship it").
  Verified EMPIRICALLY, not by reading docs: built a temporary probe against the pinned
  `aws-sdk-s3 1.133.0`/`aws-sigv4 1.4.4` and diffed presigned URLs with/without
  `.content_length()` — confirmed `content-length` genuinely enters `X-Amz-SignedHeaders`
  (not silently dropped by the presign interceptor's default-header suppression), and that
  `content-type` was already signed pre-diff (confirming the second bug was real, not
  theoretical). `i64`↔`u64` cast confirmed lossless (100MB ≪ `i64::MAX`, `size_bytes` is
  `BIGINT` on disk). Confirmed no drift: `ciphertext.length` (the exact post-encryption
  byte count) is what both `requestMediaUpload` and the PUT body use — the signed value
  always equals the real body. Residual gap flagged as pre-existing/out-of-scope, not
  introduced by this diff: `/v1/media/upload-url` has no per-device/per-day byte quota,
  only the shared per-IP `api_governor` rate limit (~4TB/day/IP sustained-worst-case) —
  the diff converts unbounded-per-URL to bounded-per-URL, which is the correct increment;
  a byte quota is a separate MEDIUM finding for a future cycle. No plaintext/PII/ciphertext
  leaked (error paths collapse to static categories; new test fixtures are filler bytes).
  Not architectural, no new server-visible metadata (R2 already saw object size regardless;
  this only makes an already-collected value load-bearing) — `threat-model-checker` not
  required. Not crypto code (S3 request-signing infra, not a message-encryption primitive)
  — `crypto-reviewer` not required.
- 4 new/updated Rust tests in `r2_media_it.rs` (2 new: oversized-body-rejected,
  undersized-body-rejected, both asserting the object never lands in S3; 2 existing tests'
  fixtures corrected to set `blob.size_bytes = body.len()` before save, since content-length
  is now signed and must match the real PUT body) — all `#[ignore = "requires Docker"]`,
  not run locally (no Docker in sandbox), will run in CI's Rust workflow. 2 new Vitest tests
  in `mediaTransfer.test.ts` proving the PUT's `Content-Type` header matches the real
  `mimeType` on both chunked and non-chunked paths — these DID run locally and pass.
  `cargo build/test --workspace` clean (all non-ignored green), `cargo clippy --workspace
  --all-targets -- -D warnings` clean, `cargo fmt --check` clean (1 auto-fix applied
  mid-cycle for the two new tests' `.expect()` line length, no logic change). Frontend:
  105/105 files, 1504/1504 tests green (was 1502). `tsc -b`/`biome check` clean.
- Target dir hygiene: not checked this cycle (FEATURE mode, not due — next due cycle 360,
  STABILIZATION).
- **Next cycle candidates:** the 2 YELLOW notes from this cycle (both optional, cheap,
  non-blocking — signing `.content_type(&row.content_type)` instead of the caller-supplied
  parameter for extra robustness against a future divergent caller; a `video/quicktime`
  test fixture that isn't in `ALLOWED_CONTENT_TYPES`, cosmetic only); a per-device/per-day
  media upload byte quota (MEDIUM, this cycle's residual finding — no `MediaRepository`
  count method exists yet, would need one, same pattern as `MAX_KEY_PACKAGES_PER_DEVICE`/
  `MAX_OUTSTANDING_INVITES_PER_DEVICE`); closing the incoming/outgoing media-key asymmetry
  (needs a new crypto-reviewed WASM key-export/local-storage-key design — scoped this
  cycle via Explore agent, confirmed genuinely multi-part, not a quick fix); PQ hybrid
  Phase A (still blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF
  upgrade (gated on ADR-0003 Phase B, itself gated on Phase A); project-context.md archival
  (184KB/2308 lines, under the 256KB Read cap but flagged repeatedly across cycles 355-358
  as increasingly pressing — cycle 360 is STABILIZATION, do it then per precedent from
  cycles 320/340).

## Previous state (2026-08-25, cycle 358 — FEATURE: automate pg_index.indisvalid migration guard, commit d3df0de)

- CI green (`gh run list --limit 3` all success), `git status` clean at cycle start. Picked
  cycle 355/357's carried-forward candidate: the manual runbook step in 0011's OPERATIONAL
  NOTE (security-auditor cycle 353) — if 0011's `CREATE INDEX CONCURRENTLY` on
  `envelopes_recipient_created_id_idx` is interrupted, Postgres leaves an INVALID index
  under that name; `IF NOT EXISTS` then no-ops on a migration retry without rebuilding it,
  and the old `0012` migration would unconditionally drop the only good (two-column)
  fallback index — every poll (every device, ~3s interval) would seq-scan `envelopes`.
- **Fix:** `git mv`'d the old `0012_envelope_poll_created_idx_drop.sql` to
  `0013_envelope_poll_created_idx_drop.sql` (content unchanged), and inserted a new
  `0012_envelope_poll_idx_validity_guard.sql` between 0011 (create) and 0013 (drop) — an
  ordinary transactional migration (`DO $$ ... $$` block, since `CONCURRENTLY` forbids
  running inside a transaction and can't share a file with a conditional check) that
  `RAISE EXCEPTION`s and aborts the whole `sqlx::migrate!().run()` call if
  `pg_index.indisvalid = false` for the new index. Updated 0011's comment to point at the
  fix instead of re-flagging closed work.
- **security-auditor: GREEN.** Verified (not rubber-stamped), including tracing the actual
  deploy path: `run_migrations` is called on every real server boot
  (`bin/powehi-server/src/main.rs`), but confirmed via `git tag` (empty, 667-commit history)
  and `.github/workflows/release.yml`/`cd.yml` (both gated on a `vX.Y.Z` tag that's never
  been pushed) that no real deployed environment has ever recorded the old migration
  version 12 in a persisted `_sqlx_migrations` table — renumbering an unreleased migration
  is safe today. Advisory-only, not blocking: once a real tag/release ships, this
  renumbering pattern must not be repeated (sqlx 0.8.6 would hard-error with
  `VersionMismatch` on a checksum mismatch for an already-applied version — fails loudly,
  not silently, if it ever were unsafe). Also confirmed the `'...'::regclass` cast is safe
  by construction (sqlx runs migrations strictly in order and aborts the whole run on any
  earlier failure, so a catalog row for the index name is guaranteed to exist by the time
  0012 runs, valid or not); no plaintext/PII logging (only index/table names in SQL
  comments and the exception message); no wire-format/API/behavior change
  (`threat-model-checker` correctly not required, diff scoped to `migrations/*.sql` +
  `tests/pg_security_it.rs` only).
- 2 new `#[ignore = "requires Docker (testcontainers)"]` tests in `pg_security_it.rs`:
  `full_migration_run_leaves_new_envelope_index_valid_and_old_index_dropped` (happy-path,
  full `sqlx::migrate!()` run leaves the new index valid + old index gone) and
  `envelope_poll_idx_validity_guard_aborts_on_invalid_index` (reproduces an invalid index
  via a `CREATE UNIQUE INDEX CONCURRENTLY` that fails on a genuine duplicate-key violation
  — the standard reliable way to get Postgres to leave a catalogued-but-invalid index, since
  there's no supported way to directly flip `pg_index.indisvalid` on a healthy one — then
  runs the **actual shipped 0012 SQL** via `include_str!`, string-substituting the index
  name, proving both directions: raises when invalid, passes silently once rebuilt valid).
  Not run locally (no Docker in this sandbox, consistent with prior cycles — will run in
  CI's Rust workflow, which has Docker). `cargo build --workspace` clean, `cargo test
  --workspace` (non-ignored) all green, `cargo clippy --workspace --all-targets -- -D
  warnings` clean, `cargo fmt --check` clean (one auto-fix applied mid-cycle for the two
  new happy-path assertions' line length, no logic change).
- Target dir hygiene: not checked this cycle (FEATURE mode, not due).
- **Next cycle candidates:** closing the incoming/outgoing media-key asymmetry (cycle 349,
  needs a new crypto-reviewed WASM key-export primitive); PQ hybrid Phase A (still blocked
  on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003
  Phase B 95%-session threshold); cycle 356's YELLOW note (KeyPackage 16KiB cap margin
  narrows under Phase A native PQ — revisit alongside that work, not standalone);
  project-context.md archival (now 2300+ lines — worth archiving older cycle entries in a
  future stabilization cycle, getting more pressing each cycle this is deferred).

## Previous state (2026-08-25, cycle 357 — FEATURE: cross-crate REST/gRPC envelope size-cap sync test, commit 781348e)

- CI green (`gh run list --limit 3` all success), `gh issue list --state open` empty,
  `git status` clean at cycle start. Picked cycle 356's top carried-forward candidate:
  threat-model-checker's cycle 355 follow-up — no compiler/test-enforced sync between
  `messaging_service.rs`'s (`powehi-application`, REST ingress) and
  `powehi-grpc/server.rs`'s (cross-region forwarder) deliberately-duplicated
  `MAX_CIPHERTEXT_BYTES`/`MAX_COMMIT_BYTES`/`MAX_WELCOME_BYTES` constants — this exact
  pair had already drifted silently once before (RED-1, cycle 353: a stale generic 1MiB
  gRPC cap outlived a tightened 96KiB REST cap).
- **Fix:** widened the three constants in each crate from private `const` to `pub const`
  (both modules were already `pub mod`, so no new module exposure) and added
  `bin/powehi-server/tests/size_cap_consistency.rs` — the only crate in the workspace
  that already depends on both `powehi-application` and `powehi-grpc` (the composition
  root), so no new cross-crate dependency was introduced. The test file has both a
  `const _: () = assert!(...)` per pair (fails `cargo build`/`cargo check` itself, added
  post-review per the auditor's suggestion — stronger than a runtime test since it can't
  be skipped by filtering `cargo test`) and matching `#[test]` runtime assertions with
  descriptive failure messages.
- **security-auditor: GREEN.** Verified (not rubber-stamped): all six constants are
  literal `usize` byte-size values, not derived from config/env/key material — `pub`
  grants read of a compile-time integer only, no capability; values are already
  black-box discoverable via size probing by any client, so zero information
  disclosure. New test file confirmed pure `assert_eq!`/`assert!` on consts, no I/O/DB/
  testcontainers/fixtures, non-flaky by construction (ran it: 3/3 passed in 0.00s). No
  other code in the diff besides the visibility bump + doc comments + new test file. No
  plaintext/PII/ciphertext logging added (zero log statements in the diff).
- Not architectural, no new server-visible metadata (pure internal visibility change +
  test-only addition, no wire-format/behavior change) — `threat-model-checker` re-run
  not required (it was the one that requested this fix); `crypto-reviewer` not required
  (no crypto code touched).
- `cargo build --workspace` clean, `cargo test --workspace` all green (no regressions,
  new 3 tests pass), `cargo clippy --workspace --all-targets -- -D warnings` clean,
  `cargo fmt --check` clean (one auto-fix applied mid-cycle for the const-assert
  formatting, no logic change).
- Target dir hygiene: not checked this cycle (FEATURE mode, not due).
- **Next cycle candidates:** `pg_index.indisvalid` migration guard automation for
  0011/0012 (cycle 355's other follow-up, cheap, low urgency); closing the incoming/
  outgoing media-key asymmetry (cycle 349, needs a new crypto-reviewed WASM key-export
  primitive); PQ hybrid Phase A (still blocked on openmls stable `MLS_128_MLKEM768`);
  OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B 95%-session threshold);
  cycle 356's YELLOW note (KeyPackage 16KiB cap margin narrows under Phase A native PQ
  — revisit alongside that work, not standalone); project-context.md archival
  (now 2200+ lines — worth archiving older cycle entries in a future stabilization
  cycle, getting more pressing).

## Previous state (2026-08-25, cycle 356 — FEATURE: KeyPackage upload per-item size cap, commit d0f0c8e)

- CI green (`gh run list --limit 3` all success), `gh issue list --state open` empty,
  `git status` clean at cycle start. Picked cycle 350's last remaining deferred LOW
  finding (the other two from that sweep — broadcast-ack access control, envelope
  pagination/size caps — were closed cycles 350/355): `KeyPackageService::upload`
  capped package *count* per call (50) and per device (200) but not individual byte
  size, inconsistent with `invite_service.rs`'s `MAX_KEY_PACKAGE_BYTES`/
  `auth_service.rs`'s `MAX_MLS_CREDENTIAL_BYTES` precedent.
- **Fix:** added the same `MAX_KEY_PACKAGE_BYTES = 16 * 1024` constant to
  `key_package_service.rs`. `upload()` now rejects the whole batch fail-closed (empty
  or >16KiB on any item) before the per-device count check's DB round trip — no
  partial upload, since `save()` loops individual INSERTs with no transaction.
- **security-auditor: GREEN.** Verified (not rubber-stamped): built a temporary probe
  in `powehi-crypto-wasm` to measure a real `openmls` KeyPackage wire size
  (PQ-hybrid-extension-included, current Phase B interim ciphersuite) at 1,541 bytes —
  16KiB gives ~10.6x headroom, no legitimate-KeyPackage rejection risk; reverted the
  probe, confirmed working tree clean before commit. No bypass path (`save`'s only
  caller is post-check; `upload`'s only production caller is the REST route; gRPC only
  reads/consumes, never writes). Fail-closed whole-batch rejection is the only clean
  choice given `save`'s non-transactional insert loop, consistent with the existing
  count-cap's same all-or-nothing behavior. No plaintext/PII logging (bytes are
  `#[instrument(skip(...))]`, error strings are static categories, `ApiError::from`
  collapses all `InvalidInput` variants to `400 invalid_input` client-side). One
  YELLOW informational, non-blocking: prd.md §5.3's Phase A native-PQ KeyPackage
  estimate (~8000B) + a max-size 4KiB LeafNode credential narrows headroom to ~25% —
  worth revisiting when `POWEHI_PQ_MLS_NATIVE_ENABLED` is ever flipped on, not now.
- Not architectural, no new server-visible metadata (same disclosure precedent as the
  existing `MAX_KEY_PACKAGE_BYTES`/`MAX_MLS_CREDENTIAL_BYTES` caps) —
  `threat-model-checker`/`crypto-reviewer` not required (diff touches no crypto code).
- 4 new tests in `key_package_service.rs` (oversized rejected, at-limit accepted,
  empty rejected, mixed-batch rejects whole batch with zero partial-store state;
  module total 8→12). `cargo test --workspace` all green, `cargo clippy --workspace
  --all-targets -- -D warnings` clean, `cargo fmt` applied (2 lines reformatted, no
  logic change).
- Target dir hygiene: not checked this cycle (FEATURE mode, not due — last checked
  cycle 355 at 14GB, well under the 20GB threshold).
- **Next cycle candidates:** the two follow-ups from cycle 355 (cross-crate
  size-cap-drift test between `messaging_service.rs`/`powehi-grpc/server.rs`;
  `pg_index.indisvalid` migration guard automation for 0011/0012) — both cheap, low
  urgency; closing the incoming/outgoing media-key asymmetry (cycle 349, needs a new
  crypto-reviewed WASM key-export primitive); PQ hybrid Phase A (still blocked on
  openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on
  ADR-0003 Phase B 95%-session threshold); this cycle's new YELLOW note (KeyPackage
  16KiB cap margin narrows under Phase A native PQ — revisit alongside that work, not
  standalone); project-context.md archival (166KB→ now larger, worth archiving older
  cycle entries in a future stabilization cycle).

## Previous state (2026-08-24, cycle 355 — STABILIZATION: envelope poll pagination + per-type size caps, commit 97c6c7c)

- CI green (`gh run list --limit 5` all success/cancelled-superseded), `gh issue list
  --state open` empty. **`git status` at cycle start was NOT clean** — found a complete,
  passing, uncommitted working-tree diff spanning what its own doc comments described as
  cycles 351-353 (same "cycle silently fails to commit" pattern as cycles 324/326/330/
  332/341/342). Per CLAUDE.md's investigate-before-discarding guidance, validated rather
  than discarded: `cargo build --workspace` clean, `cargo test --workspace` all green (no
  regressions), `cargo clippy --workspace --all-targets -- -D warnings` clean, frontend
  `pnpm test --run` 105/105 files / 1502/1502 green (was 1498), `tsc -b`/`biome check`
  clean. The diff's doc comments *claimed* prior review cycles already happened but were
  never committed — treated as unverified claims, not fact, and re-reviewed properly
  before this commit (see below). `pg_security_it.rs`'s new pagination test needs
  testcontainers/Docker, unavailable in this session's sandbox — not run locally, will be
  exercised by CI's Rust workflow (which has Docker) on push.
- **What it does:** closes both findings security-auditor deferred from cycle 350:
  1. `find_pending` had no LIMIT/pagination — a device with a large backlog (offline for
     a long time, or a flooded group) could force `poll_envelopes` to serialize an
     unbounded JSON response, risking OOM on the polling device. Fixed: exact
     `(created_at, id)` keyset cursor (`ENVELOPE_POLL_LIMIT=64` rows,
     `ENVELOPE_POLL_MAX_BYTES=4MiB` cumulative raw bytes, at-least-one-row-always-returned
     for a single oversized envelope), backed by a new 3-column index
     (`envelopes_recipient_created_id_idx`, migrations 0011/0012 — `CREATE INDEX
     CONCURRENTLY` first, `DROP INDEX CONCURRENTLY` of the old 2-column index second, so
     the table is never unindexed or lock-held during the build; `-- no-transaction`
     marker required since Postgres forbids `CONCURRENTLY` inside sqlx's default
     migration transaction).
  2. No server-side size cap on message ciphertext beyond the global 512KB body limit
     (inconsistent with `invite_service.rs`'s `MAX_KEY_PACKAGE_BYTES`/`auth_service.rs`'s
     `MAX_MLS_CREDENTIAL_BYTES` precedent). Fixed: per-type caps in
     `messaging_service.rs` — `MAX_CIPHERTEXT_BYTES=96KiB` (Application),
     `MAX_COMMIT_BYTES=64KiB`, `MAX_WELCOME_BYTES=256KiB` — checked before the membership
     DB round-trip in `send_message`/`send_welcome`/`send_commit`. Mirrored in
     `powehi-grpc/src/server.rs`'s cross-region `forward_envelope`/`forward_commit`,
     replacing a single generic 1MiB cap that would have let a compromised peer region
     forward oversized Application/Proposal envelopes and silently invalidate
     `ENVELOPE_POLL_LIMIT`'s documented worst-case-per-poll memory bound.
  REST `poll` endpoint's `PollQuery.since` changed from a Unix-timestamp `i64` to an
  RFC3339 string, plus a new `since_id` field — together they're the keyset cursor pair;
  `since_id` without `since` is rejected fail-closed. Frontend (`useMessages.ts`/
  `useWelcomePoller.ts`) advances the cursor to the last envelope of every fetched page
  unconditionally (even a page the hook doesn't fully act on — wrong group, undecryptable
  Welcome, decrypt-rate-deferred), so the next poll always moves forward; a large backlog
  drains over repeated 3s-interval ticks rather than a single in-tick loop.
- **security-auditor: GREEN.** Verified (not rubber-stamped): the byte-trim loop's
  at-least-one-row guarantee, the keyset cursor's injection-safety and gap/duplicate-
  freedom (checked against the new `find_pending_keyset_cursor_splits_same_timestamp_
  group_safely` testcontainers test — 71+ same-`created_at` envelopes paged across 10
  rounds, zero loss), the 0011/0012 migration's `-- no-transaction` mechanism against
  sqlx's actual vendored source, no bypass of the new size caps from any other route
  handler (invite.rs/push_subscription.rs/region.rs/lib.rs diffs are pure trait-signature
  plumbing for the new `since_id` param, not new call sites), no broken-access-control
  regression from since/since_id (device-scoping WHERE clause is independent of and
  applied before the cursor predicate), no plaintext/PII/ciphertext logging added. One
  non-blocking follow-up: automate a `pg_index.indisvalid` guard between 0011/0012
  instead of relying on the migration's documented manual runbook step for the rare
  interrupted-CONCURRENTLY-build case.
- **threat-model-checker: GREEN, no prd.md changes required.** Envelope ciphertext size
  was already disclosed as server-visible in prd.md §3.3 — the new caps don't add a new
  observable signal, same `MAX_KEY_PACKAGE_BYTES` precedent. Verified the pagination
  cursor can't be used as an existence oracle (a forged `since_id` can only reposition
  within the caller's own already-authorized row set, since the device-scoping filter is
  independent of the cursor predicate) and can't cause a *permanent* skip (only
  latency — draining a large/flooded backlog over multiple poll ticks, not a single-tick
  loop, is a documented availability property, not a correctness regression). Two
  non-blocking follow-ups noted: (a) no compiler-enforced sync between the REST-side
  (`messaging_service.rs`) and gRPC-side (`powehi-grpc/server.rs`) size-cap constants —
  worth a cross-crate test asserting they match, to fail CI instead of requiring a human
  to notice future drift (closing this the same way a future cycle 352-style gap would
  reopen it); (b) `MAX_WELCOME_BYTES=256KiB` is generous on paper but the pre-existing
  (unchanged by this diff) global `MAX_BODY_BYTES=512KB` body limit already truncates a
  raw Welcome to ~143KB before this check is ever reached (JSON-numeric-array ~3.57x
  inflation on a plain `Vec<u8>` field) — a pre-existing availability constraint on
  large-group MLS Welcomes, not introduced or worsened by this diff, flagged for a future
  `serde_bytes`/base64 encoding fix if ever prioritized.
- New/updated tests: `pg_security_it.rs` gained `find_pending_paginates_large_backlog`
  and `find_pending_keyset_cursor_splits_same_timestamp_group_safely` (testcontainers,
  not run locally this cycle — no Docker in sandbox, will run in CI); `messaging_service.rs`
  gained 3 oversized-payload rejection tests + 1 at-limit-accepted test;
  `powehi-grpc/server.rs` gained a per-type-cap-dispatch test (Welcome between the
  Application and Welcome caps is accepted, not rejected at the tighter cap) + an
  oversized-Welcome-rejected test; frontend `useMessages.test.ts`/`useWelcomePoller.test.ts`
  gained cursor-advancement coverage. **Frontend: 105/105 files, 1502/1502 tests green**
  (was 1498). `tsc -b` clean, `biome check` clean.
- Target dir hygiene: pruned 0-byte `.rmeta` stubs; `target/` at 14GB, under the 20GB
  prune threshold, no further action needed. `project-context.md` at 166KB/2059 lines,
  under the 256KB Read cap — no archive needed yet, but getting closer; worth archiving
  older cycle entries (300s) to a separate file in a future stabilization cycle if it
  keeps growing.
- **Next cycle candidates:** the two follow-ups from this cycle's reviews (cross-crate
  size-cap-drift test; `indisvalid` migration guard automation) — both cheap, low
  urgency; `KeyPackageService::upload`'s missing per-KeyPackage size cap (cycle 350's
  other deferred LOW finding, still not picked up — cheap, same pattern as
  `MAX_KEY_PACKAGE_BYTES` in invite_service.rs to copy); closing the incoming/outgoing
  media-key asymmetry (cycle 349, would need a new crypto-reviewed WASM key-export
  primitive); PQ hybrid Phase A (still blocked on openmls stable `MLS_128_MLKEM768`);
  OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B 95%-session threshold);
  project-context.md archival (noted above, not urgent yet).

## Previous state (2026-08-24, cycle 350 — STABILIZATION: fix broken access control in broadcast envelope ack, commit bd82201)

- CI green, `gh issue list --state open` empty, `git status` clean at cycle start. Full
  baseline pass before picking a target: backend `cargo build/test --workspace` green,
  `cargo audit`/`cargo deny check` clean, `cargo clippy --workspace --all-targets -- -D
  warnings` clean; frontend 105/105 files, 1498/1498 tests, `tsc -b`/`biome check` clean,
  `pnpm audit --prod` clean. Dispatched `security-auditor` + `crypto-reviewer` sweeps in
  parallel to find a concrete fix target (crypto-reviewer's sweep returned truncated/
  inconclusive — not resumable, not pursued further since this cycle's fix ended up
  non-crypto anyway).
- **security-auditor found a real HIGH-severity broken-access-control bug:**
  `ack_envelope` (`messaging_service.rs`) hard-deleted any broadcast envelope (group
  Application messages AND MLS Commit envelopes — anything with `recipient == None`) on
  the **first** ack from **any authenticated device**, with zero group-membership check
  and no per-device delivery tracking. Any group member — or any authenticated device
  that obtained/guessed an `envelope_id` — could delete a group message before other
  members polled it (silent censorship), or delete a Commit envelope, which is worse:
  MLS cannot self-heal from a dropped Commit, so this was a permanent group-epoch-desync
  DoS. Two more findings from the same sweep deferred (see below).
- **Fix:** new `envelope_acks(envelope_id, device_id)` table (migration
  `0010_envelope_acks.sql`), same shape/precedent as `media_acks` (cycle 289).
  `EnvelopeRepository` gained `ack_broadcast(envelope_id, device_id, group_member_ids)`;
  `PgEnvelopeRepository`'s impl inserts an ack row then deletes the envelope in the same
  transaction only if every id in `group_member_ids` now has an ack row (SQL
  set-containment `NOT EXISTS` check, atomic). `MessagingService::ack_envelope` now
  calls `check_sender_is_member` before accepting a broadcast ack (closes the actual
  membership hole), then passes the current member list (minus the envelope's own
  sender — see below) to `ack_broadcast`.
- **threat-model-checker caught a RED blocking bug in the first draft:** the initial fix
  passed *all* group members (including the sender) as the required-ack set. But a
  sender never acks their own broadcast — `useMessages.ts` in the frontend documents
  that a sender's own envelope fails MLS decrypt client-side and is deliberately never
  acked, "stays server-side indefinitely." So the all-members-acked condition could
  **never** be satisfied for an ordinary group message → GC unreachable → unbounded
  ciphertext retention / storage DoS, directly contradicting prd.md §11.4's documented
  `Stored_Server → Expired: TTL 도달 (기본 30일)` state. Fixed by excluding the
  envelope's sender from the required-ack set (mirrors `media_service.rs`'s existing
  uploader-exclusion pattern for the exact same reason). Also added the missing default
  30-day retention floor to `delete_expired` for envelopes with `expires_at IS NULL`
  (a backstop for members who leave a group without ever polling, so a straggler
  membership record can't pin an envelope forever) — this path in prd.md §11.4 existed
  in the diagram but was never actually implemented for envelopes before this cycle.
  Re-reviewed: threat-model-checker's second listed concern (new `envelope_acks`
  metadata category, higher-resolution than `media_acks` since it fires on every
  message not just shared media) addressed by adding a `docs/prd.md` §3.3 bullet + a
  §3.4 GC-timing-oracle paragraph extension, same disclosure precedent as
  `media_acks`/cycle 289-290.
- 3 new/updated unit tests in `messaging_service.rs` (non-member ack rejected +
  envelope survives; multi-member ack sequencing proves GC never needs the sender's own
  ack) — `cargo test --workspace` green (was 172 passed in `powehi-application`, still
  172 after edits — net even: 1 test rewritten, 2 added, one pre-existing test's
  assertion target changed from a random non-member device to the actual sole member,
  since acking as a non-member now correctly fails). Also had to add trivial
  `ack_broadcast` stubs to two no-op `EnvelopeRepository` test fakes in
  `powehi-grpc/src/server.rs` (compile-only impact, not exercised). Full
  build/test/clippy/fmt green after the fix.
- **Two more security-auditor findings from the same sweep, deferred as next-cycle
  candidates (documented, not blocking — both lower severity than the one fixed):**
  1. *(MEDIUM-HIGH)* `find_pending` has no `LIMIT`/pagination and `poll_envelopes`
     serializes the whole result into one JSON response — a sustained-send device could
     build a backlog that OOMs the victim's next poll. No per-message size cap beyond
     the global 512KB body limit either. Needs `LIMIT`+keyset pagination on
     `created_at` plus an explicit `MAX_CIPHERTEXT_BYTES` check in `send_message`.
  2. *(LOW)* `KeyPackageService::upload` caps count (50/call, 200/device) but not
     individual KeyPackage size, inconsistent with `invite_service.rs`'s
     `MAX_KEY_PACKAGE_BYTES = 16 KiB` and `auth_service.rs`'s
     `MAX_MLS_CREDENTIAL_BYTES`. Cheap fix, same pattern to copy.
- Target dir hygiene: pruned 0-byte aborted-build `.rmeta` stubs; `target/` at 11GB,
  under the 20GB prune threshold, no further action needed.

## Previous state (2026-08-24, cycle 349 — FEATURE: persist media messages (photo/video/voice) to Dexie, commit 2b05798)

- CI green (`gh run list --limit 3` all success), `gh issue list --state open` empty,
  `git status` clean at cycle start. Dispatched an Explore-agent scoping pass first on
  cycle 347's largest carried-forward candidate — the media-message-has-zero-Dexie-
  persistence gap (flagged since cycle 343) — before committing a cycle to it: confirmed
  the R2 blob itself is durable server-side (no client-side blob cache exists), so
  persisting only `blobId+key+iv+thumbnail+mimetype` (never raw bytes) to Dexie is
  sufficient to re-fetch and redecrypt after reload — achievable in one focused cycle,
  not the multi-part effort earlier cycles assumed.
- **Fix:** `MessageRow.mediaJson?: string` (schema v27, `db/schema.ts`) — JSON-encoded
  `MediaPayload`, added to `SENSITIVE.messages` in `encrypted-db.ts` (same transparent
  FieldEncryptor boundary as `pollJson`/`reactionsJson`/`replyToJson`, no new crypto
  primitives). `persistIncoming` (`usePersistentMessages.ts`) threads `msg.media` into
  `mediaJson` on receive. `persistOutgoing` gained an optional `media` param, but the
  actual send call sites (`useMediaSend.ts`, `ChatLayout.tsx`'s `sendForwardToSelected`)
  only ever pass a placeholder text ("Image attachment"/"Video attachment"/"Voice
  message") plus the real ciphertext — **documented architectural asymmetry**: the raw
  AES-256-GCM media key never crosses the WASM→JS boundary on send
  (`encryptAndSendMedia` in `mediaTransfer.ts` returns only an opaque-handle-backed
  result, never key bytes), so a sender has no key to persist for their own
  redisplayable copy. Not a regression — the live pre-reload optimistic bubble for a
  sent attachment never rendered an inline preview either, only this same placeholder.
  Closing the asymmetry would need a new, crypto-reviewed WASM key-export-for-storage
  primitive — explicitly out of scope this cycle. `encryptAndSendMedia`'s signature
  changed `Promise<void>` → `Promise<{envelopeId, ciphertextB64}>` so send call sites can
  persist; no wire-format change, purely a local re-encoding of already-sent bytes.
  ChatLayout's rehydration effect parses `row.mediaJson` back into `ChatMessage.media`.
- Delegated implementation to `frontend-lead` (had to resume it once — its first pass
  cut off mid-task with no tests written yet; the resume completed tests +
  verification).
- **security-auditor: YELLOW, both MEDIUM findings fixed in-cycle:**
  1. *(fixed)* Rehydration's shape validation (`ChatLayout.tsx`) checked only
     `blobId`/`blobHash`/`mediaKey`/`iv`, weaker than the live receive path
     (`useMessages.ts`), which also validates `thumbnail.ct/key/iv` exact lengths
     (≤16384/32/12) and `chunked`⇒`totalSize`/`chunkSize` validity. A malformed-but-
     truthy `thumbnail` on a rehydrated row would crash synchronously inside
     `useThumbnail`'s `thumbnail.key.length` check, uncaught — no ErrorBoundary in the
     tree. Fixed: hoisted both paths' predicates into one shared, exported
     `isValidMediaPayload()` (`useMessages.ts`), used by both the receive path (which
     also got simpler — removed ~35 lines of duplicated inline validation) and
     rehydration. mimeType sanitization (not part of the shared validator, since a bad
     mimeType shouldn't invalidate an otherwise-valid attachment) kept as an explicit
     per-branch step so it isn't silently dropped by the refactor.
  2. *(fixed)* The new rehydration test's headline assertion (`useMediaReceive` called →
     image renders) survived the reviewer's content-substitution mutation (swapping in a
     wrong `blobId`/`mediaKey`/`iv` still passed both checks), since `useMediaReceive`
     was stubbed and its call args never inspected — didn't actually prove the *right*
     key material survived the round trip, only that *some* media object did. Fixed:
     added `expect(useMediaReceive).toHaveBeenCalledWith(expect.objectContaining(media))`.
  3. *(informational, fixed cheaply)* `putMessage`'s redelivery-merge preserve-list
     doesn't carry over `mediaJson` (same as `replyToJson`) — benign since both are
     set-once-at-creation fields, a replayed `persistIncoming` for the same id carries
     the identical value in the fresh row anyway. Added a one-line comment explaining
     the omission is intentional, not an oversight.
  4. *(informational, not fixed)* one harmless redundant-narrowing nit in
     `sendForwardToSelected` (`targetChat.mlsGroupId` re-read into a local before a
     truthiness check inside a `.then` closure) — left as-is, TS's control-flow analysis
     doesn't retain narrowing on an object property across a closure boundary, so it may
     not actually be redundant.
- 1 new test file (`ChatLayoutMediaPersistence.test.tsx`: incoming-media rehydration +
  redisplay, corrupt-JSON safety, shape-invalid safety, outgoing-placeholder-only case)
  plus new/updated tests in `db/schema.test.ts`, `db/encrypted-db.test.ts`,
  `hooks/usePersistentMessages.test.ts`, `hooks/useMediaSend.test.ts`,
  `lib/mediaTransfer.test.ts`. **Frontend: 105/105 files, 1498/1498 tests green** (was
  104/1479). `tsc -b` clean, `biome check` clean (1 import-sort auto-fix applied
  post-review, no logic change). Production build: initial route 165.70 kB gzip / WASM
  642.87 kB gzip (both under prd.md §7 budgets).
- Not architectural, no new server-visible metadata (purely local Dexie persistence of
  data already flowing through existing send/receive paths, confirmed via `git diff
  --stat` — no MLS/OPAQUE/wire-format changes) — `threat-model-checker`/`crypto-reviewer`
  not required, same scoping precedent as `pollJson`/`replyToJson`/`scheduledFor`.
- **Next cycle candidates:** closing the incoming/outgoing media-key asymmetry (would
  need a new crypto-reviewed WASM key-export-for-local-storage primitive — bigger,
  crypto-adjacent, worth its own cycle if ever prioritized); the harmless redundant-
  narrowing nit in `sendForwardToSelected` (cheap, non-blocking); PQ hybrid Phase A
  (still blocked on openmls stable `MLS_128_MLKEM768`, openmls still pinned at 0.8.1 —
  re-checked this cycle); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B
  95%-session threshold).

## Previous state (2026-08-24, cycle 348 — FEATURE: mlsDecrypt cost bound + CI permissions hardening, commits a3eeee8 + 8db1748)

- CI green, `gh issue list --state open` empty at cycle start. Picked up both of cycle
  347's flagged candidates in one cycle: the CI `permissions:` hardening (cheap) and the
  security-auditor F4 unconditional-`mlsDecrypt`-cost gap (the main feature work).
- **CI hardening (a3eeee8):** `ci-frontend.yml`/`ci-rust.yml`/`ci-e2e-live.yml` had no
  top-level or job-level `permissions:` block, so `GITHUB_TOKEN` inherited repo-default
  scope. Added explicit `contents: read` to all three — none of the jobs need more.
- **mlsDecrypt cost bound (8db1748):** every Application envelope for the active group
  unconditionally paid a real `mlsDecrypt` WASM round trip before type dispatch,
  including garbage/tampered ciphertext that would fail to decrypt — the cycle 346
  reaction-rate-limiter only bounds envelopes that decrypt successfully and parse as a
  reaction, so a flooding sender still cost N decrypt attempts regardless. Added a
  coarser per-sender decrypt-attempt budget (100/10s) gating the `mlsDecrypt` call
  itself, layered on top of the existing reaction limiter.
- **security-auditor caught a silent-data-loss bug in the first draft:** dropping
  over-budget envelopes outright would have silently swallowed real text messages behind
  a burst of unrelated traffic (e.g. ~100 presence heartbeats over ~50 minutes with one
  chat left open), since the server's `find_pending` query has no redelivery path other
  than an explicit ack. Fixed: over-budget envelopes are deferred into a bounded local
  queue (500 cap) instead, retried on later poll ticks and merged/deduped by id once the
  sender's window frees up — no data loss, only latency. Also corrected a pre-existing
  inaccurate comment claiming un-acked envelopes are GC'd via server-side TTL (only
  disappearing-message `expires_at` triggers that; otherwise they're redelivered
  indefinitely on a later since-eligible poll).
- Not architectural, no new server-visible metadata (client-side receiver-side
  throttling only, no wire-format change) — `threat-model-checker`/`crypto-reviewer` not
  required, same scoping precedent as the cycle 346 reaction-rate-limit fix.
- **Next cycle candidates carried forward:** the media-message-has-zero-Dexie-
  persistence gap (large, flagged cycle 343 — picked up and closed this cycle, see
  cycle 349 above); PQ hybrid Phase A (still blocked); OPAQUE PQ-hybrid OPRF upgrade
  (gated on ADR-0003 Phase B 95%-session threshold).

## Previous state (2026-08-23, cycle 347 — FEATURE: real-browser Dexie.waitFor transaction-liveness test (F3), commit 2eb8ccf)

- CI green (`gh run list --limit 3` all success), `gh issue list --state open` empty,
  `git status` clean at cycle start. Picked cycle 346's top carried-forward candidate:
  **F3** — the `Dexie.waitFor`-held `rw` transaction in `markMessageReactionDelta`
  (encrypted-db.ts; async crypto-worker round trip *inside* an IndexedDB transaction) had
  only ever been exercised against `fake-indexeddb` in Vitest, never a real browser
  engine. First flagged cycle 344, deferred 3 cycles running (345, 346).
- **Fix:** new `app/e2e/dexie-transaction-liveness.spec.ts`. Navigates to `/`, then via
  `page.evaluate` dynamically imports `/src/db/encrypted-db.ts`/`/src/db/schema.ts`
  directly from the Vite dev server (no bundling — dev-server-only technique, confirmed
  by security-auditor to have zero prod exposure: prod build emits hashed bundles with
  no `/src/*.ts` route, and the spec lives outside `tsconfig.app.json`'s `include`).
  Constructs a real `PowehiDb` + `EncryptedPowehiDb`, injects a fake `FieldEncryptor`
  (duck-typed against the existing port in encryption.ts) whose `encryptDbField`/
  `decryptDbField` use a real `setTimeout`-based 40ms delay — a genuine macrotask, unlike
  an instantly-resolved Promise — standing in for the crypto-worker's postMessage round
  trip. Fires two concurrent `markMessageReactionDelta` calls from different senders and
  asserts both merge (no clobber, no rejected promise) — same race
  `encrypted-db.test.ts`'s existing fake-indexeddb test covers, but here against a real
  engine's actual IndexedDB transaction-lifetime behavior.
- Added a second Playwright project `webkit-dexie-liveness` (`devices["Desktop Safari"]`)
  in `playwright.config.ts`, scoped via `testMatch` to just this one spec so the rest of
  the suite doesn't pay a second real-browser run per spec; the pre-existing `chromium`
  project still runs it too (plus every other spec, unchanged). `ci-frontend.yml`'s
  `playwright` job now installs both `chromium` and `webkit` browsers (`--with-deps`).
  Installed webkit locally (`pnpm exec playwright install webkit --with-deps`, 76.7 MiB)
  to actually run and verify the test before committing — was not previously present in
  this dev environment (only chromium was, matching what CI installed pre-diff).
- **security-auditor: GREEN**, both informational notes fixed in-cycle (not blocking, but
  cheap):
  1. The reviewer **mutation-tested the test itself** — temporarily removed both
     `Dexie.waitFor` wrappers from `markMessageReactionDelta`, confirmed the spec fails
     with `TransactionInactiveError: Transaction has already completed or failed` on
     *both* chromium and webkit, restored the file via `git checkout`, confirmed all 9
     `Dexie.waitFor` call sites intact. **Not vacuous — catches the exact regression it
     claims to guard**, and notably this proved chromium's real engine *also* reproduces
     the failure, not just webkit.
  2. *(fixed)* the test's `indexedDB.deleteDatabase("PowehiDb")` cleanup resolved on the
     `onblocked` event instead of rejecting — safe today (traced every production
     `new EncryptedPowehiDb(...)` call site, all are post-login, so `page.goto("/")`
     never opens the DB pre-test) but a latent flake if the app ever gains a pre-login
     IndexedDB read, since `schema.ts`'s module-level `db` singleton is the same module
     record the test's dynamic import resolves to. Fixed: `onblocked` now rejects with an
     explicit error instead of silently continuing against potentially-stale state.
  3. *(fixed, doc-only)* both the spec's top comment and the new Playwright project's
     comment overclaimed "WebKit is the historically stricter engine... only a real
     browser can exercise this" as if webkit were required to catch the regression — the
     reviewer's own mutation test (finding 1) showed chromium already catches it too.
     Corrected both comments: webkit is engine-diversity insurance against future
     divergence, not load-bearing for closing F3.
  Also confirmed: no plaintext/key-material/PII leakage (fake encryptor's in-memory Map
  holds only synthetic fixture data, dies with the browser context, never reaches
  traces/screenshots — `ci-frontend.yml`'s `playwright` job has no `upload-artifact` step
  regardless); no supply-chain concern from installing the webkit binary (same pinned
  `@playwright/test` version, same Microsoft CDN chromium already uses, lockfile
  unchanged); `deleteDatabase` can't reach real user data (ephemeral Playwright browser
  profile, storage-partitioned from any developer's real browser profile even when
  attached to a locally-running dev server).
- One pre-existing, unrelated observation the reviewer flagged in passing (not fixed,
  not in scope): `ci-frontend.yml` has no top-level or job-level `permissions:` block, so
  `GITHUB_TOKEN` inherits repo-default permissions — cheap hardening win, worth doing
  next time that file is touched for an unrelated reason.
- Not architectural, no new server-visible metadata (test-only + CI browser-install
  change, no production crypto/backend/MLS/OPAQUE code touched — confirmed via
  `git diff --stat`: only the new spec file, `playwright.config.ts`, and
  `ci-frontend.yml` changed) — `threat-model-checker`/`crypto-reviewer` not required;
  ran `security-auditor` anyway since the diff touches CI infra and exercises the Dexie
  encryption boundary via a new test harness.
- **Frontend: 1473/1473 Vitest tests green** (unchanged — this cycle added no new Vitest
  tests, only a new Playwright spec). **Playwright: 7/7 e2e tests green** (was 5 across 2
  projects — `chromium` only; now 7 across `chromium` + the new `webkit-dexie-liveness`
  project, +1 spec × 2 projects − 0, i.e. +2 total test executions net). `tsc -b` clean,
  `biome check` clean (2 touched files). Production build/bundle budget: not re-checked
  this cycle (no app/src/ production code touched, only e2e/ + config + CI workflow).
- **Next cycle candidates:** the unconditional `mlsDecrypt`-cost gap (cycle 346's
  security-auditor F4 — a flooding sender still forces N decrypt round trips regardless
  of the reaction-callback rate limit; broader mitigation than the lock-contention fix
  already landed, not yet scoped); the media-message-has-zero-Dexie-persistence gap
  (flagged cycle 343, large, needs new schema + threading through send/receive paths,
  worth scoping as its own multi-part effort); the `ci-frontend.yml` missing
  `permissions:` block (flagged this cycle, cheap, low urgency); PQ hybrid Phase A (still
  blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on
  ADR-0003 Phase B 95%-session threshold).

## Previous state (2026-08-23, cycle 346 — FEATURE: bound reaction/reaction_remove callback rate per sender, commit f86d6e5)

- CI green (`gh run list --limit 3` all success), `gh issue list --state open` empty, `git status`
  clean at cycle start. Picked up cycle 345's top carried-forward candidate: **F1/F7** — no
  inbound rate limit on reaction/reaction_remove envelopes, so a single flooding sender
  (compromised device, or a peer replaying a batch) could force `markMessageReactionDelta`'s
  exclusive Dexie transaction lock (held across 2 sequential crypto-worker round trips) to be
  acquired at unbounded rate, head-of-line-blocking `persistIncoming`'s `putMessage` on the same
  origin. First flagged cycle 344, deferred twice.
- **Fix:** `useMessages.ts` gained a per-sender sliding-window rate limiter — `reactionTimestampsRef`
  (a `Map<string, number[]>`) tracks up to `REACTION_RATE_MAX = 20` timestamps per `senderId`
  within a `REACTION_RATE_WINDOW_MS = 10_000` window. `withinReactionRateLimit(senderId)` is added
  as the last condition (after the existing emoji-allowlist/length checks, so a malformed envelope
  never burns real budget) gating whether `onReactionRef`/`onReactionRemoveRef` fire. Both envelope
  types share ONE budget per sender since both hit the identical costly lock path. Over-budget
  envelopes are still acked (no redelivery loop) — the callback drop is a real, permanent loss for
  that receiver past the ceiling, not a deferral; documented explicitly as an accepted DoS-bound
  tradeoff (≤2 lock acquisitions/sec/sender), not equated with the nearby malformed-envelope
  discard cases. `env.sender` is server-attested (from `Envelope.sender`, never client-supplied in
  the decrypted payload), so the rate-limit key isn't spoofable from the wire.
- **security-auditor: YELLOW, both findings fixed in-cycle:**
  1. *(fixed)* `reactionTimestampsRef` lives for the hook's whole mount (one `useMessages`
     instance per logged-in session — `groupId` just changes which chat it polls), so every
     distinct sender ever seen across every group opened in the tab would linger in the map
     forever, unbounded by current group membership. Fixed: added `sweepStaleReactionRateEntries()`,
     run once per `poll()` tick (not per envelope), deleting any map entry whose timestamps have
     all aged out of the window — bounds the map to currently-active senders.
  2. *(fixed, doc-only)* the original comment justified the callback-drop-but-still-ack behavior by
     analogy to malformed-envelope discarding, which overclaimed equivalence — a legitimate
     tail-of-burst reaction (e.g. rapid-fire reacting during an active group chat) is *valid*
     content lost purely for receiver-side resource protection, with no error/feedback to the
     sender. Rewrote the comment to state this as a deliberate, accepted tradeoff, and to scope
     precisely what's protected: only the exclusive-lock-acquisition rate — NOT the unconditional
     `mlsDecrypt` every Application envelope pays before type dispatch (a flood still costs this
     client N decrypt round trips), and nothing server-side (queue growth/bandwidth unaffected).
  Also requested (point 5 of the review) and added: a test proving a burst of malformed
  (invalid-emoji) reactions does NOT consume the sender's real budget, since the rate-limit check
  is last in the validity `&&` chain — confirms the ordering the reviewer specifically asked about.
- 4 new tests in `useMessages.test.ts`: burst-of-25-caps-at-20 (still acks all 25), per-sender
  isolation (one sender's flood doesn't throttle another sender in the same batch), shared budget
  across reaction/reaction_remove for the same sender (via `vi.useFakeTimers`/`advanceTimersByTimeAsync`
  since the second envelope needs a real poll-interval tick), window-reset after 10s elapses (same
  fake-timer technique), and the malformed-envelope-doesn't-consume-budget test added post-review.
  **Frontend: 1473/1473 tests green** (was 1472, 104 files unchanged — net +5 across the review
  round: +4 initial, +1 for the review's requested test, then 1 initial test's assertion was
  corrected from a bad standalone-budget assumption to the right shared-budget-of-21 total before
  landing). `tsc -b` clean, `biome check` clean (1 formatting auto-fix applied post-review, no
  logic change). Production build: initial route 165.28 kB gzip / WASM 642.87 kB gzip (both under
  prd.md §7 budgets).
- Not architectural, no new server-visible metadata (pure client-side receiver-side throttle on an
  existing envelope type, no wire-format or server-endpoint change) — `threat-model-checker`/
  `crypto-reviewer` not required; consistent with how the identical-class `readByJson`/`putMessage`
  merge fixes (cycles 322/345) and the original reaction-delta-merge fix (cycle 344, which is where
  F1/F7 were first raised) were scoped.
- **Next cycle candidates:** F3 from cycle 344 (Playwright test for real-browser `Dexie.waitFor`
  transaction liveness — WebKit is the historical risk case, still not done); the general
  unconditional-`mlsDecrypt`-cost gap surfaced by this cycle's security-auditor F4 (a flooding
  sender still forces N decrypt round trips regardless of the reaction-callback rate limit — this
  cycle deliberately scoped to the lock-contention vector only, decrypt-cost bounding would be a
  separate, broader mitigation if ever prioritized); the media-message-has-zero-Dexie-persistence
  gap (flagged cycle 343, large, needs new schema + threading through send/receive paths, worth
  scoping as its own multi-part effort); PQ hybrid Phase A (still blocked on openmls stable
  `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B 95%-session
  threshold); the missing `~/.cargo/bin` on `$PATH` noted cycle 345 (worked around inline both
  times it's come up, may be worth a cron-env fix if it recurs a third time — this cycle was
  frontend-only, didn't touch cargo, so not re-verified).

## Previous state (2026-08-23, cycle 345 — STABILIZATION: close putMessage full-row-overwrite gap (F4), commit cb65117)

- CI green (`gh run list --limit 3` all success), `gh issue list --state open` empty, `git status`
  clean at cycle start. Full sweep before picking work: `cargo audit` (652 crates, 0 advisories),
  `cargo deny check` (advisories/bans/licenses/sources all ok), `cargo test --workspace` all green,
  `cargo clippy --workspace --all-targets -- -D warnings` clean, frontend `pnpm test --run`
  1465/1465 green (104 files) pre-cycle, `tsc -b`/`biome check` clean. `target/` 11G, well under
  the 20G hygiene threshold — no pruning needed. `project-context.md` 132KB/1646 lines, under the
  256KB Read cap — no archive needed this cycle. Note: `cargo`/`cargo-audit`/`cargo-deny` were not
  on `$PATH` this session (`~/.cargo/bin` missing from the shell's PATH) — had to `export
  PATH="$HOME/.cargo/bin:$PATH"` explicitly for every cargo invocation this cycle; if this recurs,
  worth checking whether the cron job's shell profile sourcing regressed.
- Picked cycle 344's top carried-forward candidate: **F4**, the `putMessage` full-row-overwrite
  gap — `EncryptedPowehiDb.putMessage` (encrypted-db.ts) did a blind `.put()` with no merge, and
  its 4 call sites (`persistIncoming`/`persistOutgoing`/`persistPollCreate`/
  `persistScheduledCreate` in usePersistentMessages.ts) build fresh `MessageRow` object literals
  with no dedup against an existing row. Dispatched an Explore-agent first to confirm reachability
  before spending a cycle on it (it had been deferred 2+ cycles as "pre-existing, out of scope"):
  confirmed **live, not stale** — `useMessages.ts`'s `onMessageRef.current(...)` (→
  `persistIncoming`) fires before the fire-and-forget `ackMessage(...).catch(() => {})` DELETE; a
  transient ack failure (network blip/5xx/tab-close-mid-request) leaves the envelope un-deleted
  server-side, and the client's redelivery guard (`sinceRef`) is a plain `useRef` that resets on
  reload — so **ack failure + reload while the envelope is still server-side ⇒ the same envelope
  id gets redelivered and replayed through `persistIncoming`**, wiping whatever
  reactions/read-receipts/starred/poll-votes/expiresAt had accumulated on that row since.
- **Fix:** `putMessage` now runs the `get` + merge + `put` inside one Dexie `rw` transaction —
  if an existing row is found, the fresh row's core fields (ciphertext/plaintext/sender/epoch/etc,
  via the existing `encRow` helper) are kept, but `reactionsJson`/`readByJson`/`read`/`delivered`/
  `starred`/`editedText`/`deletedAt`/`scheduledFor`/`expiresAt`/`pollJson` are carried over
  verbatim from the existing row instead of being overwritten to `undefined`. `encRow` (the
  multi-field crypto-worker round trip) now runs *before* the transaction opens, so the `rw` lock
  only spans a synchronous get+put — no `Dexie.waitFor` needed here (unlike
  `markMessageReactionDelta`/`markMessageRead`, which must decrypt-merge-reencrypt a single field
  *inside* the transaction; `putMessage` doesn't need to inspect the existing SENSITIVE values,
  only copy their already-ciphertext bytes across).
- **security-auditor: YELLOW, all 4 findings fixed in-cycle:**
  1. *(MEDIUM, fixed)* `expiresAt` wasn't in the original preserve-list — `persistIncoming`
     recomputes `expiresAt = Date.now() + ttl*1000` at receive time, so a redelivery would have
     silently *restarted* a disappearing message's TTL from a later "now" instead of preserving
     the original expiry. Added to the preserve-list.
  2. *(MEDIUM, fixed)* `pollJson` wasn't preserved either — structurally identical to
     `reactionsJson` (locally mutated post-creation by `markMessagePoll`/`persistPollVote`), so a
     replayed `putMessage` on a poll id would wipe accumulated votes. Added to the preserve-list.
  3. *(LOW, fixed)* the first draft's regression test used an identical replay (same
     ciphertext/plaintext/epoch/receivedAt on both writes) — an implementation that just
     early-returned on `existing` found would've passed vacuously. Strengthened: the replay now
     varies `ciphertextB64`/`expiresAt` and asserts the FRESH `ciphertextB64` wins while the
     ORIGINAL `expiresAt` is preserved — proves both halves of the merge, not just one. Also
     expanded coverage to `delivered`/`editedText`/`deletedAt` (previously untested) and added a
     dedicated `pollJson`-preservation test.
  4. *(LOW, fixed, robustness)* the first draft ran `encRow` *inside* the transaction via
     `Dexie.waitFor`, holding the `rw` lock across N sequential crypto-worker round trips
     (serializes all other message writes behind it, risks Dexie's transaction-timeout abort on a
     slow worker). Moved `encRow` before `db.transaction(...)` opens — the lock now spans only the
     synchronous get+put, matching the pattern `claimScheduledFire` already argues for.
  Also updated `markMessageReactionDelta`'s doc comment, which had explicitly called out this
  exact gap as "pre-existing, out of scope here" — now points at the fix instead of re-flagging a
  closed issue in a future cycle.
- 3 new/strengthened tests in `encrypted-db.test.ts`: the redelivery-merge test (rewritten, now
  non-vacuous, covers 8 preserved fields + 1 fresh-field-wins assertion), a new poll-redelivery
  test, plus the pre-existing "no existing row → plain create" test (unchanged). **Frontend:
  1468/1468 tests green** (was 1465, 104 files unchanged). `tsc -b` clean, `biome check` clean (2
  touched files). Production build: initial route 165.14 kB gzip / WASM 642.87 kB gzip (both under
  prd.md §7 budgets).
- Not architectural, no new server-visible metadata (purely local Dexie merge logic, confirmed via
  `git diff --name-only` — only `app/src/db/encrypted-db.ts`/`.test.ts` touched, no MLS/OPAQUE/
  crypto-library code) — `threat-model-checker`/`crypto-reviewer` not required, same scoping
  precedent as the identical-class `persistReaction`/`persistRead` race fixes (cycles 322/344).
- **Next cycle candidates:** F1/F7 from cycle 344 (peer-driven reaction lock-hold amplification —
  no inbound rate limit on reactions specifically, worth a look if volume ever becomes a real
  concern); F3 from cycle 344 (Playwright test for real-browser `Dexie.waitFor` transaction
  liveness — WebKit is the historical risk case); the media-message-has-zero-Dexie-persistence gap
  (flagged cycle 343, large, needs new schema + threading through send/receive paths, worth
  scoping as its own multi-part effort); PQ hybrid Phase A (still blocked on openmls stable
  `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B 95%-session
  threshold); the missing `~/.cargo/bin` on `$PATH` this session (worked around inline, may be
  worth a cron-env fix if it recurs).

## Previous state (2026-08-23, cycle 344 — FEATURE: close concurrent-reaction persistence race, commit 2b86969)

- All phase 1-6 checklists were already complete going into this cycle; CI green
  (`gh run list --limit 3` all success), `gh issue list --state open` empty. Picked
  up the standing "next cycle candidate" note from cycle 320-343's log: `persistReaction`
  still had the same full-replace-overwrite race that `persistRead`'s `readBy` had
  before cycle 322's fix (concurrent reactions to the same message from different
  devices, each computed from a possibly-stale in-memory snapshot, could have the
  later Dexie write clobber the earlier one's entry).
- Replaced `EncryptedPowehiDb.markMessageReactions(id, reactionsJson)` (full-replace)
  with `markMessageReactionDelta(id, emoji, senderId, action: "add"|"remove")` —
  reads the persisted (encrypted) reaction map, decrypts, merges the single delta,
  re-encrypts, writes back, all inside one Dexie `rw` transaction. Unlike
  `markMessageRead`'s readByJson (unencrypted field, synchronous merge), reactionsJson
  is a SENSITIVE encrypted-at-rest field, so the merge needs two async crypto-worker
  round trips inside the transaction — used `Dexie.waitFor(...)` (documented Dexie API
  for exactly this: keep an IDB transaction alive across a non-Dexie await instead of
  letting it auto-commit early) around both the decrypt and the encrypt calls.
- `usePersistentMessages.ts`'s `persistReaction` signature changed from
  `(targetMessageId, reactions: Record<string,string[]>)` to
  `(targetMessageId, emoji, senderId, action)` — call sites in `ChatLayout.tsx`
  (`handleIncomingReaction`/`handleRemoveReaction`) already computed exactly these
  primitives before building the old full map, so the call sites got simpler, not
  more complex. Optimistic `rows` update recomputes the merge from each row's latest
  functional-update snapshot.
- **security-auditor: YELLOW** (not FAIL — reviewed via Task before commit since this
  touches the Dexie encryption boundary). PASS on all 4 explicitly-asked questions: no
  plaintext/sender-id leakage into logs or thrown errors; `Dexie.waitFor` fails closed
  (rejection/60s-timeout aborts the transaction, no partial/half-merged write can
  land); the race is genuinely closed for reaction-vs-reaction (IDB serializes
  overlapping-scope rw transactions); no auth/authz regression (senderId is still
  `env.sender`, the server-attested device id — a malicious peer still can't forge
  another device's reaction, and can now only ever filter its OWN id out on remove).
  Findings applied this cycle: (F6) bounded reaction `targetMessageId` to `<=36` chars
  in `useMessages.ts` (matches `read_receipt`'s existing bound; auditor's own
  suggested cheapest mitigation for the lock-hold concern below) — done; (F8) fixed
  two stale doc-comment references to the removed `markMessageReactions` name, and
  clarified `markMessageReactionDelta`'s doc comment to not overclaim that the merge
  guarantee extends to `putMessage`'s full-row overwrite path — done. Deferred to a
  future cycle (pre-existing or narrow-impact, not regressions from this diff): (F1)
  the transaction now holds an exclusive lock across TWO crypto round trips on a
  peer-driven (reaction-rate) hot path, with no inbound rate limit today — could
  head-of-line-block `persistIncoming`'s `putMessage` under a reaction burst; (F2)
  optimistic `rows`/`chats` state isn't rolled back if the Dexie transaction aborts
  (self-heals on reload, no capability granted); (F3) the new concurrent-merge test
  runs against `fake-indexeddb`, not a real-browser transaction-liveness check
  (WebKit is the historical risk case for `waitFor`-held transactions) — a Playwright
  assertion would close this; (F4) `putMessage` (full-row upsert, encryption outside
  any transaction) can still wipe `reactionsJson`/`readByJson`/etc. on a duplicate/
  replayed `persistIncoming` for an id that already has reactions — pre-existing,
  same class noted for `readByJson` previously, doc-comment overclaim now fixed but
  the underlying gap remains; (F5) `pendingWriteIds` is a Set not a refcount, so two
  concurrent same-id reaction writes can have the first's `.finally` clear the guard
  while the second is still in flight (pre-existing shape, now more reachable since
  concurrent same-id writes are the scenario this fix targets); (F7) reaction senders
  array has no cardinality bound (pre-existing, cost of the bound now paid inside the
  exclusive lock too — compounds F1 under a compromised-server device-id-minting
  scenario).
- Not architectural, no new server-visible metadata (pure local persistence/merge
  logic for reactions that were already being received over the wire) —
  `threat-model-checker`/`crypto-reviewer` not required, consistent with how the
  identical `persistRead` fix (cycle 322) and the edit/delete/reaction persistence
  work (cycles 252-254) were scoped.
- `tsc -b` clean, `biome check` clean. Frontend `pnpm test --run`: **1465/1465 tests
  green** (104 files) — one `ChatLayoutPoll.test.tsx` failure appeared under one
  full-suite run (`poll.options[0].voters` assertion) but passed both standalone and
  on a second full-suite rerun; pre-existing test-isolation flake under parallel
  load, unrelated to this change (poll code untouched), not investigated further this
  cycle. Test counts: `encrypted-db.test.ts` net +3 (2 new delta-merge/no-op tests
  replacing the 2 old full-replace tests, +1 net), `usePersistentMessages.test.ts` net
  +1 (split one full-map test into an add+merge test and a separate remove test),
  `ChatLayout.test.tsx` unchanged count (existing reaction-persistence tests updated
  to assert the new delta call signature instead of the old full-map argument).
- **Next cycle candidates:** F1/F7 above (peer-driven lock-hold amplification — worth
  a look if reaction volume ever becomes a real concern, currently no inbound
  rate limit on reactions specifically); F3 (Playwright test for real-browser
  `Dexie.waitFor` transaction liveness); F4 (the pre-existing `putMessage`
  full-row-overwrite gap — same class as previously-deferred `readByJson` concern,
  now explicitly documented rather than newly discovered); PQ hybrid Phase A (still
  blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade
  (gated on ADR-0003 Phase B 95%-session threshold); opaque-ke live-migration
  login-round-trip regression test gap (cycle 318/319, no prod users yet, low
  urgency).

## Previous state (2026-08-23, cycle 343 — FEATURE: persist sender's own copy of forwarded text messages, commit 3fab286)

- CI green (`gh run list --limit 3`), `gh issue list --state open` empty, `git status` clean at
  cycle start. Cycle-340's "next cycle candidates" note claiming "pins/mentions remain
  session-only" was **stale/wrong** — verified via a fresh Explore-agent survey that both
  `GroupRow.pinnedMessageId` (v9) and `GroupRow.mentionCount` (v13) are already fully persisted
  and wired; corrected here so it isn't repeated. Continued searching (Draft — already persisted
  v17; pin/mention — already persisted) and found via direct grep of `persistOutgoing` call
  sites: **only 2 exist in the whole file** (plain `sendMessage`, and cycle-342's `fireScheduled`)
  — `sendForwardToOne` (text-forward path, used by both the single-target and multi-select
  forward-modal flows) never called it at all.
- **What it does:** forwarding a text message to another chat appended an optimistic "me" bubble
  and sent it over MLS, but never persisted the sender's own copy to Dexie — reload silently
  dropped it from the sender's own history (recipient's `persistIncoming` was already correct and
  unaffected). Fixed by chaining `persistOutgoing(envelopeId, mlsGroupId, text,
  uint8ToBase64(ciphertext))` after `sendMessageApi` resolves inside `sendForwardToOne`
  (ChatLayout.tsx). Uses the existing `persistOutgoing` helper — no schema change needed.
  `persistOutgoing` writes to Dexie keyed by its own `groupId` param, not the hook's bound active
  group, so writing under the *target* chat's group (which may differ from the active chat) is
  Dexie-safe — same precedent already documented on cycle-342's `fireScheduled` call.
- **Found and deliberately did NOT fix in this cycle (too large, separate gap):** grepped the
  whole `MessageRow` schema and found **no media field exists at all** — `persistIncoming` only
  ever stores `msg.text` (which is the literal string `"[image]"` for a media message, per
  `IncomingMessage`'s own doc comment), never `msg.media` (blobId/key/iv/thumbnail). This means
  **every media message (photo/video/voice note), sent OR received, has zero Dexie persistence
  for redisplay after reload** — a pre-existing, much bigger architectural gap than any single
  persistence cycle has tackled so far (would need a new encrypted `mediaJson` field, threading
  through `useMediaSend`/`encryptAndSendMedia`/`persistIncoming`, chunked-video handling,
  thumbnail bytes, rehydration UI). Left `sendForwardToSelected`'s media-forward path (which
  calls `encryptAndSendMedia` directly, no persistence hook at all) untouched to avoid an
  inconsistent half-fix — documented inline as a known limitation. **Flagging as the standing
  large-scope candidate for a future cycle or a dedicated multi-cycle push**, not attempted here.
- **crypto-reviewer: YELLOW, both findings fixed in-cycle:**
  1. **Fixed (doc-only):** added a RETENTION NOTE doc comment on `sendForwardToOne` — forwards
     have never carried the target chat's `disappearingTtl` on the wire (pre-existing,
     `sendMessageApi` called with `ttlSeconds: undefined` and a raw non-JSON payload, unlike
     `sendMessage`'s `{type:"text",text,ttl}` shape) — this diff widens that gap from "peer keeps
     it forever" to "sender AND peer keep it forever" (since nothing was persisted pre-diff, there
     was nothing to leave un-purged). Documented as an accepted widening of a known gap, not a new
     class; not fixed (would need the JSON payload shape, bigger scope than this persistence fix).
  2. **Fixed (test):** the reviewer mutation-tested the positive test and found it didn't pin the
     actual ciphertext — a bug that persisted the *source* message's ciphertext under the *target*
     group would have still passed. Strengthened: asserts `row.ciphertextB64 === "3q0="` (the
     mocked `mlsEncrypt`'s fixed `[0xde,0xad]` output) and `!== "Zg=="` (source ciphertext), plus
     `expiresAt`/`replyToJson` both `undefined`.
  3. Non-blocking note left as-is (informational, matches existing `sendMessage` error-handling
     shape): a synchronous throw inside `persistOutgoing` would be swallowed by the outer
     `.catch(() => {})` — acceptable, `putMessage` rejections already route through the opaque
     `writeErrorCount` counter.
- 2 new tests in `ChatLayoutForwarding.test.tsx`: positive (forwards a text message, asserts the
  Dexie row lands under the target group with the correct ciphertext/plaintext/sender, no
  expiresAt/replyTo) and negative (send rejects → `db.messages` for the target group stays empty,
  mutation-tested to confirm it's not vacuous). **Frontend: 1462/1462 tests green** (was 1460,
  104 files unchanged). `tsc -b` clean, `biome check` clean (2 touched files). Production build:
  initial route 164.81 kB gzip / WASM 642.87 kB gzip (both under prd.md §7 budgets).
- Not architectural, no new server-visible metadata (server-visible bytes are byte-identical to
  pre-diff — this only adds a local-only Dexie write) — `threat-model-checker` not required.
  Backend untouched (confirmed via `git diff --name-only`) — `security-auditor` not required
  either (crypto-reviewer's scope covers this diff fully, same class as cycle 342's scheduled-
  send fix).
- `gh issue list --state open` — empty at cycle start. Target dir hygiene: not checked (FEATURE
  mode, backend untouched).
- **Next cycle candidates:** the media-message-has-zero-Dexie-persistence gap surfaced this cycle
  (large, would need new schema + threading through both send and receive paths — worth scoping
  as its own multi-part effort rather than a single cycle); media forwards still unpersisted
  (same root cause, fixed together with the above); the general cross-tab cloned-MLS-sender-
  ratchet property (flagged cycle 342, still not scoped for a single cycle); PQ hybrid Phase A
  (still blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on
  ADR-0003 Phase B 95%-session threshold).

## Previous state (2026-08-23, cycle 342 — FEATURE: scheduled messages now actually send over MLS when they fire, commit 636996c)

- Cycle 341 apparently ran but never committed (`git status` at cycle start showed a complete,
  uncommitted working-tree diff across ChatLayout.tsx/encrypted-db.ts/usePersistentMessages.ts +
  tests, plus a stray debug scratch file `ZZDebugClaim.test.ts` with console.logs — same
  "cycle silently fails to commit" pattern as cycles 324/326/330/332). Per CLAUDE.md's
  investigate-before-discarding guidance, validated and landed it (like cycle 332) rather than
  redoing from scratch: deleted the scratch debug file, then built on the real diff.
- **What it does:** closes the long-standing gap (flagged since cycles 339/340) that a fired
  scheduled ("send later") message never actually transmitted over MLS — it only cleared the
  local `scheduledFor` flag. `EncryptedPowehiDb.claimScheduledFire(id)` (encrypted-db.ts) reads
  and deletes a scheduled row inside ONE Dexie `readwrite` transaction, gated on `scheduledFor`
  still being set — IndexedDB serializes same-store rw transactions, so this is an atomic claim:
  at most one caller (this tab's overlapping sweep ticks, or another same-origin tab) ever gets
  a defined row back. `ChatLayout.tsx`'s `fireScheduled` sweep (10s interval) now: claims →
  `mlsEncrypt` → `sendMessageApi` → `persistOutgoing`, the same pipeline `sendMessage` itself
  uses, instead of the old "just flip scheduledFor in memory" no-op.
- **crypto-reviewer: 2 rounds, both required since this diff calls `mlsEncrypt` directly.**
  Round 1 verdict **needs-rework**, 6 required changes (the atomic-claim pattern itself was
  GREEN from round 1 — it does correctly prevent double-encrypting the same scheduled message):
  1. **Fixed:** added a fail-closed `if (claimed.groupId !== item.groupId) continue;` before
     encrypting — nothing previously verified the claimed row's groupId matched the chat it was
     scanned from before encrypting under that chat's key material.
  2. **Fixed:** an already-expired-by-fire-time message (elapsed `expiresAt`) now `continue`s
     (drops, matching purge semantics) instead of `Math.max(1, ...)`-clamping to a 1-second TTL
     and sending already-past-retention content.
  3. **Fixed:** the empty `catch` after a failed send previously justified "no retry" with an
     incorrect claim ("would reopen a narrower version of the same TOCTOU race") — corrected to
     state the true reason (RFC 9420 §6.3: re-encrypting the already-claimed plaintext would be
     safe, since each `mlsEncrypt` call advances the sender ratchet; simply not implemented,
     matching `sendMessage`'s own no-retry-UI scope, not a safety requirement).
  4. **Fixed (doc-only):** the claim's doc comments (encrypted-db.ts + ChatLayout.tsx +
     usePersistentMessages.ts) overclaimed that this closes the general cross-tab
     cloned-MLS-sender-ratchet problem and called a generation collision "catastrophic" AEAD
     reuse. Corrected: the claim only closes *this-message* double-firing (scheduled rows are
     local-only pre-fire, so there's no separate device to race); the general cloned-ratchet
     property is pre-existing across every send path in this app (typing/presence/sendMessage),
     unresolved by this change; cited RFC 9420 §6.3.2's per-message `reuse_guard` (a bare
     generation collision isn't automatically nonce reuse).
  5. **Fixed (doc-only):** the TTL-bucket-rounding comment (server-visible retention arg snapped
     UP to nearest `TTL_OPTIONS` member instead of sent exactly) overclaimed it eliminates the
     "this was a scheduled send" fingerprint — corrected to "narrows, does not eliminate" and
     enumerated the residual peer-visible signal (exact `ttl` inside the MLS-encrypted payload,
     no preceding typing/presence traffic, no MLS `padding_size` on this path) as an accepted,
     documented gap.
  6. **Fixed:** `ChatLayoutScheduleSend.test.tsx`'s cross-tab-cancel-race test asserted
     `MOCK_WORKER.mlsEncrypt.mock.calls` never contained the cancelled text — but the real
     `fireScheduled` zeroes its plaintext buffer (`plaintext.fill(0)`) in a `finally` right after
     `mlsEncrypt` resolves, so that assertion was reading an already-zeroed buffer and would
     pass vacuously even if the guard it was testing regressed. Fixed: the mock now pushes a
     manual `new Uint8Array(plaintext)` copy into a module-level `capturedPlaintexts` array
     before returning; the test asserts against that copy instead.
  Round 2 (fresh agent, verifying the fix diff): **GREEN**, all 6 confirmed fixed, plus 2 small
  non-blocking residuals flagged and fixed in the same cycle anyway (cheap): (a) the sweep
  processes claimed items serially, each a full encrypt+network round trip, so reusing the
  sweep's single `now` for later items in the same tick could be stale — now re-reads
  `Date.now()` immediately after each claim; (b) `Math.round` on a sub-second remaining TTL could
  floor to `0` (falsy), silently downgrading a near-expiry disappearing message to a permanent
  one — restored a `Math.max(1, ...)` floor, safe now that the already-expired case is a
  `continue` guard *before* this floor (round 1's fix #2), not the same clamp that caused it.
- Not architectural, no new server-visible metadata (same TTL-rounding/envelope shape every
  other disappearing send already uses) — `threat-model-checker` not required. Backend untouched
  (confirmed via `git diff --name-only`) — `security-auditor` not required either (crypto-
  reviewer's scope covers this diff fully, it's the crypto-adjacent MLS-send path).
- Root-caused and fixed a real test bug hit while validating the dropped cycle's tests: 3 of the
  new "firing" tests failed under `vi.advanceTimersByTime` (sync). Root cause: `claimScheduledFire`
  does a `get()` then `delete()` inside one Dexie transaction; fake-indexeddb settles each
  IDBRequest via a (now-faked, since `vi.useFakeTimers()` globally replaces `setTimeout`) 0ms
  timer — the sync advance doesn't drain newly-scheduled timers between the transaction's two
  dependent awaits, so Dexie sees the transaction go idle after the `get()` and the `delete()`
  then fails, silently no-opping the claim (self-healing but permanently missing the test's
  short real-timer `waitFor` window). Fixed: switched the 4 affected `vi.advanceTimersByTime`
  calls in `ChatLayoutScheduleSend.test.tsx` to `await vi.advanceTimersByTimeAsync(...)`, which
  drains microtasks/newly-scheduled timers between ticks and keeps the transaction alive across
  both awaits. Confirmed via debug instrumentation (removed before commit) that this was purely
  a fake-timers/fake-indexeddb test-environment interaction, not a real-browser bug.
- **Frontend: 1460/1460 tests green** (was 1451 pre-cycle-341's-drop; +9 net: 6 in
  `usePersistentMessages.test.ts` for `claimScheduledFire`, 3 new ChatLayout-level firing/
  cross-tab-cancel tests). `tsc -b` clean, `biome check` clean (5 touched files). Production
  build: initial route 164.78 kB gzip / WASM 642.87 kB gzip (both under prd.md §7 budgets).
- `gh issue list --state open` — empty at cycle start. Target dir hygiene: not checked (FEATURE
  mode, backend untouched).
- **Next cycle candidates:** the crypto-reviewer's 2 residual notes are now both fixed in-cycle
  (see above, nothing deferred); the general cross-tab cloned-MLS-sender-ratchet property
  (every open tab independently imports the group's sender ratchet; this cycle explicitly did
  NOT resolve this, only documented it as pre-existing across every send path) is a bigger,
  separate architectural question — not scoped for a single cycle, would need its own design
  pass (e.g. leader-election among tabs, or a server-side single-sender lock) if ever prioritized;
  PQ hybrid Phase A (still blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF
  upgrade (gated on ADR-0003 Phase B 95%-session threshold); the `.claude/memory/project-
  context.md` file-size note (archived at cycle 340, currently ~1370 lines / 108KB — fine for
  now, re-check in a handful of cycles if it grows back toward the 256KB Read cap).

## Previous state (2026-08-23, cycle 340 — STABILIZATION: project-context.md re-archive + full security/test sweep)

- CI green (`gh run list --limit 3`), `gh issue list --state open` empty at cycle start.
- **Memory hygiene (the actual fix this cycle):** `project-context.md` had grown back to 3782
  lines / 291KB — over the Read tool's 256KB cap, so it could no longer be read whole (hit the
  cap on the very first read attempt this cycle). Flagged as overdue for 5+ cycles running
  (cycle 320's own archive-cutoff pass was itself long past the inline window). Archived cycles
  279–319's "Previous state" entries, plus a stray unarchived legacy "Cycle log (recent)" section
  (non-chronological cycles 215–262 and a stray 315 entry that cycle 320's cleanup missed) to
  `.claude/memory/archive/project-context-cycles-279-319-and-cyclelog.md` (189KB). Live file is
  now 108KB / ~1370 lines, last 18 cycles kept inline. Verified the archive/live boundary is
  clean (no dropped or duplicated content) before replacing the live file.
- **Full sweep, all green, nothing to fix:**
  - `cargo audit`: 652 crates scanned, 0 advisories.
  - `cargo deny check`: advisories ok, bans ok, licenses ok, sources ok.
  - `cargo test --workspace` (nextest not installed in this shell, used the documented fallback):
    all green across all 19 crates (0 failures).
  - `cargo clippy --workspace --all-targets -- -D warnings`: clean.
  - Frontend: `pnpm test --run` 1451/1451 tests green (104 files), `tsc -b` clean, `biome check`
    clean (170 files).
  - Target dir hygiene: 11G (well under the 20G threshold), 0-byte `.rmeta` prune ran, no further
    action needed.
- No crypto/architectural/backend-handler changes this cycle → no crypto-reviewer/threat-model-
  checker/security-auditor pass required (memory-file-only change, confirmed via `git status`).
- **Next cycle candidates:** the scheduled-messages-don't-actually-send-over-MLS gap (noted since
  cycle 339, still open, larger feature); PQ hybrid Phase A (still blocked on openmls stable
  `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B 95%-session
  threshold); pins/mentions remain session-only (no MessageRow/GroupRow fields exist for them yet).

## Archived history (cycles 20-277, 279-339, and legacy cycle-log entries)

> Cycles 20-277 were moved to `.claude/memory/archive/project-context-cycles-20-277.md` in
> cycle 320 (2026-07-19 STABILIZATION). Cycles 279-319, plus the old non-chronological
> "Cycle log (recent)" section (cycles 215-262 and a stray 315 entry that cycle 320's pass
> missed), were moved to `.claude/memory/archive/project-context-cycles-279-319-and-cyclelog.md`
> in cycle 340 (2026-08-23 STABILIZATION). Cycles 320-339 were moved to
> `.claude/memory/archive/project-context-cycles-320-339.md` in cycle 360 (2026-08-25
> STABILIZATION) — this file had grown back to 2385 lines / 192KB, approaching the
> Read-tool 256KB cap. Only the last ~20 cycles are kept inline above. Read the archive
> files directly (with offset/limit) for older-cycle detail.

## Phase checklist (prd.md §15.4; per-phase DoD in docs/phases/phase-N/STATUS.md)

### Phase 1 — Foundation & DevOps Skeleton  ← ACTIVE
- [x] Cargo workspace + hexagonal crate skeleton (domain → ports → application → adapters → bin), prd.md §6.1 — commit 940a065
- [x] powehi-domain (zero external deps) + powehi-port-inbound/outbound trait stubs — commit 940a065
- [x] React 19 + Vite 6 scaffold under `/app` — commit 312864d (pnpm workspace, Tailwind v4, Vitest, Biome, design tokens)
- [x] WASM build pipeline (empty `powehi-crypto-wasm` compiles to wasm32-unknown-unknown) — commit f498ae1
- [x] CI: GitHub Actions (fmt, clippy, nextest, biome) — commit 35ac5b9
- [x] Terraform base (Hetzner k3s) skeleton — commit d87891f (modules/hetzner-k3s, envs/{dev,prod-eu,cloudflare}, infra-test manual pass)
- [x] `cargo nextest` 100% on skeleton; hexagonal dependency direction holds — cycle 8 (verified: 21/21 domain tests pass; domain←ports←application; adapters→ports only, NOT application)

### Phase 2 — Crypto Core MVP  ← COMPLETE (cycle 11)
- [x] `powehi-crypto-wasm` w/ openmls; OPAQUE register/login; MLS group round-trip; Comlink worker; forward-secrecy invariant test; crypto-reviewer pass
  - [x] OPAQUE registration/login (opaque-ke 3.0, draft-irtf-cfrg-opaque-16): registration_start/finish + login_start/finish/full; 2 tests green — cycle 8
  - [x] MLS group create/encrypt/decrypt (openmls 0.8.1 + openmls_rust_crypto): roundtrip + forward-secrecy invariant; 2 tests green — cycle 8
  - [x] Crypto-reviewer: YELLOW (no RED). Warnings: opaque-ke 3.x vs rule 4.x (follow-up needed), max_past_epochs(0) now explicit, identity binding documented — cycle 8
  - [x] Comlink worker / wasm-bindgen exports — cycle 10 (commit b5c58b0): wasm_exports.rs + crypto.worker.ts; zeroize on export_key; Biome fixed; 30/30 tests green; crypto-reviewer YELLOW (waiver for opaque-ke 3.x recorded in crypto-libraries-pinned.md)
  - [x] WASM compilation test (wasm-pack --target web) — cycle 11: wasm-pack 0.15 success, 1.5MB binary, CI job added to ci-frontend.yml

### Phase 3 — Backend Services & API  ← ACTIVE
- [x] REST API axum adapter: AppState, auth/messaging/key-package routes, AuthenticatedDevice extractor, ApiError, 512KB body limit, 10 tests — cycle 12 (commit a31ff1a); security-auditor PASS
- [x] Composition root: wire Postgres + Redis outbound adapters into bin/powehi-server; DI wiring for AppState — cycle 14 (commit c46eec3); security-auditor GREEN
- [x] WS hub: real-time push via WebSocket (envelope delivery notifications) — cycle 16 (commit 9c9d886); security-auditor PASS
- [x] OPAQUE auth adapter: real opaque-ke server-side register/login in powehi-opaque — cycle 18 (commit 7c2a429)
- [x] Rate limiting (tower_governor 0.4 + governor 0.6, TrustedProxyKeyExtractor) — cycle 19 (commit 0a738e6)
- [x] Media (R2 upload/download via powehi-r2 adapter) — cycle 21 (commit 2527650)

### Phase 4 — Frontend & Integration
- [x] Login/Chat UI; Dexie encrypted storage; crypto worker hook — cycle 23 (commit 786cf6f)
- [x] Service Worker push; Playwright E2E; bundle budget (<200KB init, <800KB WASM) — cycle 24 (commit 600c2b3)
- [x] Safety Numbers UI — prd.md §5.6; WASM SHA-512 derivation; Dexie v2 verifiedContacts; SafetyNumbers component; crypto-reviewer PASS; security-auditor GREEN — cycle 43 (commit 68ce879)
- [x] Dexie AES-GCM-256 encryption layer — `EncryptedPowehiDb` + `encryption.ts`; key in crypto worker; schema v3 (no exportKeyB64); crypto-reviewer + security-auditor GREEN — cycle 47 (commit 380ef49)
- [x] Region-Aware Client — `GET /v1/region/detect` + Zustand region store + sidebar data residency badge; prd.md §7.6; security-auditor PASS — cycle 52 (commit b5513b1)
- UI MUST follow the design system — invoke `/powehi-design` or read `DESIGN.md` first. Brand non-negotiables (dark-first, cream text, dual-light orange=action / photon-blue=encryption, lock always photon-blue) are hard rules. Map `colors_and_type.css` → Tailwind v4 OKLCH.

### Phase 5 — Hardening
- [x] Observability: Prometheus metrics on internal admin port (127.0.0.1:9090); zero-knowledge counters; security-auditor PASS — cycle 28
- [x] SLSA L3 reproducible builds; cosign + Rekor; threat-model-checker pass; load test (10k concurrent WS); PQ migration doc — cycle 29 (commit 75e6c6f)
- [x] CSP + Trusted Types + SRI 100%: security_headers.rs axum middleware; CF Worker addSecurityHeaders; Cloudflare Pages _headers CSP (worker-src blob:, wasm-unsafe-eval, TT, COOP); Vite SRI plugin with build-fail guard — cycle 53 (commit 07e260a)

### Phase 6 — Global Infrastructure
- [x] gRPC mesh + mTLS: powehi-proto (protox 0.7), RegionGrpcServer, RegionGrpcRouter, TlsConfig, CircuitBreaker, security hardening — cycle 32 (commit 563ae8e)
- [x] AP-Seoul Tier 1 Terraform + Helm chart + synthetic checks + infra-test gate — cycle 33 (commit d92e4aa)
- [x] Cloudflare Edge Worker smart routing — TypeScript Worker + PIPA guard + HEALTH_KV failover + Terraform KV/route — cycle 34 (commit 5b7d855)
- [x] KeyPackage cross-region replication integrity — ConsumeKeyPackage RPC implemented, CAS double-consume prevention, 5 integrity tests — cycle 34 (commit 5b7d855)
- [x] Cross-region p99 <200ms live measurement + gRPC forwarding synthetic — `cross-region-p99.js` extended: gRPC HealthCheck p99 threshold; ZK guard; plaintext guard; try/finally — cycle 37 (commit 9efedcb)
- [x] Data residency verification — prd.md §4A.6: 3 compile-time gRPC PII-exclusion tests + `data-residency-check.sh` 4-layer static audit; security-auditor PASS — cycle 54 (commit e0cc130)

## Notes for the autonomous dev
- Implement ONE checklist item per cycle. Flip `[ ]` → `[x]` here when done.
- Delegate domain work via Task to the project's subagents: crypto-lead, backend-lead,
  frontend-lead, infra-lead; reviewers crypto-reviewer / security-auditor / threat-model-checker.
- Use skills: add-rust-crate, add-mls-test, new-api-endpoint, verify-reproducible-build,
  threat-model-update, infra-test.
- Review is part of writing: implement → run the relevant review agent → fix → commit.

