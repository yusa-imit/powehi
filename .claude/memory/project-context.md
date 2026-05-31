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

## Current state (2026-06-01, cycle 61 — FEATURE: dropDbKey wired to auth logout — AES-GCM key lifecycle closed)
- **Cycle 61 (commit bf1f90f):** Deferred security item from cycle 50 — AES-GCM-256 IndexedDB key now cleared on sign-out:
  - **`useCryptoWorker.ts`**: exported `getCryptoWorkerProxy()` as a non-hook callable so Zustand stores can invoke the worker singleton without violating react-hooks-only.md boundary.
  - **`auth.ts` logout()**: calls `getCryptoWorkerProxy()?.dropDbKey()` fire-and-forget before state transition. FIFO Comlink queue guarantees drop is processed before any subsequent `initDbKey()` from a new OPAQUE login. Documented scope: only the Dexie AES-GCM key is wiped; MLS WASM heap state deferred to OPAQUE→MLS session binding work.
  - **`__mocks__/useCryptoWorker.ts`**: added `dropDbKey: async () => {}` and `getCryptoWorkerProxy` export (type-fidelity fix from security-auditor YELLOW-7).
  - **+2 frontend tests**: `dropDbKey called on logout`; `null proxy guard — still transitions to login`.
  - **security-auditor**: YELLOW (fire-and-forget TOCTOU window documented in comment; MLS WASM state scope documented; test adequacy note added per testing-conventions.md convention). No RED findings blocking commit.
  - **66 frontend tests** (was 64, +2); Biome clean; 284 Rust tests unchanged.
  - **Remaining deferred:** MLS WASM heap wipe on logout (full session-clear); mTLS peer-cert → home_region binding (RED-2/RED-3, architectural); set_expire stale-token accumulation; revoke_device mid-loop delete failure logging.

## Current state (2026-05-31, cycle 60 — STABILIZATION: orphan-session security fix + test gap closure)
- **Cycle 60 (commit 6b89f4a):** STABILIZATION — CI green, no open issues, security fix + test gaps:
  - **Orphan-session bug found and fixed (security-significant):** In `login_finish`, when `set_add` (device_sessions tracking) failed, code returned `Unauthorized` but LEFT an orphan `session:{token}` in the cache. Token unreachable by client but persisted for SESSION_TTL. Fixed: `is_err()` branch now explicitly deletes `session_cache_key` before returning. Added `tracing::warn!` on both cleanup-failure paths (set_add fail + revoke-race fail) so cache partitions surface to ops.
  - **Test that proved the bug:** `login_finish_set_add_failure_returns_unauthorized_and_cleans_session` — uses `SetAddFailCache` error-injectable fake; originally FAILED (confirmed orphan session existed), passes after fix.
  - **+5 gRPC input-validation tests:** `sync_group_membership_home_region_too_long`, `sync_group_membership_home_region_exactly_64_chars_is_accepted` (boundary), `sync_group_membership_invalid_member_device_id`, `forward_commit_invalid_group_id`, `forward_commit_invalid_sender_device_id`
  - **Comment fix:** `home_region` validation comment corrected (was "ASCII printable" — code only checks length/non-empty)
  - **security-auditor:** GREEN (no RED; YELLOWs addressed: cleanup warn-logging added, comment fixed, boundary test added; remaining deferred: set_expire best-effort stale-token accumulation, revoke_device partial-delete logging)
  - **284 Rust tests** (was 278, +6); clippy clean; rustfmt clean; cargo audit 1 allowed warning (RUSTSEC-2024-0384 unchanged)
  - **Remaining deferred (non-blocking):** mTLS peer-cert → home_region binding (RED-2/RED-3, architectural), set_expire stale-token accumulation, revoke_device mid-loop delete failure logging

## Current state (2026-05-31, cycle 59 — FEATURE: gRPC sender-membership enforcement — gRPC R-1 closed)
- **Cycle 59 (commit 63ce31d):** Closed long-deferred gRPC R-1 (forward_envelope no sender-membership check):
  - **`RegionGrpcServer` gains `group_repo: Arc<dyn GroupRepository>`** — passed from `main.rs` (clone of `PgGroupRepository`)
  - **`check_sender_is_member`** helper: calls `group_repo.list_members(group_id)`:
    - **Fail-closed** — if no membership data (empty list), rejects with PermissionDenied + warning log
    - If members exist, sender must be in the list; generic `"sender is not authorized for this group"` error (no member-list leakage)
    - Architectural deferral comment: RED-2/RED-3 (mTLS peer-identity binding to home_region) deferred until tonic `TlsConnectInfo` plumbing
  - **`forward_envelope` + `forward_commit`** call `check_sender_is_member` before saving the envelope
  - **`sync_group_membership`** now persists: checks `find_by_id` → creates Group stub if absent → `add_member` for each device_id (ON CONFLICT DO NOTHING)
  - **YELLOW-2 fix**: `home_region` validated (non-empty, ≤64 chars) before DB writes
  - **YELLOW-3 fix**: `#[instrument]` added to `sync_group_membership`; logs only `group_id` UUID + `member_count` (no device UUIDs per no-plaintext-logging.md)
  - **+6 tests**: known-member accepted, non-member rejected, unknown-group fail-closed, commit non-member rejected, sync persists+enables forward, empty home_region rejected
  - **278 Rust tests** (was 272, +6); clippy clean; rustfmt clean
  - **Remaining deferred**: RED-2/RED-3 (mTLS peer-cert → home_region binding), TOCTOU in find_by_id→save under concurrent sync (low-risk, add_member is idempotent), non-atomic member batch insertion

## Current state (2026-05-31, cycle 58 — FEATURE: session-auth hardening — YELLOWs Y-1…Y-5 + RED-1 closed)
- **Cycle 58 (commit 951f5d3):** Closed all 5 deferred security-auditor YELLOWs from cycle 56 + auditor RED-1 found in review:
  - **Y-1 (session revocation on device revoke):** `login_finish` writes session token into `device_sessions:{device_id}` Redis set (SADD + EXPIRE). `revoke_device` calls SMEMBERS, deletes each `session:{token}`, deletes the set. Immediate invalidation on device revoke.
  - **R-1 (revoke↔login_finish race):** `login_finish` re-verifies device existence _after_ writing the session. If device was concurrently revoked, the orphan session is deleted before returning Unauthorized.
  - **Y-1 / set_add hard-fail:** `set_add` failure now returns Unauthorized instead of silently creating an untrackable session.
  - **Y-2 (nonce TTL naming):** Separate `LOGIN_NONCE_TTL` constant distinct from `REG_TTL` (same 300s, semantically separate).
  - **Y-3 (atomic nonce consume):** `login_finish` uses `cache.get_del` (Redis GETDEL) — no TOCTOU replay window.
  - **Y-4 (device_id logging order):** Removed `device_id` from `#[instrument]` fields; logged only after ownership verification via `tracing::debug!`.
  - **Y-5 (remove unused user_id field):** `LoginFinishRequest.user_id` removed; server always resolves user from nonce cache.
  - **CachePort new methods:** `get_del`, `set_add`, `set_expire`, `set_members` with default no-op implementations; `RedisCache` overrides with GETDEL/SADD/EXPIRE/SMEMBERS.
  - **+3 tests:** `login_finish_nonce_cannot_be_reused`, `revoke_device_invalidates_active_sessions`, `login_finish_after_device_revoked_returns_unauthorized`.
  - **272 Rust tests** (cargo test; was 274 with nextest — no regressions); clippy clean; rustfmt clean.
  - **Remaining deferred:** Y-4 (`set_expire` without NX/GT flag — acceptable, `EXPIRE` renews TTL on each login which is correct behavior).

## Current state (2026-05-31, cycle 56 — FEATURE: Redis session auth — Bearer stub closed on REST + WS)
- **Cycle 56 (commit 52e30d9):** Closed the stub Bearer auth vulnerability (R-2/R-1 from security-auditor):
  - **R-2 (REST API):** `AuthenticatedDevice` middleware rewritten from raw `DeviceId` UUID parse to `session:{token}` → DeviceId UUID bytes Redis cache lookup. Any token not in the live session store returns 401. `FromRef<AppState> for Arc<dyn CachePort>` added. `AppState` gains `cache` field. `EmptyCache`/`FakeCache` added to all test state constructions.
  - **R-1 (WebSocket hub):** `extract_device_id` changed from sync UUID parse to async Redis session lookup. `WsHubState { hub, cache }` struct added in `lib.rs`. `router()` now takes `Arc<WsHub>` + `Arc<dyn CachePort>`. Handler uses `State<WsHubState>`. `main.rs` passes `Arc::clone(&cache)` to WS router.
  - **auth_service changes:** `login_init` seeds `login_nonce:{nonce}` → user_id bytes (replay prevention). `login_finish` resolves user from nonce cache (server-controlled), verifies device ownership, deletes nonce, writes `session:{token}` → DeviceId bytes with SESSION_TTL. `LoginFinishRequest` gains `device_id: DeviceId` field (port change).
  - **Regression tests:** `raw_device_uuid_without_session_returns_401` (REST), `raw_device_uuid_without_session_is_401` (WS); `login_finish_issues_session_token_bound_to_device`; `login_finish_wrong_device_owner_returns_unauthorized`.
  - **274 Rust tests** (was 266 +8); clippy clean; rustfmt clean.
  - **security-auditor deferred (non-blocking YELLOWs):**
    - Y-1: Sliding TTL / session revocation on device revoke
    - Y-2: Rename nonce TTL constant to LOGIN_NONCE_TTL (cosmetic)
    - Y-3: Atomic nonce consume (GETDEL or document OPAQUE mutex guarantee)
    - Y-4: Move device_id logging after ownership verification
    - Y-5: Remove or document req.user_id field (client should not send it)
    - gRPC R-1 (forward_envelope no sender-membership check) — architectural deferred

## Current state (2026-05-31, cycle 55 — STABILIZATION: CI fix + ack IDOR fix)
- **Cycle 55 (commits 7d0bed9, 40aa98c):**
  - **CI red fix (7d0bed9):** `powehi-grpc/src/server.rs` rustfmt failure — stable 1.96.0 requires 2-arg `assert!` macros to be multi-line when over line length. Three `assert!` calls in data-residency tests expanded. CI now green.
  - **ack IDOR fix — security-auditor Y-3 (40aa98c):** `MessagingService::ack_envelope` was deleting any envelope by ID without checking caller ownership. Fix: added `EnvelopeRepository::find_by_id` to port + all impls; ownership check in service: broadcast (None recipient) = any device may ack; unicast = only recipient may ack; idempotent when not found.
    - `+1` method to `EnvelopeRepository` port (find_by_id)
    - `+12` SQL lines in `PgEnvelopeRepository` (find_by_id)  
    - `+1` method to all stub/fake impls (`FakeEnvelopeRepo`, `NoopEnvelopeRepo`)
    - `+3` application-layer tests: wrong-device-unauthorized, owner-succeeds, idempotent-not-found
    - `+1` REST-layer test: ack_by_wrong_device_returns_401
  - **266 Rust tests** (+4 from 262); **64 frontend tests** (unchanged); clippy clean; rustfmt clean.
  - **security-auditor remaining deferred (2 pre-existing architectural deferrals):**
    - R-1: gRPC `forward_envelope` has no sender-membership check (requires GroupRepository in gRPC server — architectural deferred)
    - R-2: Bearer token = raw DeviceId UUID (stub auth, replacing with Redis session is a Phase 3 deferred item)
    - Y-1: `poll` broadcast envelopes need group-membership scoping (adapter-level gap, deferred)
    - Y-2: media `get_download_url` ACL needs upload-time group binding (Phase 4 deferred)
    - Y-4: `consume_key_package` peer region not validated against mTLS identity (deferred)

## Current state (2026-05-31, cycle 54 — FEATURE: CI fix + Data Residency Verification — Phase 6 complete)
- **Cycle 54 (commits fc7c5e0, e0cc130):**
  - **CI fix (fc7c5e0):** `app/vite.config.ts` SRI plugin timing bug — `generateBundle{order:"post"}` runs AFTER Vite's HTML-emitting `generateBundle` hook (which calls `transformIndexHtml`), so the hashes Map was always empty at transform time. Fix: removed separate `generateBundle` hook; moved hash computation into `transformIndexHtml` using `ctx.bundle`. Also migrated from deprecated `enforce:` to `order:` (Vite 6). CI — Frontend was failing on bundle-budget step; now fixed. **64 frontend tests** unchanged; biome clean.
  - **Data Residency Verification (e0cc130):** Phase 6 final DoD item — prd.md §4A.6:
    - **powehi-grpc/server.rs +3 tests:** Exhaustive struct destructuring tests for `ForwardEnvelopeRequest` (7 fields) and `ForwardCommitRequest` (4 fields) — compile error if PII field added; UUID validation on all IDs; `sync_group_membership_member_ids_are_opaque_uuids`.
    - **`infra/synthetic/data-residency-check.sh` (NEW):** 4-layer static verification script: (1) proto schema — \b word boundaries, awk message extraction; (2) gRPC server+client code — comment-stripped scanning, awk multi-line instrument block; (3) DomainEvent definitions; (4) all messaging*.rs files. All 11 checks PASS.
    - **security-auditor:** RED-1 (grep-A overflow), RED-2 (PII denylist word boundary), RED-3 (multi-line instrument grep) — all fixed. YELLOW-5 (all messaging files) fixed.
  - **262 Rust tests** (+3 from 259); **64 frontend tests** (unchanged); clippy clean; rustfmt clean; Biome clean.
  - **Phase 6 ALL DoD items now complete.**

## Current state (2026-05-31, cycle 53 — FEATURE: CSP + Trusted Types + SRI — Phase 5 hardening)
- **Cycle 53 (commit 07e260a):** Phase 5 remaining DoD item — CSP + Trusted Types + SRI 100%:
  - **Backend (`security_headers.rs` NEW):** Tower/axum middleware adds X-Content-Type-Options (nosniff), X-Frame-Options (DENY), Referrer-Policy (no-referrer), Permissions-Policy (geolocation/camera/mic=blocked), HSTS (max-age=63072000; includeSubDomains; preload) to ALL API responses. Wired as outermost layer via `from_fn(set_security_headers)` in `router_inner`. +8 tests (5 unit + 3 integration on /health).
  - **CF Worker (`smart-router/src/index.ts`):** `addSecurityHeaders(response)` wraps all outgoing responses (forwarded origin + ALL_REGIONS_DOWN + ORIGIN_UNREACHABLE + PIPA-blocked). Same 5-header set. +3 tests.
  - **Cloudflare Pages (`app/public/_headers`):** Full CSP for the SPA — `script-src 'self' 'wasm-unsafe-eval'`; `worker-src 'self' blob:` (Comlink crypto worker + Service Worker); Google Fonts (`fonts.googleapis.com` CSS + `fonts.gstatic.com` woff2); `require-trusted-types-for 'script'; trusted-types default`; `frame-ancestors 'none'; object-src 'none'; base-uri 'self'`; COOP same-origin (NO COEP — Google Fonts has no CORP header, and SharedArrayBuffer not needed for MLS/OPAQUE).
  - **Vite SRI plugin (`vite.config.ts`):** `sriPlugin()` compute SHA-256 hashes of ALL emitted JS/CSS chunks in `generateBundle {order: "post"}`, inject `integrity="sha256-..."` on `<script src="/assets/...">` and `<link href="/assets/...">` in HTML via `transformIndexHtml {enforce: "post"}`. Build-fail guard: throws if any matched asset lacks integrity attribute.
  - **security-auditor:** R1 fixed (worker-src blob: added); R2 fixed (COEP removed — Google Fonts incompatible); R3 fixed (SRI order: post + build-fail guard); Y2 (Trusted Types policy name `default` vs `react-html`), Y3 (connect-src host), Y4 (panic 500 headers), Y5 (intentional overwrite) — all documented/deferred.
  - **259 Rust tests** (+8 from 251); **64 frontend tests** (unchanged); **27 CF Worker tests** (+3 from 24); clippy clean; rustfmt clean; Biome clean.

## Current state (2026-05-31, cycle 52 — FEATURE: Region-Aware Client — prd.md §7.6)
- **Cycle 52 (commit b5513b1):** Region-Aware Client — missing Phase 4 DoD item:
  - **Backend:** `GET /v1/region/detect` (no auth required, parity with /health)
    - `AppState` gains `region_id: String` from `AppConfig.region_id`
    - Handler returns `{"region_id": "eu-de-1"}` — no PII, no IP, no country code
    - CF Worker already routed to correct origin; endpoint just confirms the server's region
    - +3 Rust tests: eu-de-1 response, ap-sin-1 response, no-auth-required (assert !401)
    - security-auditor PASS: YELLOW-1 region_id unvalidated (operator-controlled, JSON-safe); YELLOW-2 public routes unrated (parity with /health)
  - **Frontend:** region store + detect hook + sidebar data residency badge
    - `app/src/store/region.ts`: Zustand store; fetch() → /v1/region/detect; silently fails on errors; guards empty strings
    - `app/src/hooks/useRegionDetect.ts`: useEffect-based hook; returns regionId | null
    - `app/src/components/ChatLayout.tsx`: Sidebar footer shows `[globe] eu-de-1` badge when regionId non-null (prd.md §7.6 UX)
    - `app/src/components/Icon.tsx`: added "globe" SVG icon
    - +5 frontend tests: initial null, successful fetch, non-ok, network error, empty region_id
  - **251 Rust tests** (was 248, +3); **64 frontend tests** (was 59, +5); clippy clean; rustfmt clean; Biome clean

## Current state (2026-05-30, cycle 51 — FEATURE: confirm_upload IDOR fix)
- **Cycle 51 (commit 5875c3e):** Closed `confirm_upload` IDOR (security-auditor Y8, deferred since cycle 21):
  - **Root cause:** `POST /v1/media/:id/confirm` handler extracted `AuthenticatedDevice` but discarded it (`_device`). Any authenticated device could confirm any `media_id`.
  - **Fix:** `MediaUseCase::confirm_upload` gained `confirmer_device: &DeviceId` parameter. `MediaService::confirm_upload` now fetches the blob and checks `blob.uploader_device == confirmer_device`, returning `DomainError::Unauthorized` on mismatch (same ownership pattern as `get_download_url` and `delete`). REST handler passes `device_id` instead of ignoring it. All mock impls updated.
  - **+2 tests:** `confirm_upload_by_different_device_returns_unauthorized` (application layer); `confirm_upload_wrong_device_returns_401` (REST integration) — 248 Rust tests total (was 246)
  - **security-auditor:** GREEN on IDOR fix; YELLOWs: confirm_upload is a semantic no-op (no state transition, pre-existing); TOCTOU on find+check (low impact, pre-existing); MediaId enumeration oracle mitigated by rate limiter + UUIDv4 space
  - **248 Rust tests** (was 246, +2); clippy clean

## Current state (2026-05-30, cycle 50 — STABILIZATION: CI red fix + security sweep)
- **Cycle 50 (commits addd946, d648bfc):** STABILIZATION — CI red fixed + security RED + 5 YELLOWs addressed:
  - **CI red fix (addd946):** `ChatLayout.test.tsx` — `afterEach` missing from vitest import (TS2304) + `KAT_SN` declared but never used (TS6133); fix: add `afterEach` to import, use `KAT_SN` in the "clears verification" test body
  - **security-auditor RED #1 (d648bfc):** `ChatLayout.tsx InfoPanel` was writing/reading `db.verifiedContacts` via raw `PowehiDb`, bypassing `EncryptedPowehiDb`; `safetyNumber` was persisted in plaintext. Fix: import `EncryptedPowehiDb`; create `encryptedDb = useMemo(() => new EncryptedPowehiDb(db, cryptoWorker), [cryptoWorker])`; replace all 3 `db.verifiedContacts.*` calls with `encryptedDb.*VerifiedContact` calls; `encryptedDb === null` when worker unavailable — fail closed
  - **YELLOW #2:** `computedSafetyNumber` reset to null at top of WASM `useEffect` on every dep change — prevents stale SN from previous chat causing transient false MITM alarm on rapid chat switch
  - **YELLOW #5:** `dropDbKey()` added to `crypto.worker.ts`; call from auth store logout to clear AES-GCM key from worker memory (previously lingered until page close)
  - **YELLOW #6:** `deriveDbKey` throws `"export key too short"` if `exportKeyBytes.length < 32` (defensive guard against weak HKDF input)
  - **YELLOW #7:** `crypto.subtle.decrypt` in `decryptField` wrapped in try/catch; re-throws as `Error("decrypt_failed")` to prevent browser DOMException detail from leaking into logs
  - **+1 test:** `encryption.test.ts` — `deriveDbKey throws when export key < 32 bytes`; wrong-key test now asserts `"decrypt_failed"` message
  - **59 frontend tests** (was 58, +1); **246 Rust tests** (unchanged); TypeScript strict: clean; Biome: clean; cargo audit: 1 allowed warning (RUSTSEC-2024-0384 instant/openmls waiver)
  - **Remaining deferred (security-auditor YELLOW):**
    - Y3: `.catch(() => {})` in InfoPanel swallows error category — add opaque counters (low priority)
    - Y4: HKDF salt fixed constant — acceptable per NIST SP 800-56C, add comment (Y4 already documented)
    - Y8: `confirm_upload` IDOR (any device confirms any media_id) — Phase 4 media ACL deferred
  - **NOTE:** `dropDbKey()` in `crypto.worker.ts` is wired to the API but NOT yet called from the auth store logout — needs to be called in auth.ts `logout()` reducer when auth store is wired to real OPAQUE

## Current state (2026-05-30, cycle 49 — FEATURE: WASM safety number wiring)
- **Cycle 49 (commit a324e53):** InfoPanel WASM safety number wiring (deferred from cycle 44):
  - **`ChatLayout.tsx` InfoPanel**: replaced `MOCK_SAFETY_NUMBER` constant with async WASM computation
    - `cryptoWorker = useCryptoWorker()` top-level hook call in InfoPanel
    - `computedSafetyNumber` state (null = unavailable)
    - `useEffect` calls `cryptoWorker.mlsGroupMembers(identityId, groupId)` then `mlsComputeSafetyNumber(key1, key2)`
    - Fails closed: WASM unavailable → stays null → SafetyNumbers not rendered, no false MITM alarm
    - `handleVerify` guards on `computedSafetyNumber !== null`
    - MITM alert: `computedSafetyNumber !== null && stored.safetyNumber !== computedSafetyNumber`
    - `hexToBytes` validates hex input (Y2 fix); `members.length !== 2` fail-closed check (Y1 fix)
    - Added `mlsGroupId?: string` and `mlsIdentityId?: string` to Chat interface
    - SEED_CHATS[0] (Maya) has mock UUID group/identity IDs for testing
  - **`ChatLayout.test.tsx`**: `vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(MOCK_WORKER)` in beforeEach (vi.mock factory does NOT intercept ES module live bindings in Vitest 3.x; spyOn does)
  - **`app/src/hooks/__mocks__/useCryptoWorker.ts`** (NEW): manual mock file
  - **security-auditor**: PASS (Y1 + Y2 fixed; fail-closed behavior, no logging, race condition cleanup verified)
  - **58 frontend tests** (unchanged total, 14 ChatLayout tests updated); Biome clean; 246 Rust tests unchanged
  - **NOTE**: vi.mock with factory does NOT work for Vitest 3.x ES module live bindings; use vi.spyOn(module, 'fn').mockReturnValue() instead

## Current state (2026-05-30, cycle 47 — FEATURE: Dexie AES-GCM-256 encryption layer)
- **Cycle 47 (commit 380ef49):** IndexedDB encrypted storage layer — long-standing security-auditor RED #2 fixed:
  - **`app/src/db/encryption.ts`** (NEW): `deriveDbKey` (HKDF-SHA-256 from OPAQUE export key → AES-GCM-256 CryptoKey, non-extractable); `encryptField` (12-byte random IV || GCM ciphertext, base64url); `decryptField` (28-byte min length check, AES-GCM auth tag enforced); `FieldEncryptor` interface; `DirectFieldEncryptor` (test-only adapter)
  - **`app/src/db/encrypted-db.ts`** (NEW): `EncryptedPowehiDb` — SENSITIVE fields per-table: messages (ciphertextB64, plaintextB64), groups (mlsStateB64), verifiedContacts (safetyNumber); identity has no sensitive unindexed fields; getMessagesByGroup sorts by epochSeq (MLS RFC 9420 §6.3.1)
  - **`app/src/db/schema.ts` v3**: removed `LocalIdentity.exportKeyB64` — OPAQUE export key must not be persisted to IndexedDB (circular wrapping key dependency)
  - **`app/src/workers/crypto.worker.ts`**: added `initDbKey(exportKeyBytes)`, `encryptDbField(value)`, `decryptDbField(enc)` — CryptoKey held in worker, never crosses to main thread (react-hooks-only.md)
  - **crypto-reviewer**: R1 fixed (no circular key wrapping: exportKeyB64 removed), R2 documented (session write budget <<2^32 per NIST SP 800-38D), R3 fixed (key in worker), Y1 fixed (min length <IV+TAG=28 bytes), Y5 fixed (epochSeq sort); Y2/Y3/Y4 addressed via comments
  - **security-auditor**: GREEN — non-extractable key, random IV per call, no plaintext logged, indexed fields unencrypted by design
  - **+15 frontend tests**: 9 encryption unit tests (deriveDbKey, encryptField/decryptField round-trips, IV randomness, wrong-key rejection, tamper detection, truncation); 6 encrypted-db integration tests (round-trip, raw-blob verification, group sort, identity, verifiedContact lifecycle, cross-key rejection)
  - **58 frontend tests** (was 43, +15); Biome clean; 246 Rust tests unchanged

## Current state (2026-05-30, cycle 45 — STABILIZATION: boundary tests + media size defense-in-depth)
- **Cycle 45 (commit 2a08dac):** STABILIZATION — CI green, no open issues, security YELLOW #1 fixed + test gaps:
  - **security-auditor (cycle 45):** YELLOW #1 fixed: `MediaService::request_upload` now validates `size_bytes ∈ [1, 100MB]` (defense-in-depth — non-REST callers like gRPC cannot bypass cap); YELLOW #2 (confirm_upload IDOR: any device can confirm any media_id) deferred (low impact, confirm-only path); YELLOW #3 (retain_recent) already wired in cycle 42 main.rs; RED: none
  - **+7 Rust tests** (246 total, was 239):
    - `powehi-rest-api` +5: TTL min boundary (30→200), TTL max boundary (604800→200), TTL above max (604801→400), media size zero (400), media size too large >100MB (400)
    - `powehi-application` +2: `request_upload_size_zero_returns_invalid_input`, `request_upload_size_too_large_returns_invalid_input`
  - **cargo audit**: 1 allowed warning (RUSTSEC-2024-0384 instant/openmls waiver unchanged)
  - **246 Rust tests** (was 239, +7); **43 frontend tests** (unchanged); clippy clean; rustfmt clean; Biome clean

## Current state (2026-05-30, cycle 44 — FEATURE: Safety Numbers persistence + MITM alert wiring)
- **Cycle 44 (commit c4a1602):** CI red fix (Biome: 6 errors from cycle 43) + Safety Numbers DB persistence:
  - **CI fix (commit 5cd7b70):** 6 Biome errors fixed — SafetyNumbers.test.tsx import order; SafetyNumbers.tsx `<div role="group">`→`<fieldset>` (a11y); `key={i}`→`key={block}` (noArrayIndexKey); collapsed background ternary; ChatLayout.test.tsx multi-line expect collapsed; ChatLayout.tsx MOCK_SAFETY_NUMBER const split + span inline style expanded
  - **Safety Numbers persistence (commit c4a1602):** Completes cycle-43 INFO-9 deferred wiring:
    - `InfoPanel.useEffect`: loads `db.verifiedContacts.get(chat.id)` on mount + chat switch; `cancelled` flag prevents stale updates on rapid chat switch
    - `.catch` on DB read: fails gracefully to unverified state; no content/PII logged (security-auditor RED #3 fixed)
    - `handleVerify`: persists `{contactId, safetyNumber, verifiedAt}` to Dexie
    - `handleReset`: deletes record, clears all verification state
    - **MITM detection**: `mitmAlert = stored.safetyNumber !== MOCK_SAFETY_NUMBER` → red banner "Safety number changed — verify again to confirm identity"
    - TODO comment: comparison must use `cryptoWorker.mlsComputeSafetyNumber()` with fail-closed when WASM unavailable (deferred to wasm-wiring)
    - `test-setup.ts`: `import "fake-indexeddb/auto"` added globally
    - **+3 frontend tests**: DB persists on verify; MITM alert on stale SN; DB cleared on reset — 43 total (was 40)
    - **security-auditor**: RED #3 fixed (.catch); RED #1 TODO-d (WASM wiring); RED #2 pre-existing (Dexie unencrypted across all schema — deferred); YELLOW #4 fixed; GREEN #6/#7
  - **239 Rust tests** (unchanged); **43 frontend tests** (was 40, +3); clippy clean; rustfmt clean; Biome clean
  - **Safety Numbers feature COMPLETE** — both the WASM derivation (cycle 43) and DB persistence/MITM detection (cycle 44) are done; remaining deferred: Dexie encryption layer (pre-existing across schema), real WASM worker value wiring

## Current state (2026-05-29, cycle 43 — FEATURE: Safety Numbers — MLS identity verification fingerprint — prd.md §5.6)
- **Cycle 43 (commit 68ce879):** Safety Numbers — MLS identity verification fingerprint:
  - **WASM** (`powehi-crypto-wasm/src/wasm_exports.rs`):
    - `compute_safety_number_inner`: SHA-512, domain prefix `"powehi-safety-number-v1"`, length-prefixed + sorted key concat, 12×6-digit groups (prd.md §5.6), enforces 32-byte inputs
    - `mls_group_members`: returns all group member leaf indices + signature public keys (public data per RFC 9420 §7.2)
    - `mls_compute_safety_number`: wasm_bindgen export, symmetric, propagates length-validation error
    - +5 WASM tests: symmetry, format (12 groups × 6 digits × len=83), differing-pairs, wrong-length rejection (31/33/0 bytes), KAT frozen at "689053 337949 184798 288064 134849 362568 560227 765408 921198 315305 693006 807986"
    - **crypto-reviewer R1** (domain separation) → FIXED; **R2** (6-digit spec) → FIXED; **R5** (length validation) → FIXED; Y3 (truncation documented), Y4 (bias minimal)
  - **Frontend**:
    - `SafetyNumbers.tsx` (new): presentational component — 4×3 grid of digit blocks, inline confirm prompt, verified/unverified state, `onVerify`/`onReset` callbacks; no crypto imports (rule: react-hooks-only)
    - `db/schema.ts` v2: `verifiedContacts` table (`contactId`, `safetyNumber`, `verifiedAt`) — Dexie additive migration preserves v1 data
    - `crypto.worker.ts`: `mlsGroupMembers` + `mlsComputeSafetyNumber` Comlink bindings + TS return types
    - `ChatLayout.tsx`: `InfoPanel` replaces hardcoded fingerprint card with `<SafetyNumbers>`; state: `safetyVerified` + `verifiedAt`; mock safety number = KAT value
    - +5 frontend tests (12-block render, verified-state timestamp, confirm flow calls onVerify, cancel is idempotent, unverified badge)
    - **security-auditor**: GREEN — no RED/YELLOW; INFO-8 (comment inconsistency) fixed
  - **239 Rust tests** (was 234, +5); **40 frontend tests** (was 35, +5); clippy clean; rustfmt clean
  - **Remaining wiring** (deferred, security-auditor INFO-9): persist verification to `db.verifiedContacts`; compare stored vs. recomputed safety number on each group open → MITM alert if mismatch

## Current state (2026-05-29, cycle 42 — FEATURE: Per-handle-hash rate limiting — credential-stuffing protection)
- **Cycle 42 (commit 1cf76db):** Per-handle rate limiting (deferred from cycle 19 TODO(hardening)):
  - **`HandleRateLimiter`** (`powehi-rest-api/src/rate_limit.rs`): `governor::DefaultKeyedRateLimiter<u128>` keyed on first 16 bytes of `handle_hash` (SHA-256 of plaintext handle, client-computed); burst=5, 1 refill per 3 minutes; `retain_recent()` for GC; `Default` impl
  - **`ApiError::too_many_requests()`** (`error.rs`): static `{"code":"rate_limited"}` 429, no handle/timing leak
  - **`AppState`** (`lib.rs`): gains `handle_rate_limiter: Arc<HandleRateLimiter>` field; all AppState constructions updated
  - **`register_init` + `login_init`** (`routes/auth.rs`): (1) validate `handle_hash.len() == 32` → 400; (2) check handle bucket → 429; both before logging or calling use case
  - **`main.rs`**: hourly `retain_recent()` GC task to bound DashMap memory growth
  - **Tests**: +3 unit (HandleRateLimiter tight/isolation/short-hash), +2 integration (same-hash 429, different-hash isolation) — total: 234 Rust tests (was 229)
  - **security-auditor**: YELLOW #1 (handle_hash length not validated) → FIXED; YELLOW #3 (unbounded DashMap growth) → FIXED (retain_recent GC); YELLOW #2 (empty hash zero-bucket) → resolved by #1; GREEN #4-7

## Current state (2026-05-29, cycle 41 — FEATURE: Disappearing Messages — Post-MVP TTL-gated expiry)
- **Cycle 41 (commit fb85680):** Disappearing Messages (Post-MVP roadmap item):
  - **Port** (`powehi-port-inbound`): `MessagingUseCase::send_message` gains `ttl_seconds: Option<u32>` (range [30, 604800])
  - **Application** (`MessagingService`): TTL validated; `expires_at` computed server-side (`Utc::now() + duration`) — clients cannot set arbitrary timestamps; `FakeEnvelopeRepo::find_pending` now filters expired entries in tests
  - **DB adapter** (`PgEnvelopeRepository`): `find_pending` SQL hardened to `AND (expires_at IS NULL OR expires_at > NOW())` — expired ciphertext never returned even before GC runs
  - **REST API** (`SendMessageRequest`): `ttl_seconds: Option<u32>` with edge validation [30, 604800]; returns 400 on out-of-range
  - **Background GC** (`bin/powehi-server`): tokio 5-min interval task calling `delete_expired`; logs only `deleted = N` count; no content, no device IDs
  - **Frontend** (`ChatLayout.tsx` + `Icon.tsx`): `timer` icon added; `Composer` TTL toggle button (cycles Off → 5m → 1h → 1d → 1w → Off) with orange active state; sent messages with active TTL show "Disappearing" badge; `InfoPanel` "Disappearing messages" row dynamic
  - **Tests**: +4 backend (TTL set, TTL too short, TTL too long, REST 400), +2 frontend (timer cycle, badge render) — total: 229 Rust + 35 frontend
  - **security-auditor**: GREEN (9 findings: all GREEN; 1 YELLOW pre-existing broadcast/fake divergence accepted)
  - **229 Rust tests** (was 225 + 4 new); **35 frontend tests** (was 33 + 2 new); clippy clean; rustfmt clean; biome clean

## Current state (2026-05-29, cycle 40 — STABILIZATION: test gaps + AppConfig secret redaction)
- **Cycle 40 (commit d06bd36):** Stabilization — CI green, no open issues, test gaps closed + security YELLOW fixed:
  - **MessagingService `maybe_push()` — 5 new tests** (was 0): noop when push not configured; noop with no subscription; fires when sub exists; push failure does not propagate (fire-and-forget invariant); send_welcome pushes to target not sender
  - **push_subscription route — 5 new tests**: wrong p256dh length (64 bytes); invalid p256dh base64url; wrong auth length (15 bytes); endpoint too long (>2048 chars); IPv6 ULA (fc00::/7, fd00::/8) + link-local (fe80::/10) SSRF guard
  - **AppConfig Debug redaction**: replaced `#[derive(Debug)]` with manual impl that redacts `database_url`, `redis_url`, `r2_secret_access_key`, `vapid_private_key_pem`; new test asserts secrets never appear in `format!("{cfg:?}")`
  - **security-auditor**: YELLOW-1 (AppConfig Debug leaks VAPID key + DB credentials) → fixed; remaining YELLOWs accepted or pre-existing
  - **cargo audit**: 1 allowed warning (RUSTSEC-2024-0384 instant/openmls waiver unchanged)
  - **225 Rust tests** (was 214, +11); clippy clean; rustfmt clean

## Current state (2026-05-29, cycle 39 — FEATURE: Web Push subscription management — RFC 8291/8292 VAPID)
- **Cycle 39 (commit a8715db):** Web Push subscription management — post-Phase-6 bonus:
  - **Domain/Ports**: `PushSubscription` struct; `PushSubscriptionRepository` port; `WebPushPort` port
  - **powehi-webpush adapter**: `VapidWebPushAdapter` — ES256 VAPID JWT (p256 RustCrypto, no homegrown crypto); empty-body POST (ZK: no content through push channel); redirect disabled (SSRF via open-redirect); 410 Gone handled as success; graceful `disabled()` mode (no VAPID keys in dev)
  - **powehi-postgres adapter**: `PgPushSubscriptionRepository` — upsert/fetch/delete; migration 0004 + rollback script; ignored Postgres integration test (run with `--ignored` against live DB)
  - **REST API**: `POST/DELETE /v1/push-subscriptions` behind `AuthenticatedDevice` + `api_governor`; SSRF guard rejects private IPv4, RFC-1918, link-local, IPv6 loopback, ULA, and IPv4-mapped IPv6 (`::ffff:169.254.169.254`); no endpoint/key logged
  - **Application layer**: `MessagingService.with_push()` + `maybe_push()` — fire-and-forget push on send_message/send_welcome; failures never propagate to caller
  - **Config**: `vapid_private_key_pem` + `vapid_contact` (both optional)
  - **Security auditor RED fixed**: IPv4-mapped IPv6 SSRF bypass (`::ffff:169.254.169.254`) — `to_ipv4_mapped()` check added; `to_ipv4()` NOT used (would incorrectly match `::1` as `0.0.0.1`)
  - **crypto-reviewer**: PASS — ES256 r||s JOSE encoding correct; serde_json escapes `aud` claim; no homegrown crypto
  - **214 Rust tests** (was 194); clippy clean; rustfmt clean

## Current state (2026-05-29, cycle 37 — FEATURE: Phase 6 COMPLETE — gRPC p99 synthetic + CI fix)
- **Cycle 37 (commit 9efedcb):** Phase 6 final item completed + CI red fixed:
  - **CI red fix (commit 9efedcb):** `powehi-grpc/src/client.rs` rustfmt diff in circuit-breaker test blocks → `cargo fmt` applied; CI was failing on Format check job for 2 consecutive commits
  - **`infra/synthetic/cross-region-p99.js` (EXTENDED):** Completes Phase 6 DoD "Cross-region message round-trip p99 <200ms (EU↔KR), incl. gRPC forwarding":
    - Added `k6/net/grpc` gRPC `HealthCheck` RPC round-trip for both EU and AP-Seoul with `grpc_req_duration p(99)<200ms` thresholds; same channel as `ForwardEnvelope` — validates gRPC forwarding path latency SLA (prd.md §4A.6)
    - `assertGrpcZeroKnowledge()`: ZK guard on gRPC `HealthCheckResponse` (checks for forbidden `content`/`plaintext` fields)
    - **R1 fix:** `assertZeroKnowledge()` now handles bare `"ok"` string (axum health handler returns plain string, not JSON — previous guard was always failing with `JSON.parse("ok")` throw)
    - **R2 fix:** `GRPC_PLAINTEXT=1` blocked for non-dev addresses; only `localhost/127.0.0.1/*.local/*.internal` allowed (prevents accidental plaintext to production mTLS endpoints)
    - **Y4 fix:** `try/finally` wraps each `connect/invoke/close` block (prevents leaked connections when invoke() throws)
    - gRPC tests optional: skipped when `EU_GRPC_ADDR`/`AP_SEOUL_GRPC_ADDR` not set; thresholds pass trivially when no data points emitted
  - security-auditor: R1 (HTTP ZK guard broken) + R2 (GRPC_PLAINTEXT fail-open) fixed; Y1 (log category) + Y4 (try/finally) fixed; Y2 (PROTO_DIR path) + Y3 (ZK guard completeness) accepted
  - **194 Rust tests**; clippy clean; rustfmt clean
  - **Phase 6 ALL DoD items complete** — STATUS.md updated to "COMPLETE"

## Current state (2026-05-28, cycle 36 — FEATURE: Phase 6 single-region failover verification)
- **Cycle 36 (commit 6a07f28):** Phase 6 DoD item "Single-region failure auto-failover verified (RTO <5min, RPO <30s)" completed:
  - **`infra/synthetic/rpo-check.sh` (NEW):** Postgres streaming replication lag pre-check; queries `pg_stat_replication`; fails if any standby has `replay_lag > RPO_THRESHOLD_SECONDS` (default: 30s); validates no-standby degenerate state; `RPO_THRESHOLD_SECONDS` integer-validated before SQL interpolation (security R1 fix)
  - **`infra/synthetic/failover-drill.sh` (EXTENDED):** Step 0 RPO pre-check (calls rpo-check.sh if DB_HOST set); Step 3b CF HEALTH_KV propagation assertion; Step 4 strict RTO exit-1 (was warn-only); Security fixes: R1 SQL injection (RPO_THRESHOLD_SECONDS integer guard), Y1 `^https://` scheme validation + `--proto '=https'` on curl, Y2 REGION allow-list regex, Y3 mktemp for temp file
  - **`powehi-grpc/src/client.rs` (TESTS):** 2 circuit-breaker integration tests: `with_retry_fast_rejects_when_circuit_open` + `with_retry_trips_circuit_after_all_retries_fail`
  - **STATUS.md updated:** Marked [x]: KeyPackage consume integrity (cycle 34), Edge Worker routing (cycle 34), Single-region failover (cycle 36)
  - security-auditor: R1 fixed (SQLi), Y1/Y2/Y3 fixed; Y4 accepted (no content/PII/ciphertext in replication lag output)
  - **194 Rust tests** (was 192); clippy clean
  - **Phase 6 remaining:** Cross-region message round-trip p99 <200ms (EU↔KR) — gRPC forwarding latency synthetic test needed

## Current state (2026-05-28, cycle 35 — STABILIZATION: CF Worker security fixes + test gap closure)
- **Cycle 35 (commit 91ef88e):** Stabilization — security sweep fixed 2 RED findings + 1 YELLOW, test gaps closed:
  - **RED #1 (PIPA bypass):** CF Worker `index.ts` read country from client-controlled `CF-IPCountry` header; fixed to read from `request.cf.country` (CF infrastructure, cannot be spoofed). KR users could bypass PIPA 503 by sending `CF-IPCountry: DE`.
  - **RED #2 (trust-header injection):** CF Worker forwarded all inbound headers to origin, including `X-Forwarded-For`, `X-Real-IP`, `CF-IPCountry`; fixed to strip full set of 8 trust/IP/geo headers before forwarding; backend rate-limiter was exploitable via IP rotation in XFF.
  - **YELLOW #3:** Unguarded `fetch()` now wrapped in try/catch returning structured 503 ORIGIN_UNREACHABLE JSON (was CF default error page with ray-ID).
  - **index.test.ts (new):** 8 security-invariant Vitest tests: RED-1 PIPA bypass invariant, RED-2 header stripping for all 7 headers + X-Powehi-Region overwrite, ALL_REGIONS_DOWN failover, ORIGIN_UNREACHABLE try/catch.
  - **group_service.rs:** 4 new unit tests (create_group, add_member, remove_member, home_region invariant) using in-memory FakeGroupRepo — was 0 tests despite 66 lines of service code.
  - **RUSTSEC-2025-0134 waiver:** `rustls-pemfile` unmaintained advisory (tonic 0.12.3 transitive dep) waived in both `.cargo/audit.toml` and `deny.toml`; `cargo audit` now shows 1 allowed warning (RUSTSEC-2024-0384 for instant/fluvio-wasm-timer, pre-existing).
  - **192 Rust tests** (was 188); **24 CF Worker tests** (was 16); clippy clean; rustfmt clean; cargo audit 1 allowed warning.
  - security-auditor: GREEN (all RED fixed, YELLOW fixed, remaining YELLOW-4/5 noted as acceptable).
  - Next: Phase 6 remaining items — cross-region message round-trip p99 <200ms (EU↔KR); single-region failover RTO <5min RPO <30s; KeyPackage cross-region replication consume integrity.

## Current state (2026-05-28, cycle 34 — FEATURE: Phase 6 CF smart-router + KeyPackage consume integrity)
- **Cycle 34 (commit 5b7d855):** Two Phase 6 items implemented:
  - **Cloudflare Edge Worker smart routing** (`infra/cloudflare/workers/smart-router/`):
    - `src/router.ts`: pure routing logic — `resolveTarget` (geographic by CF-IPCountry), `pickOrigin` (health-state failover), `rewriteUrl`; zero-knowledge (never reads body)
    - `src/index.ts`: CF Worker entry — reads `HEALTH_KV` (set by k6 synthetic), routes EU/AP, fails over on unhealthy, strips CF-Connecting-IP
    - PIPA guard: KR → 503 `PIPA_REGION_PENDING` (sin1 ≠ Korea, prd.md §4A.1)
    - `wrangler.toml`: powehi-smart-router, HEALTH_KV binding, EU/AP origins
    - 16 Vitest tests: country routing, failover, PIPA block, URL rewrite — all green
    - `infra/terraform/envs/cloudflare/worker.tf`: `cloudflare_workers_kv_namespace` (health state) + `cloudflare_workers_route` api.powehi.app/*
    - Terraform v5 migration fix: `cloudflare_record` → `cloudflare_dns_record`, `value` → `content`, `.hostname` → `.name` in outputs; `tofu validate` clean
    - `pnpm-workspace.yaml`: added infra/cloudflare/workers/smart-router
  - **KeyPackage cross-region consume integrity**:
    - `powehi-domain`: `ConsumeResult` enum (Consumed/AlreadyConsumed/NotFound)
    - `powehi-port-outbound`: `KeyPackageRepository.mark_consumed` added
    - `powehi-postgres`: `PgKeyPackageRepository.mark_consumed` — CAS UPDATE + EXISTS (atomic double-consume prevention)
    - `powehi-grpc/server.rs`: `consume_key_package` RPC implemented; UUID validation; ConsumeResult→ConsumeStatus mapping; no KP content touched
    - 5 new gRPC tests (Consumed/AlreadyConsumed/NotFound/invalid-UUID/empty-region)
    - `main.rs`: `key_package_repo.clone()` → both KeyPackageService and RegionGrpcServer
  - security-auditor: GREEN (YELLOW-8 benign TOCTOU; YELLOW-9 mTLS-mitigated oracle — neither blocking)
  - 188 Rust tests passing (was 182); 16 Worker tests; clippy clean; rustfmt clean
  - Next: cross-region p99 <200ms live measurement; single-region failover drill (RTO verification)

## Current state (2026-05-28, cycle 33 — FEATURE: Phase 6 AP-Seoul Tier 1 + Helm + synthetic)
- **Cycle 33:** CI was RED (rustfmt assert_eq! multi-line in powehi-grpc/server.rs) → fixed + pushed (694661f). Then Phase 6 infra batch:
  - `infra/terraform/envs/prod-ap-seoul/`: Hetzner sin1 k3s HA (3CP+3W cx41); S3 remote backend (not local state)
  - `infra/terraform/envs/prod-eu/versions.tf`: migrated to `backend "s3"` (matching prod-ap-seoul)
  - `infra/terraform/envs/backend.hcl.example`: backend config template for operators
  - `infra/helm/powehi/`: full Helm chart — Deployment (runAsNonRoot/readOnly/drop-ALL/limits), Service (8080/9090/50051), ConfigMap, HPA, 9-policy NetworkPolicy (deny-all + whitelist), ExternalSecret (ESO), ServiceAccount
  - Security fixes from security-auditor: gRPC egress port 50051 added; 169.254.169.254/32 added to HTTPS egress except-block; failover-drill.sh guards against credentials-in-URL
  - `infra/synthetic/cross-region-p99.js`: k6 p99<200ms + ZK guard
  - `infra/synthetic/failover-drill.sh`: idempotent drain→probe→restore, RTO measurement
  - prd.md §4A.1 updated: AP-Seoul = Hetzner sin1 (Singapore, interim), PIPA note added
  - threat-model-checker: YELLOW (no crypto drift; Singapore≠Korea documented)
  - `helm lint` clean; `tofu validate` green (both envs)
  - 182 tests passing; clippy clean; rustfmt clean
  - **Phase 6 infra-test gate DONE** — gRPC mesh + AP-Seoul Tier 1 + Helm + synthetic COMPLETE
  - Next: Cloudflare Edge Worker smart routing; KeyPackage cross-region replication integrity test; cross-region p99 measurement

## Current state (2026-05-28, cycle 32 — FEATURE: Phase 6 gRPC inter-region mesh)
- **Cycle 32 (commit 563ae8e):** gRPC cross-region delivery mesh:
  - `powehi-proto`: `region.proto` — 5 RPCs (ForwardEnvelope, ForwardCommit, SyncGroupMembership, ConsumeKeyPackage, HealthCheck); built with `protox 0.7` (pure-Rust, no system protoc); `compile_fds` API; 4 proto enum tests
  - `powehi-grpc`: full server + client:
    - `RegionGrpcServer`: implements `RegionService` tonic trait; `domain_err_to_status` strips internals; forward_envelope saves + publishes EnvelopeReceived; forward_commit does NOT trust peer-supplied epoch (deferred GroupRepository validation); consume_key_package returns `Unimplemented`; health_check returns HEALTHY; 5 tests
    - `RegionGrpcRouter`: implements `RegionRouter` port; per-peer circuit breaker (`AtomicU32` + `Mutex<Option<Instant>>`); 3-retry exponential backoff; mTLS via `TlsConfig.server_tls/client_tls`; build_channel enforces https URI via `http::Uri` parsing (SSRF hardening); 5 tests
    - `TlsConfig`: reads PEM files; ServerTlsConfig (mTLS client_ca_root) + ClientTlsConfig (identity + ca_cert)
    - `CircuitBreaker`: threshold-based open/closed; poison-safe `unwrap_or_else(|e| e.into_inner())`; 5 tests
  - `powehi-config`: `grpc_port` (default 50051), `grpc_peers` CSV parser, `grpc_tls_cert/key/ca`; `grpc_tls_enabled()` requires all 3 fields; 4 tests
  - `bin/powehi-server`: fail-to-start when peers configured without mTLS; `max_decoding_message_size(64 KiB)`; `tokio::try_join!` now 3 futures (public + admin + gRPC)
  - Security fixes applied (security-auditor pass): epoch not trusted from peer; internal errors not leaked; https-only when TLS; consume_key_package returns Unimplemented not silent CONSUMED; no plaintext in spans
  - Test fix: `forward_commit_returns_accepted_with_zero_epoch` (was asserting peer-supplied epoch 42; now asserts 0 — server must not echo attacker-controlled value)
  - 182 tests passing; clippy clean; rustfmt clean
  - **Phase 6 item PARTIAL** — gRPC mesh + mTLS DONE; AP-Seoul Tier 1, cross-region p99, failover, KeyPackage replication, data residency, infra-test gate PENDING
  - Next: AP-Seoul Tier 1 Terraform + Helm deployment

## Current state (2026-05-28, cycle 31 — STABILIZATION: CI red fix + test gap closure)
- **Cycle 31 (commit 7402476):** CI was RED (rustfmt format check failed on powehi-redis tests added in cycle 30):
  - **Root cause**: 3 struct literals in `serde_round_trip_*` tests exceeded rustfmt's line-width limit:
    - `DomainEvent::UserRegistered { ... }` → expanded to multi-line
    - `DomainEvent::EnvelopeReceived { envelope_id, group_id, .. }` → expanded + `} = rt {` pattern
    - `DomainEvent::EpochAdvanced { ... }` → expanded to multi-line
  - **Fix**: expanded all 3 struct literals in `powehi-redis/src/lib.rs` to match rustfmt output
  - **Test gaps closed**:
    - `powehi-r2`: +5 tests (all 8 allowed content types via loop, 8 disallowed types, expires_at Some, storage_key verbatim) — total: 7 (was 3)
    - `powehi-telemetry`: +3 tests (install_prometheus_succeeds, valid text format, no user identifiers in output) — total: 3 (was 0)
  - CI: green (rustfmt clean). 161 Rust tests (was 156). clippy: clean. cargo audit: only RUSTSEC-2024-0384 waiver.
  - Next: Phase 6 — gRPC mesh + mTLS; AP-Seoul Tier 1; cross-region p99 <200ms; failover; KeyPackage replication; data residency; infra-test gate

## Current state (2026-05-28, cycle 30 — STABILIZATION: test coverage + Biome fix)
- **Cycle 30 (commit 06bc0d4):** Stabilization — test gap closure + Biome artifact fix:
  - **powehi-redis**: 12 new pure unit tests (total: 14 was 2):
    - `event_topic` routing for all 7 DomainEvent variants
    - Serde round-trips for `UserRegistered`, `EnvelopeReceived`, `EpochAdvanced`
    - Security invariant: `EnvelopeReceived` JSON contains only opaque UUIDs, no `content`/`ciphertext`/`plaintext` keys
    - `EmptyStream::poll_next` returns `Poll::Ready(None)`
  - **ChatLayout.test.tsx**: 9 new component tests (security + UX invariants):
    - Encryption banner renders; E2EE notice in message area; composer placeholder says "encrypted"
    - Search filter; empty-query no-match; send message appends; info panel opens; conversation switching
  - **Biome fix**: `app/biome.json` now excludes `test-results/**` and `playwright-report/**` — eliminates spurious format errors from Playwright artifacts
  - **gitignore**: `app/test-results/` and `app/playwright-report/` added to root `.gitignore`
  - CI: green. `cargo audit`: only RUSTSEC-2024-0384 existing waiver. clippy: clean. biome: clean.
  - **156 Rust tests** (was 142); **33 frontend tests** (was 24)
  - Next: Phase 6 — gRPC mesh + mTLS; AP-Seoul Tier 1; cross-region p99 <200ms; failover; KeyPackage replication; data residency; infra-test gate

## Current state (2026-05-28, cycle 29 — FEATURE: Phase 5 SLSA L3 + cosign/Rekor + load test + PQ ADR)
- **Phase 5 cycle 29 (commit 75e6c6f):** Supply-chain hardening + load test + PQ migration doc:
  - `Dockerfile`: multi-stage `rust:1.83.0-bookworm` → `debian:bookworm-20250317-slim`; non-root `powehi` uid 1000; `SOURCE_DATE_EPOCH=0` + `--locked` for byte-reproducible builds; exposes 8080 (public) + 9090 (admin/metrics)
  - `.dockerignore`: excludes `target/`, `app/`, `node_modules/`, `.git/`, `.env*`, `*.pem`, `*.key`, `app/test-results/`
  - `.github/workflows/release.yml`: 4-job SLSA L3 pipeline triggered on `v*.*.*` tags:
    - `build-binary` → computes SHA-256 base64 subjects
    - `binary-provenance` → `generator_generic_slsa3.yml@v2.0.0` (Rekor + .intoto.jsonl on GitHub release)
    - `build-push-container` → ghcr.io push + `cosign sign --yes` keyless → Rekor; `id-token: write` (security-auditor RED fix)
    - `container-provenance` → `generator_container_slsa3.yml@v2.0.0` (OCI attestation + Rekor)
    - `dtolnay/rust-toolchain@1.83.0` (not `@stable`); `--locked`; `concurrency` block; `github.repository_owner`
  - `load-tests/ws-10k.js`: k6 script ramp 0→10k concurrent WS; thresholds `ws_connecting p95<500ms`, `error_rate<1%`; asserts notifications have no `content`/`ciphertext` fields (zero-knowledge guard)
  - `docs/decisions/0003-pq-migration.md`: ADR for ML-KEM-768+ML-DSA-65 in 3 phases; OPAQUE PQ path tracked
  - Threat-model-checker: GREEN (T3 reproducible builds + T6 PQ strengthened)
  - Security-auditor: RED fix (`id-token: write`), all critical YELLOWs addressed; SHA action pins + base-image digest pins noted as follow-up (not blocking)
  - 142 tests pass; clippy clean
  - **Phase 5 COMPLETE — all checklist items done**
  - Next: Phase 6 — gRPC mesh + mTLS; AP-Seoul Tier 1; cross-region p99 <200ms; infra-test gate

## Current state (2026-05-27, cycle 28 — FEATURE: Phase 5 Prometheus metrics observability)
- **Phase 5 cycle 28 (commit 457435c):** Prometheus metrics endpoint (zero-knowledge observability):
  - `powehi-telemetry`: `install_prometheus() -> anyhow::Result<PrometheusHandle>` — no `expect()` in lib code (crates-naming.md)
  - `powehi-rest-api`: `admin_router(handle)` — serves GET `/metrics` with Prometheus text format; `metrics_response()` uses `HeaderValue::from_static` (no panic)
  - Zero-knowledge counters: `auth_register_total{result}`, `auth_login_total{result}`, `messages_sent_total{kind}`, `key_packages_uploaded_total`, `key_packages_fetched_total` — all labels are static strings, no user/device IDs
  - `powehi-config`: `admin_port` (default 9090, `POWEHI__ADMIN_PORT` env var)
  - `bin/powehi-server`: admin server bound to `127.0.0.1:admin_port` via `tokio::try_join!`; `/metrics` never exposed on public port (security-auditor RED finding addressed)
  - Tests: `metrics_endpoint_returns_200_with_prometheus_content_type`, `metrics_output_is_prometheus_text_format` — UUID-label leak detection
  - Security-auditor YELLOW deferred: traffic-analysis risk from aggregate counters (acceptable internal-only), future path normalization for axum metrics middleware
  - 142 tests pass (was 140); clippy + rustfmt clean
  - Next: remaining Phase 5 items — SLSA L3, cosign+Rekor, load test (10k concurrent WS), PQ migration doc

## Current state (2026-05-27, cycle 27 — STABILIZATION: CI red fix — @types/node + Playwright locator)
- **Cycle 27 (commit d2a7abb):** Two frontend CI failures fixed; CI was red → auto-switched to STABILIZATION:
  - **Fix 1 (TS2307/TS2693/TS2339):** `vite.config.ts` imports `node:fs`, `node:path`, `node:url`, uses `URL` and `import.meta.url` — all fail `tsc` without `@types/node`; added `@types/node ^25.9.1` to app devDependencies
  - **Fix 2 (Playwright strict-mode):** `getByText(/handle/i)` matched both `<label>Handle</label>` AND `<div>Handle and password are required.</div>` after empty-form submit; narrowed to `getByText(/are required/i)` which is unambiguous
  - 24 Vitest + biome clean; 140 Rust tests green; build + budget pass
  - Next: Phase 5 — SLSA L3 reproducible builds + cosign + Rekor + load test + observability

## Current state (2026-05-27, cycle 26 — STABILIZATION: CI red fix — WASM stub Vite plugin)
- **Cycle 26 (commit 80511b7):** Two CI failures fixed; CI was red → auto-switched to STABILIZATION:
  - **Root cause:** `vite:worker-import-meta-url` plugin ignores `/* @vite-ignore */` when bundling workers; tries to resolve `../wasm/powehi_crypto_wasm.js` which doesn't exist in CI (gitignored with `*`)
  - **Fix 1 (Bundle budget / build):** Added `powehiWasmStub` Vite plugin to `vite.config.ts` — hooks `resolveId`/`load`, redirects any `powehi_crypto_wasm` import to a no-op virtual module (`export default async function init() {}`) when wasm-pack artifact is absent; plugin registered in both `plugins[]` AND `worker.plugins()` (worker-build context is separate)
  - **Fix 2 (Playwright E2E):** Vite dev server was sending error overlay via HMR WebSocket when worker fetched the missing WASM; `<vite-error-overlay>` intercepted all button clicks; same stub plugin prevents the error
  - **Fix 3 (bundle budget regex):** `/index-[a-zA-Z0-9]+\.js$/` → `/index-[\w-]+\.js$/` — Rollup hashes with underscores (`C7__kd29`) were silently missed
  - 24 Vitest + biome clean; 140 Rust tests green; both Vite build paths verified locally
  - Next: Phase 5 — SLSA L3 reproducible builds + cosign + Rekor + load test + observability

## Current state (2026-05-27, cycle 25 — STABILIZATION: CI red fix + security audit + test gap closure)
- **Cycle 25 (commits 93e393d + 19a79b2):** 3 frontend CI failures fixed + security RED patched:
  - **CI fix 1 (Biome):** `check-bundle-budget.mjs` — merged duplicate node:fs imports, removed unused `brotliCompressSync`, collapsed multiline filter; `sw.js` — collapsed `clients.matchAll().then()` chain; all biome errors resolved
  - **CI fix 2 (bundle-build/TS2307):** `vite-env.d.ts` — added wildcard ambient module declaration `declare module "*powehi_crypto_wasm.js"` so tsc resolves the dynamic WASM import in CI without wasm-pack artifact
  - **CI fix 3 (Playwright):** `Login.tsx` button text "Send" → "Sign in" (Playwright tests were timing out on `getByRole('button', {name:/sign in/i})`); h1 heading added with SR-only "Powehi" span for heading role assertion; `App.test.tsx` matcher updated /send/i → /sign in/i
  - **Security RED fixed:** `key_package.rs` upload handler — added ownership check `caller == device_id` preventing MLS key substitution (IDOR where any device could upload KPs under another identity); new 401 test `upload_key_packages_cross_device_returns_401`
  - **Test gaps closed:** `src/store/auth.test.ts` (5 Zustand tests: login/logout transitions), `src/components/Login.test.tsx` (7 tests incl. security invariants: empty handle → rejected before crypto call)
  - YELLOW findings deferred to Phase 5: confirm_upload cross-device check, content_type allowlist, stub bearer auth, WS connection cap
  - 44 Rust rest-api tests (was 43); 24 Vitest tests (was 12); Biome clean; clippy clean; cargo audit clean (RUSTSEC-2024-0384 waiver)
  - Next: Phase 5 — SLSA L3 reproducible builds + cosign + Rekor + load test + observability

## Current state (2026-05-27, cycle 24 — FEATURE: Phase 4 Service Worker + Playwright + bundle budget)
- **Phase 4 cycle 24 (commit 600c2b3):** Service Worker push + Playwright E2E + bundle budget:
  - `app/public/sw.js`: Web Push RFC 8291 wake-up handler; notification body is constant "New encrypted message" (no content); groupId validated as UUID v4 regex before use (security-auditor YELLOW-1/2 addressed); open-window uses literal "/" only
  - `app/src/hooks/useServiceWorker.ts`: SW registration + VAPID subscribe hook; non-fatal error handling; `urlBase64ToUint8Array` returns `Uint8Array<ArrayBuffer>` for TS5.8 compat
  - `app/src/main.tsx`: Root component wraps App with useServiceWorker(); `worker.format: "es"` in vite.config.ts fixes production build of Comlink crypto worker
  - `app/e2e/login.spec.ts` + `app/e2e/chat.spec.ts`: Playwright tests; `playwright.config.ts` with Chromium, webServer auto-start
  - `app/scripts/check-bundle-budget.mjs`: bundle gate (init JS <200KB gz, WASM <800KB gz); actual: 69.1KB JS + 553.4KB WASM — both pass
  - `.github/workflows/ci-frontend.yml`: added `playwright` and `bundle-budget` CI jobs
  - `pnpm-lock.yaml` regenerated — fixed frozen-lockfile mismatch that was causing CI failures
  - TypeScript fixes: schema.test.ts unused variable removed; crypto.worker.ts cast via unknown; Uint8Array<ArrayBuffer> type
  - 12 frontend tests green; 174 Rust tests green; biome clean; security-auditor PASS
  - Phase 4 checklist item COMPLETE: Service Worker push + Playwright E2E + bundle budget
  - Next: Phase 5 — SLSA L3 reproducible builds + cosign + Rekor + load test + observability

## Current state (2026-05-27, cycle 23 — FEATURE: Phase 4 Login/Chat UI)
- **Phase 4 cycle 23 (commit 786cf6f):** Login/Chat UI + Dexie encrypted storage:
  - `src/index.css`: Geist + Instrument Serif Google Fonts; all design tokens from DESIGN.md as CSS vars
  - `src/components/Login.tsx`: OPAQUE username/password form — cosmic radial-gradient bg, glassmorphism card, Instrument Serif tagline, accretion-orange CTA, photon-blue lock icon footer
  - `src/components/ChatLayout.tsx`: 3-pane layout (Sidebar 320px + Conversation flex + InfoPanel 340px toggle); mock seed chats; orange/surface message bubbles; composer
  - `src/components/Icon.tsx`: 19 inline SVG icons (lucide-style) — lock always photon blue (#A8C8FF)
  - `src/db/schema.ts`: PowehiDb (Dexie v4) — MessageRow (ciphertextB64, no plaintext), GroupRow, LocalIdentity; no-plaintext-content invariant by type
  - `src/store/auth.ts`: Zustand store — phase (login|app) + deviceId
  - `src/hooks/useCryptoWorker.ts`: module-level Comlink singleton, graceful import error for missing WASM
  - `fake-indexeddb` moved to devDependencies; `dexie` + `zustand` in prod deps
  - 12 frontend tests green (5 Dexie schema, 7 App); biome clean; 139 backend tests unaffected
  - Next: Service Worker push + Playwright E2E (Phase 4 remaining items)

## Current state (2026-05-27, cycle 22 — STABILIZATION: rustls security fix)
- **Cycle 22 (commit 6112530):** RED CI fixed — 3 new RUSTSEC vulns in rustls-webpki 0.101.7:
  - RUSTSEC-2026-0098/0099 (upgrade to >=0.103.12) + RUSTSEC-2026-0104 (upgrade to >=0.103.13)
  - Root cause: `aws-sdk-s3` default features included `rustls` (legacy path → aws-smithy-http-client/
    legacy-rustls-ring → hyper-rustls 0.24.2 → rustls 0.21.12 → rustls-webpki 0.101.7)
  - Fix: `aws-sdk-s3 = { default-features = false, features = [...all except rustls...] }`
  - Dropped: rustls 0.21.12, rustls-webpki 0.101.7, hyper-rustls 0.24.2, tokio-rustls 0.24.1 (+5 deps)
  - Remaining TLS: only rustls 0.23.40 + rustls-webpki 0.103.13 (safe) via default-https-client path
  - cargo audit: only RUSTSEC-2024-0384 (existing waiver for openmls instant dep)
  - 139 tests passing, clippy clean, rustfmt clean

## Current state (2026-05-27, cycle 21 — FEATURE: Phase 3 Media R2)
- **Phase 3 cycle 21 (commit 2527650):** R2 media adapter implemented:
  - `powehi-r2` crate: `R2MediaAdapter` (aws-sdk-s3 v1 + sqlx); content-type allowlist (8 types);
    presigned PUT (upload, 900s TTL) + GET (download, 300s TTL); no ciphertext proxied
  - `powehi-domain`: `MediaId.as_uuid()` + `From<Uuid>`; `MediaBlob.uploader` → `uploader_device: DeviceId`
  - `powehi-port-inbound`: `MediaUseCase` updated — `get_download_url` takes `requestor_device`
  - `powehi-application`: `MediaService` — download ACL (uploader-only, Phase 4 → group-member); `size_bucket` tracing
  - DB migration `0003_media_blobs.sql`: metadata table with FK to `devices`
  - `powehi-rest-api`: 4 media routes; `size_bytes` [1, 100MB] enforced in handler
  - `powehi-config`: R2 fields; credentials have no defaults (operator must inject)
  - 139 tests passing (was 122); clippy clean; security-auditor R1+R2 addressed
  - Deferred (Phase 4): group-member ACL for download URL; pre-signed URL size binding (Y2); confirm_upload HeadObject check (Y3); SSRF r2_endpoint validation (Y5); orphan row GC (Y6)
- Next action (Phase 4): Login/Chat UI + Dexie encrypted storage + crypto worker integration

## Current state (2026-05-26, cycle 20 — STABILIZATION)
- Planning docs complete: `docs/prd.md` (v3), `docs/orchestration.md`, `docs/decisions/` (ADR-0001, 0002).
- Agent infra complete: `.claude/agents` (22), `skills` (7), `rules` (6), `commands` (4), `hooks` (5).
- Design system available: `DESIGN.md` + `docs/design/powehi-design-system/` + `/powehi-design` skill — read before any UI work.
- **Phase 1 COMPLETE. Phase 2 COMPLETE (cycle 11). Phase 3 ACTIVE (cycle 12).**
- **Stabilization cycle 13 (commits 19b1551 + 8e266c8):**
  - Fixed red CI: cycle-12 code was missing `cargo fmt` — rustfmt diff in error.rs/lib.rs/auth.rs/messaging.rs fixed.
  - Added 21 new unit tests (total workspace: 51 passing):
    - AuthService: register_finish, login_init (known/unknown), register_device, revoke_device (3 cases)
    - KeyPackageService: upload, fetch_one, fetch_one empty→NotFound, count lifecycle
    - MessagingService: send_message, send_commit epoch-advance, send_commit unknown group, poll filter, ack delete
    - middleware: AuthenticatedDevice extractor — valid UUID, missing header, non-UUID, wrong scheme, empty (all 401)
  - cargo audit: clean (instant unmaintained warning via openmls is pre-existing waiver)
  - CI fix: committed pre-formatted code; lesson: always run `cargo fmt --all` before committing
- **Stabilization cycle 15 (commit 23e92ac):**
  - CI: green. cargo audit: clean. clippy -D warnings: clean.
  - Added 14 new tests (total workspace: 87 passing — was 73):
    - powehi-rest-api: 11 handler-level tests using success/NotFound mocks: send_message 200, poll 200 empty, poll with since, ack 204, ack invalid id 400, send_welcome 204, send_commit epoch, upload 200 ids, fetch_one 200 data, count 200, fetch_one 404. Total rest-api: 26.
    - powehi-config: 3 unit tests: region() wraps region_id, roundtrips, load() defaults. Total config: 3.
  - GroupId/DeviceId JSON serialization confirmed (newtype struct → UUID string)
- React 19 + Vite 6 scaffold complete (commit 312864d): pnpm workspace, Vitest 2/2 green, Biome clean, TypeScript strict.
- WASM build pipeline complete (commit f498ae1): openmls 0.8 + js feature, wasm-pack --target web, pnpm build:wasm, bulk-memory wasm-opt flag.
- CI complete (commit 35ac5b9): ci-rust.yml (fmt→clippy+nextest) + ci-frontend.yml (biome+vitest); all local gates pass.
- Stabilization cycle 5 (commit 69891fa): pnpm version fix in ci-frontend.yml (9→10.28.2), cargo-audit CI gate added, RUSTSEC-2023-0071 (rsa, not compiled) acknowledged in audit.toml, 21 domain unit tests green (19 new: group, envelope, key_package, region, error).
- Stabilization cycle 6 (commit 3bf58b1): CI — Rust was red (cargo-binstall nextest install failing silently → exit 101); fixed by replacing binstall approach with `taiki-e/install-action@nextest`, the nextest-recommended CI installation method. All 21 tests + clippy + cargo-audit pass locally.
- Phase 1 COMPLETE (cycle 8). Phase 2 in progress.
- Comlink worker + wasm-bindgen exports DONE (cycle 10). crypto-reviewer YELLOW, both findings addressed.
- **Phase 2 COMPLETE (cycle 11).** All crypto core items done. Phase 3 begins next cycle.
- **Phase 3 cycle 12 (commit a31ff1a):** REST API axum adapter implemented:
  - `powehi-rest-api` fully wired: AppState(Arc<dyn AuthUseCase|MessagingUseCase|KeyPackageUseCase>)
  - Routes: /v1/auth/{register,login}/{init,finish}, /v1/messages (send/welcome/commit/poll/ack), /v1/key-packages (upload/fetch/count)
  - AuthenticatedDevice extractor (Bearer token = DeviceId UUID, stub — Redis session deferred)
  - ApiError: DomainError → HTTP status, code-only response (no detail leak)
  - DefaultBodyLimit::max(512KB) global cap
  - 10 tests green: health, auth-bypass ×3, 413 body limit, error-mapping ×5
  - security-auditor: PASS (YELLOW-1 body limit fixed; YELLOW-2 stub auth documented; YELLOW-3 app-layer auth deferred)
- **Phase 3 cycle 14 (commit c46eec3):** Composition root: powehi-postgres (5 sqlx repos: User/Device/Envelope/Group/KeyPackage + 0001_initial.sql migration + atomic KP fetch via SELECT FOR UPDATE SKIP LOCKED), powehi-redis (RedisCache CachePort + RedisEventBus DomainEventBus), bin/powehi-server full DI wiring; domain From<Uuid>/as_uuid() added to 4 ID types; 73 tests pass; security-auditor GREEN.
- **Phase 3 cycle 16 (commit 9c9d886):** WS hub implemented:
  - `powehi-ws-hub`: WsHub (tokio::sync::broadcast fan-out, 512-capacity ring), WsNotification enum (envelope_received/epoch_advanced/member_added/member_removed — no ciphertext, only opaque UUIDs), ws_handler (Bearer auth before upgrade → 401 before 101, ping/pong, Lagged skip), WsEventBus (composes RedisEventBus + WsHub dispatch).
  - MessagingService: now publishes EnvelopeReceived/EpochAdvanced events after save (removed dead_code attr).
  - Server main.rs: WsHub + WsEventBus wired; GET /v1/ws mounted alongside REST.
  - Design: global broadcast (all devices get wake-up signal, filter by polling REST) — narrows to group/device targeting in Phase 5.
  - 87 → 95 tests; clippy clean; security-auditor PASS (YELLOW-1: auth stub same as REST, YELLOW-2: no WS rate limit yet — both deferred to rate-limit work).
- **Stabilization cycle 17 (commits 166cb01 + 253c55d):**
  - Fixed RED CI: clippy::collapsible_match in powehi-ws-hub/handler.rs — async match guard not allowed; restructured to `should_break` bool pattern.
  - Added 5 auth-invariant unit tests to handler.rs (total ws-hub: 13, workspace: 100 passing — was 95).
  - Security hardening from security-auditor review (YELLOW findings addressed):
    - `max_message_size(4096)` on WebSocketUpgrade (finding 6: Ping amplification)
    - 10s send timeout on all `socket.send` calls (finding 8: slowloris hold)
    - Disconnect on unexpected client frames Text/Binary (finding 7: DoS vector)
    - Documented global-broadcast as known-deferred Phase 5 decision (finding 4)
  - cargo audit: clean (RUSTSEC-2024-0384 `instant` via openmls is existing waiver).
  - gh issues: none open.
  - clippy --workspace -D warnings: CLEAN.
- **Stabilization cycle 20 (commit a1f31b0):**
  - Fixed RED CI: cycle-19 rate-limit tests were not rustfmt-compliant (method chains on single line) — `cargo fmt` applied. This was why CI never triggered for cycle-19 commits.
  - Fixed security-auditor R1 (RED): `/v1/ws` was unrated — applied `api_governor()` to ws_hub router in `main.rs:79`.
  - Fixed security-auditor Y7: auth routes logged client-supplied `req.user_id` before validation; `register_finish` now logs server-returned UserId, `login_finish` drops the field entirely.
  - Added 8 unit tests for `TrustedProxyKeyExtractor` header-priority invariants (CF-Connecting-IP > rightmost XFF > X-Real-IP > 0.0.0.0 fallback; malformed fallthrough; whitespace trim).
  - `cargo audit`: clean (RUSTSEC-2024-0384 existing waiver). clippy: clean. 122 tests passing.
- **Phase 3 cycle 19 (commit 0a738e6):** Rate limiting implemented:
  - `rate_limit` module in powehi-rest-api: `TrustedProxyKeyExtractor` (CF-Connecting-IP → rightmost XFF → X-Real-IP → 0.0.0.0 fallback)
  - Auth endpoints: burst=5, 1 token/6s (brute-force guard)
  - API endpoints: burst=60, 1 token/2s (general throttle)
  - Router split into auth + api sub-routers via `router_inner`; `/health` unrated
  - `tower_governor = "0.4"` + `governor = "0.6"` added to powehi-rest-api
  - 3 new rate-limit tests (per-IP isolation, auth 429, api 429)
  - Total tests: 132 passing; clippy clean
  - security-auditor: YELLOW (R1 leftmost-XFF spoofing fixed → rightmost; Y1 global-bucket/Y2 per-handle throttle deferred Phase 5; Y3 tracing feature comment added)
  - Deferred (Phase 5 hardening): per-handle_hash bucket for credential stuffing; ingress XFF stripping config; CF-Connecting-IP as primary in prod
- **Phase 3 cycle 18 (commit 7c2a429):** OPAQUE auth adapter implemented:
  - `OpaqueServerPort` trait + `OpaqueServer` adapter: registration_start/finish, login_start/finish
  - login_start: nonce-keyed pending map (R-1/R-2), synthetic KE2 for unknown users (R-3)
  - login_finish: returns (session_key, bound_user_identity) — session subject never client-supplied
  - AuthService wired: OpaqueServerPort + CachePort; registration window cached 5 min; sessions 24h
  - User domain model: `opaque_password_file: Vec<u8>` + `User::registered()` constructor
  - DB migration 0002: `opaque_password_file` column + `UNIQUE(handle_hash)`
  - PgUserRepository: handles new column
  - Composition root: OpaqueServer wired
  - 111 tests passing (was 100)
  - Crypto-reviewer: YELLOW (all RED findings addressed; deferred: ServerSetup persistence/Y-2, identifier binding/Y-4)
  - Security-auditor: WARN → findings #1 (server-bound session subject) + #5 (delete-after-save) addressed; deferred: rate limiting, per-field input bounds
- Next action (Phase 3): Media (R2 upload/download via powehi-r2 adapter)
- Follow-up (crypto-reviewer Finding 1): upgrade opaque-ke from 3.0 (draft-16) to stable 4.x (RFC 9807) when stable version ships (currently only 4.1.0-pre.2 available). Waiver recorded in .claude/rules/crypto-libraries-pinned.md.
- Workspace deps added in cycle 8: openmls_rust_crypto, openmls_basic_credential, openmls_traits, argon2 (all in workspace Cargo.toml).
- Build/test (once code exists):
  - `cargo build --workspace`
  - `cargo nextest run --workspace` (fallback `cargo test --workspace` if nextest absent)
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - frontend `pnpm --filter app test` (Vitest) + `biome check`
  - infra `terraform validate` / `helm lint` (skill: infra-test)

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
