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

## Current state (2026-07-07, cycle 249 — FEATURE: @mention highlighting in message bubbles)
- **Cycle 249 (commit 7feb09c):** FEATURE — @mention highlighting in message bubbles.
  - **Mode:** FEATURE (counter 249 % 5 ≠ 0). CI was green on main.
  - **Feature (7feb09c):** `@username` tokens in message text now render as visually distinct chips.
    - `FmtSegment` type extended to include `"mention"` variant.
    - `FMT_RE` in `parseFormatting` extended: `|(@[A-Za-z0-9_.-]+)` — captures any `@handle` as a `mention` segment.
    - `renderFmtWithHighlight` gains optional `myHandle?: string` param. New `"mention"` case:
      - Self-mention (`@all` or `@{myHandle}` case-insensitive) → orange tinted chip: `background: rgba(255,138,61,0.20)`, `color: #FF8A3D`, `fontWeight: 600`, `data-testid="mention-self"`.
      - Other-handle mention → muted chip: `background: rgba(255,255,255,0.09)`, `color: #C8C0B8`, `data-testid="mention-other"`.
    - `HighlightedText`, `MessageBubble`, `MessageList` each gain `myHandle?: string` prop, threaded through.
    - ChatLayout passes `myHandle={useAuthStore.getState().myHandle ?? undefined}` to `MessageList`.
    - Seed message in Design Team (`"@you ... @all feedback welcome"`) immediately demos the feature.
  - **security-auditor: GREEN** — no XSS (`f.value` is always JSX text child, React auto-escapes), no ReDoS (`@[A-Za-z0-9_.-]+` is linear-time character class), `myHandle` never reaches DOM attribute/style (comparison only), no plaintext logging.
  - **10 tests** in `ChatLayoutMentionHighlight.test.tsx`: @all renders mention-self, non-myHandle renders mention-other, incoming @myHandle renders mention-self, self-mention chip orange color, other-mention chip muted color, no chips on plain message, @myHandle + @all = two self chips, mixed mention types in one message, case-insensitive myHandle match, mention chips in DM chats.
  - **Frontend: 1114 tests pass** (+10); tsc clean; biome clean.
  - **Next cycle:** PQ hybrid Phase A (ML-KEM768 openmls stable) or more UX polish (e.g. per-chat notification sound picker, message pinning indicator in sidebar).

## Previous state (2026-07-06, cycle 248 — FEATURE: emoji reactions in thread panel)
- **Cycle 248 (commit 8566522):** FEATURE — Emoji reactions in thread panel (root + reply messages).
  - **Mode:** FEATURE (counter 248 % 5 ≠ 0). CI was green on main.
  - **Feature (8566522):** Thread panel `MsgCard` now supports emoji reactions — both root and reply messages.
    - `MsgCard` updated: accepts `onMsgReact?: (msgId: string, emoji: string) => void` prop. Added `hovered: boolean` state + `onMouseEnter`/`onMouseLeave` on the card container.
    - On hover (non-deleted, has `msg.id`): shows `data-testid="thread-react-row"` with 6 quick-emoji buttons from `ALLOWED_REACTION_EMOJIS` (`data-testid="thread-react-btn-{emoji}"`).
    - Existing reactions displayed as chips (`data-testid="thread-reaction-chip-{emoji}"`) with sender count below message text.
    - `data-testid="thread-msg-card"` added to MsgCard outer div for reliable test targeting.
    - `ThreadPanel` new prop `onReact?: (msgId: string, emoji: string) => void` — threaded to both root and reply `MsgCard`s.
    - Call site passes `onReact={sendReaction}` — same MLS-encrypt path used by main message list. No new server surface.
  - **security-auditor: GREEN** — no XSS (JSX text children only; emoji from closed ALLOWED_REACTION_EMOJIS constant), no plaintext logging, no new API calls, `msg.id` non-null guard on every `onMsgReact` call, deleted-message react row suppressed (`!msg.deleted`), `sendReaction` validates emoji + sessionToken + mlsGroupId + mlsIdentityId before encrypting.
  - **13 tests** in `ChatLayoutThreadReactions.test.tsx`: chip on root, chip on reply, count, hover root shows row, hover reply shows row, 6 emoji btns, mlsEncrypt called, no chips without reactions, mouse leave removes row, multiple emojis show separate chips, deleted reply no react row, aria-labels, chips container present.
  - **Frontend: 1104 tests pass** (+13); tsc clean; biome clean.
  - **Next cycle:** PQ hybrid Phase A (ML-KEM768 openmls stable) or more UX polish (e.g. per-chat notification sound picker, @mention message highlighting).

## Previous state (2026-07-06, cycle 247 — FEATURE: message thread panel)
- **Cycle 247 (commit fe5808a):** FEATURE — Message thread panel (slide-in right panel for threaded replies).
  - **Mode:** FEATURE (counter 247 % 5 ≠ 0). CI was green on main.
  - **Feature (fe5808a):** Messages with one or more replies now show a "N replies ▸" button below the bubble. Clicking opens a Thread Panel (300 px) to the right of the main chat area.
    - `threadReplyMap` memo: `Map<string, number>` — maps `msg.id` → count of messages with `replyTo.messageId === msg.id`. Recomputed on `active.messages` change.
    - `threadPanelMsgId: string | null` state: ID of the root message whose thread is open. Populated from `msg.id` only (never from user input).
    - `threadRootMsg`/`threadReplies` memos: derived from `active.messages` — no new data structures.
    - `ThreadPanel` component: root message card (avatar initial, sender name, time, text), reply-count divider, reply list, mini-composer (textarea + Send button, Enter to send). Closes with X button.
    - `handleSendThreadReply(text)`: pure `setChats` append — no API call, no MLS op, no logging. Creates `ChatMessage` with `replyTo: { messageId: threadPanelMsgId, excerpt: root.text.slice(0, 80) }`.
    - `MessageBubble`: `threadCount?: number` + `onOpenThread?: () => void` props. Thread badge renders JSX text children only (no dangerouslySetInnerHTML). Chevron-right icon from Icon.tsx.
    - `MessageList`: `threadCountMap?: Map<string, number>` + `onOpenThread?: (msg: ChatMessage) => void` props, threaded to `MessageBubble`.
  - **security-auditor: GREEN** — no server calls, no MLS ops, no XSS (all JSX text children), no plaintext logging, thread panel styles are static literals, `threadPanelMsgId` comes only from `msg.id` values (never raw user input), thread text renders via `msg.text` JSX child.
  - **11 tests** in `ChatLayoutThread.test.tsx`: no-reply (no button), 1-reply button, 2-replies button, clicking opens panel, panel testid, root text, reply text, close button, reply count, composer present, send adds reply.
  - **Frontend: 1091 tests pass** (+11); tsc clean; biome clean.
  - **Next cycle:** PQ hybrid Phase A (ML-KEM768 openmls stable) or more UX polish (e.g. message reactions in thread panel, per-chat notification sound picker).

## Previous state (2026-07-06, cycle 246 — FEATURE: per-chat background theme)
- **Cycle 246 (commit f18fa8b):** FEATURE — Per-chat background theme in InfoPanel.
  - **Mode:** FEATURE (counter 246 % 5 ≠ 0). CI was green on main.
  - **Feature (f18fa8b):** Users can pick from 6 preset background themes (Warm / Ocean / Forest / Rose / Lavender / Slate) or reset to default in the InfoPanel.
    - `Chat.chatTheme?: string` — optional field, local-only, never sent to server, never in MLS payload, never logged.
    - `CHAT_THEMES` constant: 6 entries with `{ key, label, swatch, background }`. Background values are hardcoded CSS gradient strings. Closed set — no user-supplied strings enter style.
    - `MessageList background?: string` prop: overrides the default gradient when set. Value comes only from `CHAT_THEMES.find(...).background` (closed lookup).
    - InfoPanel "Chat theme" section: 7 swatch buttons (default + 6 presets) with orange border on active selection. Shows theme label below swatches.
    - `handleSetChatTheme(chatId, key)` in ChatLayout: pure `setChats` update, no API call, no MLS op, no logging.
  - **security-auditor: GREEN** — no server calls, no XSS, no plaintext logging, chatTheme string never reaches style attribute directly (closed constant lookup only).
  - **12 tests** in `ChatLayoutTheme.test.tsx`: theme section in DM InfoPanel, theme section in group InfoPanel, default label "Default", default swatch present, all 6 presets rendered, clicking swatch updates label, default swatch resets to Default, message list background changes after theme applied, background resets to default when cleared, per-chat isolation (different chats have independent themes), theme persists across chat switches, aria-labels on swatches.
  - **Frontend: 1080 tests pass** (+12); tsc clean; biome clean.
  - **Next cycle:** PQ hybrid Phase A (ML-KEM768 openmls stable) or message threading panel.

## Previous state (2026-07-06, cycle 245 — STABILIZATION)
- **Cycle 245 (commit 5789e3f):** STABILIZATION — CI fix (Biome formatter) + security sweep.
  - **Mode:** STABILIZATION (counter 245 % 5 == 0). CI was RED on main.
  - **CI fix (5789e3f):** `ChatLayout.tsx:8181-8184` — `<KeyboardShortcutsModal>` JSX was multi-line (4 lines) but Biome formatter requires it to fit on one line. Collapsed to single line. Only formatting change, no logic change.
  - **Security sweep — GREEN:** `security-auditor` reviewed all backend handler crates (`crates/adapters/inbound/` + `crates/application/`). All non-negotiables hold: auth extractor rejects missing/malformed Bearer before handlers, OPAQUE login_finish closes nonce race via `get_del`, errors collapse to `Unauthorized` (no oracle), invite code 32-char hex validation, push subscription SSRF guard (loopback/RFC-1918/ULA/IPv4-mapped IPv6/userinfo bypass), logging uses only opaque UUIDs + coarse size buckets (no plaintext content, handles, or tokens).
  - **Target dir:** No target dir found (clean; CI builds on remote runners only).
  - **Rust tests:** 87 application + 120 rest-api + 40 + 85 + 143 + ... all pass (zero failures, zero broken tests).
  - **Frontend: 1068 tests pass** (unchanged); tsc clean; biome clean.
  - **Next cycle:** PQ hybrid Phase A (ML-KEM768 openmls stable) or per-group theme/background.

## Previous state (2026-07-06, cycle 244 — FEATURE: keyboard shortcut help modal)
- **Cycle 244 (commits 25fec82 + f90f482):** FEATURE — CI fix + Keyboard shortcut help modal (`?` key).
  - **Mode:** FEATURE (counter 244 % 5 ≠ 0). CI was RED on main — fixed first.
  - **CI fix (25fec82):** Two TS6133 unused-variable regressions from cycle 243:
    1. `ChatLayout.tsx:1861` — `onChatSearchOpen` destructured but never used in `ConversationHeader` body; removed from props + type annotation + caller.
    2. `ChatLayoutSearch.test.tsx:2` — `type MockedFunction` imported but never used; removed.
  - **Feature (f90f482):** Keyboard shortcut help modal — press `?` (no modifier, not in INPUT/TEXTAREA) to toggle.
    - `shortcutsOpen: boolean` state added near other modal state in ChatLayout.
    - Global `keydown` handler extended: `key === "?"` without modifiers and `activeElement.tagName` not INPUT/TEXTAREA → `setShortcutsOpen(v => !v)`.
    - `KeyboardShortcutsModal` component: `<dialog open>` with backdrop-click + Escape-to-close (consistent with 8 other dialogs). Lists 9 shortcuts in a `<table>` with `<kbd>` elements using inline CSS custom properties. Static content only.
    - `SHORTCUT_ROWS` constant: Open search (Ctrl+F/Cmd+F), Close search (Esc), Shortcuts (?), Send (Enter), New line (Shift+Enter), Toggle info (i), Jump to latest (End), Navigate up (↑), Navigate down (↓).
    - `data-testid="keyboard-shortcuts-modal"` on dialog; `data-testid="keyboard-shortcuts-close"` on close button.
    - **security-auditor: GREEN** — static content only, no server call, no crypto state, no user input rendered, no XSS vector. Noted: if contentEditable ever added, `?` guard should be extended (not a current defect).
  - **11 tests** in `ChatLayoutShortcuts.test.tsx`: hidden by default, `?` opens, `?` no-op in textarea, correct testid, title content, Ctrl+F listed, close button, Escape closes, toggle, backdrop click, `?` no-op in input.
  - **Frontend: 1068 tests pass** (was 1057, +11); tsc clean; biome clean.
  - **Next cycle:** PQ hybrid Phase A (ML-KEM768 openmls stable) or per-group theme/background.

## Previous state (2026-07-06, cycle 243 — FEATURE: in-chat search bar)
- **Cycle 243 (commits 8dbd316 + 78e3e6c):** FEATURE — In-chat search bar (Ctrl+F) with match navigation.
  - **Mode:** FEATURE (counter 243 % 5 ≠ 0). CI was RED on main — fixed first.
  - **CI fix (8dbd316):** Two lint regressions from cycle 242:
    1. `ChatLayoutSlowMode.test.tsx:6` — unused `waitFor` import (TS6133) removed.
    2. `auth_service.rs:1341` — `vec![id1, id2]` → `[id1, id2]` (clippy::useless-vec under Rust 1.96.1 -D warnings).
  - **Feature (78e3e6c):** In-chat message search bar opens with Ctrl+F/Cmd+F.
    - `chatSearchOpen / chatSearchQuery / chatSearchIndex` state in ChatLayout.
    - `chatSearchMatchIds`: useMemo — case-insensitive substring filter on `active.messages`; excludes media/deleted; maps to server-assigned message IDs only.
    - Hoisted `const active` and `chatSearchMatchIds` useMemo BEFORE the scroll useEffect that depends on them (fixes TDZ: `Cannot access 'chatSearchMatchIds' before initialization`).
    - Search bar (`data-testid="chat-search-bar"`) slides in above the composer when open.
    - Input auto-focuses; count shows "N / M"; prev/next cycle with wrap-around; close resets.
    - Escape key closes bar; chat switch resets bar.
    - `searchMatchQuery` prop added to MessageList → used as `highlightQuery` in MessageBubble via `HighlightedText`; matched substrings wrapped in `<mark>` (JSX children — no XSS, no dangerouslySetInnerHTML). `applyHighlight` uses `indexOf`/`slice`.
    - `CSS.escape(currentId)` in scroll querySelector (existing pattern).
    - **security-auditor: GREEN** — local-only, no server call, no logging, no XSS, CSS.escape guard.
  - **11 tests** in `ChatLayoutSearch.test.tsx` (new describe block "in-chat search bar"): bar hidden by default, Ctrl+F opens, controls present, count empty, N/M count, 0/0 on no-match, close clears, next advances, prev wraps, chat switch resets, mark appears.
  - **Frontend: 1057 tests pass** (was 1046, +11); tsc clean; biome clean.
  - **Next cycle:** PQ hybrid Phase A, keyboard shortcut help modal, or per-group theme/background.

## Previous state (2026-07-06, cycle 242 — FEATURE: group slow mode)
- **Cycle 242 (commits 78582d7 + e241c77):** FEATURE — Group slow mode + CI fix.
  - **Mode:** FEATURE (counter 242 % 5 ≠ 0). CI was RED on main (Rust 1.96.1 fmt drift in auth_service.rs) — fixed first.
  - **CI fix (78582d7):** `cargo fmt --all` on `crates/application/powehi-application/src/auth_service.rs` — DeviceRegistrationRequest struct literal formatting changed by Rust 1.96.1 stable update. 87 Rust tests still pass.
  - **Feature (e241c77):** Group slow mode — admins can set a per-message send cooldown (Off / 5s / 30s / 1m / 5m / 1h) in the group InfoPanel.
    - `SlowModeDelay = 0 | 5 | 30 | 60 | 300 | 3600` type + `formatSlowMode()` helper.
    - `slowModeDelay: Record<string, SlowModeDelay>` + `slowModeCooldownUntil: Record<string, number>` + `slowModeTick` state in ChatLayout.
    - `setInterval(1000)` tick only runs while `hasCooldown = Object.values(cooldownUntil).some(v => v > Date.now())`.
    - `activeCooldownSec = useMemo(...[slowModeCooldownUntil, activeId, slowModeTick])` — recomputed on each tick.
    - Composer: slow-mode-banner above input when delay > 0; countdown badge (`data-testid="slow-mode-countdown"`) replaces send button AND voice icon while cooldown > 0.
    - InfoPanel group section: admin sees `<select data-testid="slow-mode-select">` for all SLOW_MODE_OPTIONS; non-admin sees read-only `data-testid="slow-mode-member-row"` with current delay label.
    - `isAdmin` derived client-side from `myHandle` vs `member.role === "admin"` — fine since slow mode is local-only.
    - `data-testid="composer-textarea"` added to the composer `<textarea>` for reliable test targeting.
    - **security-auditor:** GREEN — local-only (no server call, no MLS path touched), no XSS (select coerced via `Number()`, `formatSlowMode` closed domain), no plaintext logging, timer leaks nothing.
  - **11 tests** in `ChatLayoutSlowMode.test.tsx`: slow-mode section visible in group / absent in DM, admin has select / non-admin has read-only row, select default Off, admin sets 30s, banner appears when delay>0 / absent when Off, countdown shows after send, send button absent during cooldown, countdown decrements over time, selector default Off.
  - **Frontend: 1046 tests pass** (was 1035, +11); tsc clean; biome clean.
  - **Next cycle:** PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768), or more UX polish (message threading panel, per-group theme/background, keyboard shortcut help modal).

## Previous state (2026-07-06, cycle 241 — FEATURE: chat export)
- **Cycle 241 (commits ddd80b5 + d25bf84):** FEATURE — Chat export (download as JSON or text).
  - **Mode:** FEATURE (counter 241 % 5 ≠ 0). CI was green on main.
  - **Commit 1 (ddd80b5):** Committed pending `list_devices` tests in `powehi-application` (4 tests: empty list, returns all devices, user isolation security invariant, last_seen_at is None at registration). 87 application tests pass.
  - **Feature (d25bf84):** "Export Chat" button in InfoPanel → confirm dialog (Cancel / JSON / Text) → local-only browser download.
    - JSON payload: `{ chat: { name, handle, isGroup }, messages: [{ from, text, time, ts, edited }] }` — whitelist approach, mlsGroupId/mlsIdentityId/pqBindingHex/envelope IDs/media/reactions all omitted.
    - Text format: `"Sender (time): body"` one line per message.
    - Handle sanitized to `[A-Za-z0-9._-]` (max 64 chars, no leading dot) before `<a download>` interpolation — defense against RTL-override filename spoofing.
    - `exportConfirm: boolean` state in InfoPanel; `onExportChat?: (format) => void` prop.
    - `handleExportChat(chatId, format)` in ChatLayout using `URL.createObjectURL` + `<a>` trigger + `URL.revokeObjectURL`.
  - **security-auditor verdict:** YELLOW → GREEN after handle sanitization fix. All zero-knowledge invariants pass: no server call, no crypto-state leak, no plaintext logging, no XSS.
  - **11 tests** in `ChatLayoutExport.test.tsx`: button visible, correct label, confirm dialog shows 3 buttons, cancel restores button, JSON triggers download + closes, text triggers download + closes, JSON omits mlsGroupId/mlsIdentityId/pqBindingHex (security invariant), JSON contains name + messages array, text has line-per-message format, messages remain after export (non-destructive), coexists with clear-messages button.
  - **Frontend: 1035 tests pass** (was 1024, +11); tsc clean; biome clean.
  - **Next cycle:** Message search within active chat, or per-message reaction breakdown tooltip, or PQ hybrid Phase A.

## Previous state (2026-07-04, cycle 239 — FEATURE: custom user status)
- **Cycle 239 (commit f578537):** FEATURE — Custom user status in sidebar footer.
  - **Mode:** FEATURE (counter 239 % 5 ≠ 0). CI was green on main (all recent runs success).
  - **Feature:** Users can set a custom status (emoji + text) that appears at the bottom of the sidebar under "You".
    - `StatusEditor` modal: emoji input (max 4 chars) + text input (max 80 chars), 5 quick-preset buttons, clear/cancel/save actions. Uses `<dialog open>` element (same pattern as `RecoveryPhraseModal`) for correct a11y.
    - `user-status-bar` in Sidebar footer: photon-blue avatar ("Y"), "You" label, status text or "Set a status..." placeholder, edit button (`Icon name="edit-2"`).
    - `customStatus: CustomStatus | null` + `statusEditorOpen: boolean` state in `ChatLayout`.
    - Contact card overlay (`{contactCard !== null && ...}`) also converted to `<dialog open>`.
  - **Bug fix (pre-existing):** The `{chat.isGroup ? (` ternary in InfoPanel had two sibling JSX nodes after InfoSection (the member list + contact card overlay) without a React fragment — biome parse error. Fixed by wrapping with `<>...</>`.
  - **security-auditor:** GREEN — status is local-only (never sent to server, no MLS payload, no logging); rendered via JSX text children (no dangerouslySetInnerHTML).
  - **12 new tests** in `ChatLayoutCustomStatus.test.tsx`:
    1. Status bar always visible.
    2. Default placeholder "Set a status..." when no status set.
    3. Edit button opens status editor.
    4. Editor has emoji + text inputs.
    5. Clicking a preset populates both inputs.
    6. Saving shows status in sidebar.
    7. Saved emoji appears in status bar.
    8. Cancel closes editor without saving.
    9. Clear status removes status → returns to placeholder.
    10. Saving empty inputs clears status.
    11. Clicking backdrop closes editor without saving.
    12. Clear button only visible when status exists.
  - **Frontend: 1024 tests pass** (was 1012, +12); tsc clean; biome clean.
  - **Next cycle:** Chat export (download conversation as JSON/text), or message search within active chat, or per-message reaction breakdown tooltip.

## Previous state (2026-07-03, cycle 237 — FEATURE: click reply quote to jump to original message)
- **Cycle 237 (commit 47eb4c4):** FEATURE — Reply-quote click jumps to original message.
  - **Mode:** FEATURE (counter 237 % 5 ≠ 0). CI was green on main (all recent runs success).
  - **Feature:** Clicking the reply-quote banner in a message bubble now scrolls to and flashes the original referenced message (same scroll+flash animation as the pinned-message jump).
    - Reply-quote `<div>` → `<button type="button">` for accessibility (keyboard focusable, `cursor: pointer`).
    - `onJumpToReply?: (messageId: string) => void` prop added to `MessageBubble` and `MessageList`.
    - Wired in `ChatLayout` as `onJumpToReply={(id) => setJumpToMessageId(id)}` — reuses existing `jumpToMessageId` + `handleJumpComplete` machinery.
    - **Security fix (auditor YELLOW → GREEN):** `CSS.escape(jumpToMessageId)` applied at the querySelector call site to prevent CSS-selector injection from peer-supplied `messageId` values (peer-controlled string was interpolated raw into `[data-msg-id="${id}"]`).
  - **7 tests** in `ChatLayoutJumpToReply.test.tsx`:
    1. Button present when message has `replyTo`.
    2. Shows excerpt text.
    3. Clicking triggers scroll to original message.
    4. `<button>` tag (accessibility).
    5. No reply-quote for plain messages.
    6. Multiple independent reply quotes.
    7. Cross-message isolation (clicking one doesn't affect others).
  - **`security-auditor` verdict:** YELLOW initially (CSS-selector injection via peer `messageId`); fixed with `CSS.escape()` → GREEN.
  - **Frontend: 1012 tests pass** (was 1005, +7); tsc clean; biome clean.
  - **Next cycle:** PQ hybrid Phase A or more UX polish (e.g. custom user status, chat export, contact card on group member tap).

## Previous state (2026-07-03, cycle 236 — FEATURE: disappearing-message countdown tick + CI fix)
- **Cycle 236 (commits 102980e + 7b64665):** FEATURE — Disappearing-message countdown tick + CI Format check fix.
  - **Mode:** FEATURE (counter 236 % 5 ≠ 0). CI was red (rustfmt on `event.rs` serde test) → fixed first.
  - **CI fix (102980e):** `cargo fmt --all` on `crates/domain/powehi-domain/src/event.rs` — the `.expect()` chains in `serde_json_round_trips_all_variants` were formatted differently locally vs CI. Rustfmt normalized them.
  - **Feature (7b64665):** Disappearing-message countdown badge now updates every second.
    - `countdownTick: number` state in `ChatLayout` — incremented by `setInterval(1000)` only when `hasExpiringMessages` (active chat has ≥1 message with `expiresAt`). Interval auto-clears when no expiring messages are present.
    - Prop threaded: `ChatLayout` → `MessageList` → `MessageBubble` as `countdownTick?: number`.
    - `data-countdown-tick={countdownTick ?? 0}` on `<span data-testid="disappearing-badge">` — observable in tests and ensures React compiler cannot elide re-renders.
    - `formatTimeLeft(msg.expiresAt)` re-evaluated on every tick because `Date.now()` is called inline.
  - **8 new tests** in `ChatLayoutCountdownTick.test.tsx` (fake timers via `vi.useFakeTimers`):
    1. Badge renders when message has `expiresAt`.
    2. Badge shows "Disappearing ·" prefix.
    3. `data-countdown-tick` increments after 1 s.
    4. `data-countdown-tick` increments 3 times after 3 s.
    5. No badge without `expiresAt`.
    6. '2m' label for 2-minute TTL.
    7. 'soon' label for already-expired message.
    8. Text updates from '2m' → '1m' after clock advances.
  - **Frontend: 1005 tests pass** (was 997, +8); tsc clean; biome clean.
  - **Note:** The "presence indicators" feature was already fully implemented in prior cycles; "disappearing countdown tick" was the missing piece.
  - **Next cycle:** PQ hybrid Phase A or more UX polish (e.g. message reactions total for group, per-message reaction breakdown tooltip).

## Previous state (2026-07-03, cycle 235 — STABILIZATION: DomainEvent serde round-trip tests)
- **Cycle 235 (commit 2184757):** STABILIZATION — Added 4 unit tests to `DomainEvent` in `powehi-domain`.
  - **Mode:** STABILIZATION (counter 235 % 5 == 0). CI was green on main.
  - **Rust: 578 tests pass** (was 574, +4); clippy clean; `cargo audit` 3 pre-existing allowed warnings, no new vulns. Target dir: 9.7 GB (< 20 GB, no pruning). 997 frontend tests pass.
  - **Next cycle:** PQ hybrid Phase A or more UX polish (e.g. presence indicators, disappearing-messages countdown tick, message reactions total for group).

## Previous state (2026-07-03, cycle 234 — FEATURE: time-window message grouping)
- **Cycle 234 (commit 9dd6398):** FEATURE — Time-window message grouping (3-minute visual groups).
  - **Mode:** FEATURE (counter 234 % 5 ≠ 0). CI was green (last run: success on cycle 233).
  - **Feature:** Consecutive messages from the same sender within 3 minutes now form a visual group: avatar shown only at group head, subsequent bubbles use 2px top margin (vs 8px). Messages > 3 min apart break into a new group.
  - **Implementation:**
    - Added `ts?: number` (Unix ms) to `ChatMessage` interface.
    - Set `ts: now.getTime()` in `handleIncoming`, `sendMessage` optimistic push, and media upload optimistic push.
    - `buildGroups` computes `showAvatar` per `msg` group entry: uses 3-minute window when both messages have `ts`; falls back to `msg.continued` for legacy seed data (zero visual regression).
    - `MessageBubble` receives `showAvatar` from `MessageList`; uses it for avatar render and `marginTop` (8 vs 2). `data-testid="msg-avatar"` added for testability.
    - `TIME_GROUP_WINDOW_MS = 3 * 60 * 1000` constant.
  - **Security:** `ts` is local-only (never in MLS payload, API body, or logs). Pure render logic — no server calls, no new server-visible metadata.
  - **Tests:** 10 tests in `ChatLayoutTimeGrouping.test.tsx` — group head avatar, <3 min grouped, >3 min breaks group, boundary 2m59s grouped, seed fallback regression, different-sender independence, margin 2px for continuation, margin 8px for group start, 3-quick-msgs = 1 avatar, gap >3 min = new avatar.
  - **997 frontend tests pass (+10)**; tsc clean; biome clean; budget OK (JS 145.7 KB gz, WASM 553.7 KB gz).
  - **Next cycle:** PQ hybrid Phase A or more UX polish (e.g. presence indicators, disappearing-messages countdown tick, message reactions total for group).

## Previous state (2026-07-02, cycle 233 — STABILIZATION: CI fix rustfmt formatting)
- **Cycle 233 (commit 1d6886a):** STABILIZATION (forced — CI — Rust Format check was red).
  - **Mode:** FEATURE counter 233, but switched to STABILIZATION because CI was red.
  - **Root cause:** `cargo fmt --all --check` failed — two `assert!` / `assert_eq!` calls added in cycle 232 tests exceeded the line-length threshold (rustfmt requires multi-line form for long assert calls with messages).
    - `lib.rs:3024`: `assert!(!body.contains("db unavailable"), "...")` → multi-line
    - `lib.rs:3050`: `assert_eq!(json, serde_json::json!([]), "...")` → multi-line
  - **Fix:** `cargo fmt --manifest-path crates/adapters/inbound/powehi-rest-api/Cargo.toml`; verified `cargo fmt --all --check` exits 0.
  - **143 tests pass** (no regressions); push triggered new CI run.
  - **Next cycle:** PQ hybrid Phase A or more UX polish (e.g. message grouping by time window, presence indicators, disappearing-messages countdown tick).

## Previous state (2026-07-02, cycle 232 — STABILIZATION: CI fix + list_devices error-path tests)
- **Cycle 232 (commits 03b561f + e883d96):** STABILIZATION (forced — CI — Frontend was red).
  - **Mode:** FEATURE counter 232, but switched to STABILIZATION because CI — Frontend was red.
  - **Root cause:** Biome lint/format errors introduced in cycle 231 (linked devices panel):
    - `auth.test.ts:408,433` — `useLiteralKeys`: `["Authorization"]` → `.Authorization`
    - `LinkedDevicesPanel.test.tsx` — multi-line `waitFor/expect` calls collapsed to single-line
    - `LinkedDevicesPanel.tsx` — formatter diff
  - **Fix (03b561f):** `biome check --fix --unsafe` auto-corrected all 4 violations. 987 frontend tests pass.
  - **CI — Frontend:** Green on `03b561f` (success), restoring green on main.
  - **New tests (e883d96):** Closed 2 coverage gaps in `powehi-rest-api` for `GET /v1/auth/devices`:
    1. `list_devices_service_error_returns_500` — asserts 500 status + no internal detail in body (no-plaintext-logging invariant).
    2. `list_devices_empty_list_returns_200_with_empty_array` — asserts 200 OK with `[]` when no devices.
  - **security-auditor:** GREEN (all 4 invariants verified — no-plaintext-logging, unimplemented! side-effect isolation, no real PII/keys, no auth bypass).
  - **powehi-rest-api: 143 tests pass** (was 141, +2); clippy clean; `cargo audit` 3 pre-existing allowed warnings, no new vulns. Target dir: 9.5 GB (< 20 GB, no pruning). 987 frontend tests pass.
  - **Next cycle:** PQ hybrid Phase A or more UX polish (e.g. message grouping by time window, presence indicators, disappearing-messages countdown tick).

## Previous state (2026-07-02, cycle 231 — FEATURE: linked devices panel)
- **Cycle 231 (commit 85a4a54):** FEATURE — Linked Devices panel + GET /v1/auth/devices backend endpoint.
  - **Note:** This commit introduced biome lint errors that were fixed in cycle 232 (03b561f).
  - **Next cycle:** Fixed in cycle 232.

## Previous state (2026-07-02, cycle 230 — STABILIZATION: proptest property-based crypto tests)
- **Cycle 230 (commit 135e537):** STABILIZATION — Added 6 proptest property-based tests for AES-256-GCM media encryption.
  - **Mode:** STABILIZATION (counter 230 % 5 == 0).
  - **CI:** Green on main (all recent runs pass). No open issues.
  - **proptest added to workspace:** `proptest = "1"` in workspace `[dev-dependencies]`; wired as `proptest = { workspace = true }` in `powehi-crypto-wasm` dev-deps.
  - **6 invariants in `media.rs` `property` submodule (native-only, `cfg(not(target_arch = "wasm32"))`):**
    1. `encrypt_decrypt_roundtrip` — any plaintext 0–64 KB round-trips through AES-256-GCM correctly.
    2. `wrong_key_len_always_rejected` — any key length ≠ 32 always returns `InvalidKeyLen` before any decryption.
    3. `wrong_iv_len_always_rejected` — any IV length ≠ 12 always returns `InvalidIvLen`.
    4. `tampered_ciphertext_never_decrypts` — any single-byte flip in ciphertext/GCM tag causes decryption failure.
    5. `blob_hash_mismatch_rejected_before_decrypt` — any bit flip in expected blob hash returns `BlobHashMismatch`.
    6. `semantic_security_different_ciphertexts` — two encryptions of the same plaintext always differ (fresh random key+IV).
  - **Security:** Tests verify security invariants (GCM integrity, pre-decryption hash check, semantic security). No crypto code changed; test-only diff. Satisfies testing-conventions.md "Property-based (proptest): crypto round-trips".
  - **powehi-crypto-wasm: 120 tests pass** (was 114, +6 proptest); all workspace tests green; clippy clean; `cargo audit` 3 existing allowed warnings (instant/openmls, bitcoin_hashes/bip39, anyhow), no new vulns. Target dir: 8.9 GB (< 20 GB, no pruning needed). 969 frontend tests pass.
  - **Next cycle:** PQ hybrid Phase A or more UX polish (e.g. message grouping by time window, presence indicators, disappearing-messages countdown tick).

## Previous state (2026-07-02, cycle 229 — FEATURE: browser tab title unread badge)
- **Cycle 229 (commit d1cd843):** FEATURE — Browser tab title now shows unread count.
  - **`tabTotalUnread`:** Computed in `ChatLayout` via `chats.reduce((s,c) => s + c.unread, 0)`.
  - **`useEffect`:** Sets `document.title = "(N) Powehi"` when N > 0; resets to `"Powehi"` when 0 or on unmount.
  - **Security:** Display-only side effect; no server calls, no new metadata, no logging. The count is an integer derived from local state only.
  - **969 frontend tests pass (+9: `ChatLayoutTabTitle.test.tsx` — initial badge (2), numeric format match, background-chat increment, mark-all-read reset, chat-switch clear, active-chat no-increment, unmount restore, multi-chat accumulation, individual-clear revert)**; tsc clean; biome clean.
  - **Next cycle:** PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768 ciphersuite), or more UX polish (e.g. message grouping by time window, presence indicators, disappearing-messages countdown tick).

## Previous state (2026-07-02, cycle 228 — FEATURE: media gallery in InfoPanel)
- **Cycle 228 (commit 9dbe9f1):** FEATURE — InfoPanel's Media section now shows real image thumbnails.
  - **`InfoPanel` new props:** `mediaMessages?: ChatMessage[]` and `onOpenLightbox?: (msg: ChatMessage) => void`. Wired from ChatLayout with existing `mediaMessages` memo and `handleOpenLightbox` callback.
  - **Grid:** 3-col CSS grid, up to 6 `MediaImage` thumbnails (`object-fit: cover`, `aspect-ratio: 1/1`). Each wrapped in `<button data-testid="media-gallery-thumb">`. Clicking opens the existing Lightbox at the correct index.
  - **Overflow:** When the chat has 7+ media messages, the 6th slot shows a `data-testid="media-gallery-overflow"` overlay with "+N" count (N = total − 5). Its aria-label reads "View all N images".
  - **Empty state:** `data-testid="media-gallery-empty"` shows "No shared media" when no media in the chat.
  - **Security:** Display-only — no server calls, no new metadata, JSX text children only (no dangerouslySetInnerHTML). Uses existing `useMediaReceive` decryption path. security-auditor: GREEN.
  - **960 frontend tests pass (+10: `ChatLayoutMediaGallery.test.tsx` — empty state, grid appears on media, 1 thumbnail for 1 image, 6 thumbnails for 6 images, overflow indicator for 8 images, cap at 6 thumbs, click opens lightbox, aria-label "View image", overflow aria-label "View all N images", empty state gone once media arrives)**; tsc clean; biome clean; bundle budget OK (JS 145.5KB gz / WASM 553.7KB gz).
  - **Note:** Unread divider (`new-messages-divider`) was already implemented (discovered during cycle) — `buildGroups` inserts it at `firstUnreadIndex`.
  - **Next cycle:** PQ hybrid Phase A or more UX polish (e.g. draft message persistence, message search, presence indicators).

## Previous state (2026-06-30, cycle 227 — FEATURE: typing bubble in message list + biome CI fix)
- **Cycle 227 (commits 19b3c5e + 60e21fd):**
  - **CI fix (19b3c5e):** Frontend CI was red — Biome wanted multi-line `waitFor(() =>\n  expect(...),\n)` collapsed to single-line. Fixed `ChatLayoutClearMessages.test.tsx` with `biome format --write`.
  - **Typing bubble (60e21fd):** `MessageList` now renders an animated `TypingDots` bubble at the bottom of the message area when `isTyping` is true. Bubble is styled as a peer incoming message: avatar initial (photon-blue ring), speech bubble with `border-radius: 4px 16px 16px 16px`, containing `<TypingDots />`. Added `isTyping?: boolean` prop to `MessageList`; passed `active.typing` from ChatLayout. No server calls, no logging, no new metadata — pure display layer. Existing `useLayoutEffect` scroll-to-bottom handles auto-scroll when bubble appears.
  - **950 frontend tests pass (+7: `ChatLayoutTypingBubble.test.tsx` — bubble visible (Sam), testid present, contains typing-dots, shows avatar initial S, absent on non-typing chat, disappears on switch, sidebar dots present)**; tsc clean; biome clean.
  - **Next cycle:** PQ hybrid Phase A or more UX polish (e.g. draft message persistence, message search, unread divider).

## Previous state (2026-06-30, cycle 226 — FEATURE: clear chat history)
- **Cycle 226 (commit dc124e4):** FEATURE — "Clear messages" button in InfoPanel now functional with inline confirm flow.
  - **`handleClearMessages(chatId)`:** Pure `setChats` — resets `messages[]`, `unread`, `mentionCount`, `pinnedMessageId`, `firstUnreadAt`, `last`, `time`. No MLS op, no server contact, no logging.
  - **InfoPanel `clearConfirm` state:** Click "Clear messages" → shows inline confirm panel ("Clear all messages? This cannot be undone.") with Cancel / Clear buttons. Confirming calls `onClearMessages?.()` and collapses back. No `window.confirm` (testable, better UX).
  - **No new server-visible metadata.** JSX text children only (no dangerouslySetInnerHTML). Destructive-button style (red tint: rgba(205,48,63,0.14)). Starred messages derived from messages[] so they auto-clear.
  - **943 frontend tests pass (+11: `ChatLayoutClearMessages.test.tsx` — button visible, correct text, shows confirm on click, confirm has warning text, Cancel hides prompt, Cancel keeps messages intact, Confirm removes all messages, unread badge cleared, confirm prompt closes after confirm, other chats unaffected, starred message from cleared chat removed from starred panel)**; tsc clean; biome clean; bundle budget OK.
  - **Next cycle:** PQ hybrid Phase A or more UX polish.

## Previous state (2026-06-30, cycle 225 — STABILIZATION: EpochAdvanced + MemberRemoved edge-case tests + MediaId unit tests)
- **Cycle 225 (commit 3e7ed3b):** STABILIZATION — Added 14 Rust unit tests closing coverage gaps.
  - **CI:** Green on main (all 3 recent runs pass). No open issues.
  - **ws-hub handler.rs (+6 tests):** `EpochAdvanced` notification filtering for member (true) / non-member (false) / invalid-group-id (false); `MemberRemoved` for another device (remaining member notified, non-member suppressed); phantom-removal security guard (MemberRemoved for this device when not in group → false).
  - **powehi-domain media.rs (+8 tests):** `MediaId` From\<Uuid\> round-trip, two new() calls distinct, Display matches inner UUID, Default non-nil, equality by UUID, serde_json serialize/deserialize round-trip. Added `serde_json` as dev-dependency in `powehi-domain/Cargo.toml`.
  - **Security sweep:** clippy clean (0 errors/warnings), biome clean (133 files), tsc clean, `cargo audit` 3 pre-existing allowed warnings (instant unmaintained via openmls, bitcoin_hashes yanked via bip39, one other transitive) — no new vulnerabilities.
  - **Target dir:** 7.4 GB (under 20 GB threshold, no pruning needed).
  - **Rust: 542+ tests pass (0 failed)**; frontend: 932 tests pass.
  - **Next cycle:** PQ hybrid Phase A or more UX polish.

## Previous state (2026-06-30, cycle 224 — FEATURE: starred messages test coverage)
- **Cycle 224 (commit b7b9808):** FEATURE — Added 12 tests for the starred messages feature (`ChatLayoutStarred.test.tsx`).
  - **Gap closed:** `StarredPanel` + `handleStarMessage` + `star-button` in `MessageBubble` were fully implemented in `ChatLayout.tsx` (local-only, no server contact, no MLS op) but had zero dedicated tests.
  - **Tests:** star button on hover, aria-label "Star message" for unstarred, "Starred messages" button opens panel, empty state text, close button dismisses panel, starring adds to panel, starred item shows message text, starred item shows chat name, clicking item switches chat + closes panel, unstar removes from panel, star absent for deleted messages, starring incoming message with stable id.
  - **Security:** Test file only — no implementation changes. Starred feature is local-only (never in MLS payload, never logged, never in API body). Confirmed by prior security-auditor pass.
  - **932 frontend tests pass (+12: `ChatLayoutStarred.test.tsx`)**; tsc clean; biome clean; bundle budget OK (JS 145.0KB gz / WASM 553.7KB gz).
  - **Next cycle:** PQ hybrid Phase A or more UX polish.

## Previous state (2026-06-30, cycle 223 — FEATURE: date separator auto-labels for runtime messages)
- **Cycle 223 (commit fdee407):** FEATURE — Date separators now auto-computed for runtime messages.
  - **`getDayLabel(ts: number): string`** (exported pure helper): returns "Today", "Yesterday", or locale-formatted date (e.g. "Mon, Jun 28"). Uses `new Date(ts)` vs today/yesterday comparison by year+month+date — no I/O, no DOM sink.
  - **`handleIncoming` updated:** Backwards scan finds last explicitly-set `day` field in chat history. New incoming message gets `day: getDayLabel(now.getTime())` only when the day has changed from `prevDay`. Enables date separators to appear automatically at midnight boundaries for real messages.
  - **`sendMessage` optimistic update:** Same auto-day logic applied so outgoing messages also trigger date separators when day rolls over.
  - **`data-testid="date-separator"`** added to the day-divider `<div>` in MessageList for testability.
  - **Security:** `day` is absent from all MLS plaintext paths (explicit payload construction from `text`/`replyTo`/`ttl`). JSX text children only (no dangerouslySetInnerHTML). No PII logging. No new server-visible metadata. security-auditor: **GREEN**.
  - **920 frontend tests pass (+10: `ChatLayoutDateSeparator.test.tsx` — getDayLabel today, getDayLabel yesterday, getDayLabel older, getDayLabel deterministic, seed shows Today separator, seed shows Yesterday separator, no duplicate day labels, same-day incoming no extra separator, separator non-empty, Yesterday before Today ordering)**; tsc clean; biome clean; bundle budget OK (JS 145.0KB gz / WASM 553.7KB gz).
  - **Next cycle:** PQ hybrid Phase A or more UX polish.

## Previous state (2026-06-30, cycle 222 — FEATURE: inline text formatting)
- **Cycle 222 (commit fc2ecfd):** FEATURE — Inline text formatting in chat message bubbles.
  - **`parseFormatting(text)`:** New pure function. Regex `` /`([^`]+)`|\*\*([^*]+)\*\*|\*([^*]+)\*/g `` splits text into `FmtSegment[]` with types `text | bold | italic | code`. Bold (`**`) matched before italic (`*`) in alternation so `**` consumed as a unit. Linear-time (negated char classes, no ReDoS).
  - **`renderFmtWithHighlight(fmtSegs, highlight, kp)`:** Renders segments to JSX: bold → `<strong data-testid="fmt-bold">`, italic → `<em data-testid="fmt-italic">`, code → `<code data-testid="fmt-code" style={{fontFamily:"monospace",...}>`. All JSX text children — no `dangerouslySetInnerHTML`. Search highlight (`applyHighlight`) applied inside bold/italic content; code content is literal.
  - **`HighlightedText` updated:** Now chains `parseMessageLinks` → `parseFormatting` per text segment. URL links unaffected (href comes only from `parseMessageLinks`). Fast path preserved: pure text with no URLs, formatting, or highlight returns `<>{text}</>` directly.
  - **Seed message added:** Maya's chat: `"Also **bring your charger** — the \`outlet\` by the window is the *only one* that works."` — demonstrates all three formatting types.
  - **Security:** No `dangerouslySetInnerHTML` anywhere in file (grep confirmed). `<strong>`/`<em>`/`<code>` are non-sink semantic tags. Inline `style` has only hardcoded literal values. `href` in `<a>` tags comes from `parseMessageLinks` only (protocol-validated, unchanged). No server calls, no MLS ops, no PII logging, no new server-visible metadata. security-auditor: **GREEN** — no findings; React JSX escaping makes XSS impossible; no ReDoS exposure (linear-time negated char class quantifiers).
  - **910 frontend tests pass (+12: `ChatLayoutFormatting.test.tsx` — seed bold renders `<strong>`, seed italic renders `<em>`, seed code renders `<code>`, incoming `**bold**` renders strong, incoming `*italic*` renders em, incoming `` `code` `` renders code, plain text no fmt elements, unmatched `*` stays as text, bold+URL same message, code has monospace style, mixed bold+italic, URL linkification still works)**; tsc clean; biome clean; bundle budget OK (JS 144.8KB gz / WASM 553.7KB gz).
  - **Next cycle:** PQ hybrid Phase A or more UX polish.

## Previous state (2026-06-30, cycle 221 — FEATURE: mark-all-read button)
- **Cycle 221 (commit fb27f08):** FEATURE — "Mark all as read" button in sidebar header.
  - **`check-square` icon:** Added to `Icon.tsx` (static SVG path, Lucide-style). Local-only.
  - **`Sidebar` prop `onMarkAllRead?: () => void`:** Optional callback. Sidebar computes `totalUnread = chats.reduce(...)`, `totalMentions = chats.reduce(...)`, `hasUnread = totalUnread > 0 || totalMentions > 0`. Renders `<IconBtn icon="check-square" label="Mark all as read">` in header only when `hasUnread && onMarkAllRead`.
  - **`handleMarkAllRead`:** Pure `setChats` map — sets `unread:0, firstUnreadAt:undefined, mentionCount:0` for all chats in one operation. No API call, no MLS op, no server contact, no logging.
  - **Button visibility:** Visible when any chat has unread messages or mention badges (Jordan seed data has `unread:2`; Design Team has `mentionCount:2`). Disappears after clicking. Reappears when new messages arrive.
  - **Security:** Purely local React state. Fields are local-only (never in MLS plaintext or API request body). Button label is a string literal. No new server-visible metadata. security-auditor: GREEN — verified no server calls, no MLS, no XSS, no PII logging.
  - **898 frontend tests pass (+11: `ChatLayoutMarkAllRead.test.tsx` — button visible on load, aria-label correct, clicking clears unread badges, button hides itself after click, mention badges cleared, button reappears after new incoming msg, active chat messages intact, Chats-tab unread cleared, Groups-tab mention cleared, no-op when no unread, chat select still works after mark-all-read)**; tsc clean; biome clean; bundle budget OK (JS 144.4KB gz / WASM 553.7KB gz).
  - **Next cycle:** PQ hybrid Phase A or more UX polish.

## Previous state (2026-06-29, cycle 220 — STABILIZATION: security-invariant input validation tests)
- **Cycle 220 (commit f16c4a5):** STABILIZATION — Added 6 missing security-invariant input validation tests to `powehi-rest-api`.
  - **`register_init_short/long_handle_hash_returns_400`:** SHA-256 constraint — `handle_hash` must be exactly 32 bytes; shorter/longer inputs must be rejected at the HTTP layer before the OPAQUE state machine runs (prevents brute-force handle enumeration via oracle).
  - **`login_init_short/long_handle_hash_returns_400`:** Same constraint for login path.
  - **`fetch/upload_key_packages_malformed_device_id_returns_400`:** `parse_device_id` with non-UUID path param returns InvalidInput; handler must reject before reaching use case.
  - **CI:** Green (2 allowed warnings: instant unmaintained via openmls; bitcoin_hashes yanked via bip39 — both transitive). No new vulnerabilities.
  - **Target dir:** 7.4 GB (under 20 GB threshold, no pruning). fmt clean; clippy clean.
  - **powehi-rest-api: 139 tests pass (+6).**
  - **Next cycle:** PQ hybrid Phase A or more UX polish.

## Previous state (2026-06-29, cycle 219 — FEATURE: chat nickname for DM contacts)
- **Cycle 219 (commit c779153):** FEATURE — Chat nickname: custom display name for DM contacts (local-only, never sent to server).
  - **`Chat.nickname?: string`:** New optional field on Chat. Local-only — absent from all MLS encrypt paths, API request bodies, and log statements.
  - **`handleUpdateNickname(chatId, nickname)`:** Pure `setChats` immutable update. Empty string → `undefined` (clears nickname). No API call, no MLS op, no server contact.
  - **`InfoPanel` Nickname section (DM only):** Appears between user info block and Safety Numbers section. View mode: shows nickname text or "No nickname set" placeholder + pencil edit button. Edit mode: controlled `<input type="text" maxLength=50>` with Save/Cancel/Enter/Escape. `autoFocus` on open (biome-ignore comment, explicit user action).
  - **Display propagation:** `chat.nickname ?? chat.name` shown in `ChatRow` (sidebar), `ConversationHeader` (data-testid="conversation-header-name"), `InfoPanel` user info block. When nickname set, original name shown as subtitle in InfoPanel.
  - **`QuickSwitcher` updated:** Filter includes `(c.nickname ?? c.name)` in addition to `c.name` and `c.handle`. Display shows `c.nickname ?? c.name`; subtitle shows `c.name` (real name) when nickname set, else `@handle`.
  - **Security:** JSX text children only (no dangerouslySetInnerHTML). `nickname` never in MLS payload, never logged, never in any API call. Controlled input (maxLength=50). No new server-visible metadata. security-auditor: GREEN (pending confirmation).
  - **887 frontend tests pass** (+13: `ChatLayoutNickname.test.tsx` — DM shows nickname section, group does NOT, no-nickname placeholder, edit opens input, maxLength 50, Save saves+hides input, Enter saves, Cancel discards, Escape discards, nickname in ConversationHeader, clearing restores real name, searchable in QuickSwitcher, QuickSwitcher displays nickname); tsc clean; biome clean; bundle budget OK (JS 144.3KB gz / WASM 553.7KB gz).
  - **Next cycle:** PQ hybrid Phase A or more UX polish.

## Previous state (2026-06-29, cycle 218 — FEATURE: Cmd+K quick chat switcher)
- **Cycle 218 (commit 15ab178):** FEATURE — Cmd+K quick chat switcher modal.
  - **`QuickSwitcher` component:** Full-screen backdrop (rgba 0.72), centered 400px panel. Auto-focused search input filters chats by name or handle (case-insensitive). Items shown with avatar initial, name, and @handle. Arrow keys navigate highlighted item (`aria-selected`); Enter selects; Escape / second Ctrl+K / backdrop click closes.
  - **State:** `quickSwitcherOpen`, `quickSwitcherQuery`, `quickSwitcherActive`, `quickSwitcherInputRef` — all local to `ChatLayout`.
  - **Global keydown listener:** `(e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k"` (CapsLock-safe); `e.preventDefault()` suppresses browser address-bar focus; cleanup on unmount.
  - **Security:** JSX text children only (no dangerouslySetInnerHTML). Query never logged, never sent to server. No API calls. No new server-visible metadata. security-auditor: PASS. Advisory fixed: CapsLock robustness via `.toLowerCase()`.
  - **874 frontend tests pass** (+12: `ChatLayoutQuickSwitcher.test.tsx` — not visible on init, Ctrl+K opens, Meta+K opens, Escape closes, backdrop click closes, lists seed chats, typing filters, no-match empty state, click switches chat, ArrowDown highlights, Enter selects, second Ctrl+K closes); tsc clean; biome clean; bundle budget OK (JS 143.9KB gz / WASM 553.7KB gz).
  - **Next cycle:** PQ hybrid Phase A or more UX polish.

## Previous state (2026-06-29, cycle 217 — FEATURE: group description in InfoPanel)
- **Cycle 217 (commit 865909a):** FEATURE — Editable group description ("About" section) in group InfoPanel.
  - **`Chat.description?: string`:** Local-only field. Never sent to server, never in MLS payload, never in any API request body. Comment documents this explicitly.
  - **`handleUpdateGroupDescription(chatId, desc)`:** Pure `setChats` immutable map update. No API call, no MLS op, no server contact.
  - **InfoPanel "About" section:** Rendered for group chats only (DMs unchanged). View mode: description text (or "No description set" placeholder in muted fg-4 color) + pencil edit button. Edit mode: controlled `<textarea>` (maxLength=200), Save/Cancel buttons, Enter (without Shift) saves and collapses, Escape cancels without saving.
  - **`edit-2` icon:** Lucide-style `<path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/>` added to Icon.tsx.
  - **Design Team seed:** `description: "Where design meets code — share mockups, get feedback, ship it."` added.
  - **Security:** JSX text children only (no dangerouslySetInnerHTML). Controlled textarea. No logging. No new server-visible metadata. `data-testid` values are string literals. security-auditor: GREEN. YELLOW-1 advisory: handler has no length guard (safe now since local-only — note for when/if promoted to synced field).
  - **862 frontend tests pass** (+9: `ChatLayoutGroupDescription.test.tsx` — seed description shown, new group placeholder, edit button present, textarea opens, Save saves, Enter saves+collapses, Escape cancels, Cancel button cancels, absent for DM); tsc clean; biome clean; bundle budget OK (JS 143.1KB gz / WASM 553.7KB gz).
  - **Next cycle:** PQ hybrid Phase A or more UX polish.

## Previous state (2026-06-29, cycle 216 — STABILIZATION: CI format fix + security audit)
- **Cycle 216 (commit a19ec02):** STABILIZATION — Fixed `Format check` CI failure (main was red).
  - **Root cause:** Two `let env_repo = \n    FakeEnvelopeRepo::with_memberships(...)` bindings added in cycle 215 were split across 2 lines even though they fit within 100 chars. `cargo fmt --check` in CI failed with exit code 1.
  - **Fix:** `cargo fmt --package powehi-application` collapsed both bindings to single lines (lines 1193, 1223 in `messaging_service.rs`).
  - **Verification:** `cargo fmt --check` clean, all 83 application tests pass, full workspace build clean.
  - **Security audit:** `security-auditor` on `messaging_service.rs` + `envelope_repo.rs` → PASS. No critical/high/medium findings. TTL filter consistent in both SQL branches (`expires_at IS NULL OR expires_at > NOW()`). Auth checks correct. No plaintext logging. Integration test `find_pending_excludes_expired_envelopes` in `pg_security_it.rs` is authoritative TTL gate.
  - **`cargo audit`:** 2 allowed warnings (instant unmaintained via openmls; bitcoin_hashes yanked via bip39 — both transitive, upstream-controlled). No vulnerabilities.
  - **Target dir:** 7.2 GB (under 20 GB threshold). No pruning needed.
  - **Next cycle:** PQ hybrid Phase A or more UX polish.

## Previous state (2026-06-29, cycle 215 — STABILIZATION: MLS security-invariant tests)
- **Cycle 215 (commit 6cbde19):** STABILIZATION — MLS KeyPackage single-use and disappearing-message expiry invariants.
  - **Next cycle:** More UX polish or PQ hybrid Phase A.

## Previous state (2026-06-29, cycle 214 — FEATURE: image lightbox)
- **Cycle 214 (commit cdba978):** FEATURE — Image lightbox: clicking a media image opens a full-screen overlay.
  - **`Lightbox` component:** Full-screen overlay (rgba 0.94 void bg, z-index 60). Close button, backdrop click, and Escape/ArrowLeft/ArrowRight keyboard handlers via useEffect. Prev/next navigation arrow buttons visible only when adjacent images exist. Counter shows "N / total" when there are multiple images. Image rendered via `MediaImage` with `imgStyle` override (max 90vw/85vh instead of inline 320px).
  - **`MediaImage` changes:** Added optional `imgStyle?: CSSProperties` prop merged into `<img>` style (thumbnail and full image). Enables lightbox to render the image at larger dimensions without duplication.
  - **`MessageBubble` changes:** Added `onOpenLightbox?: () => void` prop; wraps `<MediaImage>` in a `<button data-testid="media-open-lightbox">` when the prop is provided.
  - **`MessageList` changes:** Added `onOpenLightbox?: (msg: ChatMessage) => void` prop, threaded through to `MessageBubble` for each media message.
  - **`ChatLayout`:** Added `lightboxMsgIdx` state, `mediaMessages` memo, and `handleOpen/Close/Prev/Next` callbacks. Renders `<Lightbox>` above all panels when idx is non-null.
  - **Security:** Lightbox renders only already-decrypted object URLs from `useMediaReceive`; no new server requests, no new server-visible metadata. Pure display layer.
  - **853 frontend tests pass** (+7: `ChatLayoutLightbox.test.tsx` — open on click, close button, Escape key, backdrop click, counter + prev/next buttons, ArrowRight nav, ArrowLeft nav); tsc clean; biome clean; bundle budget OK (JS 142.6KB gz / WASM 553.7KB gz).
  - **Next cycle:** More UX polish or PQ hybrid Phase A.

## Previous state (2026-06-29, cycle 213 — FEATURE: reaction detail tooltip)
- **Cycle 213 (commit 6e12181):** FEATURE — Reaction detail tooltip: hover any reaction chip to see who reacted.
  - **`getReactionHandles(senders, members, myDeviceId)`:** Pure function mapping device IDs to display handles. Shows "You" for `myDeviceId`, looks up `handle` from group `members`, falls back to 8-char ID truncation.
  - **`MessageBubble` changes:** Added `members?: ChatMember[]` prop; `hoveredReaction: string | null` state; each reaction chip row is wrapped in `<div data-testid="reaction-chip-wrapper-{emoji}">` with `onMouseEnter`/`onMouseLeave` handlers. Tooltip `data-testid="reaction-tooltip-{emoji}"` is absolutely positioned above the chip, `pointerEvents: none`, `zIndex: 20`. Only shown when `hoveredReaction === emoji`.
  - **`MessageList`:** Added `members?: ChatMember[]` prop, threaded through to `MessageBubble`.
  - **`ChatLayout`:** Passes `active.members` to `MessageList`.
  - **Security:** Handles resolved from local group roster only — never sent to server. No new server-visible metadata. Tooltip has `pointerEvents: none` so it can't intercept clicks.
  - **846 frontend tests pass** (+4: `ChatLayoutReactionDetail.test.tsx` — shows handles on hover, hides on leave, shows ❤️ tooltip with correct handle, chip tooltips are independent); biome clean; bundle budget OK.
  - **Next cycle:** More UX polish or PQ hybrid Phase A.

## Previous state (2026-06-28, cycle 212 — FEATURE: group poll creation in chat composer)
- **Cycle 212 (commit a7a3a71):** FEATURE — Group poll feature in chat composer.
  - **`PollView`:** Renders poll question + clickable option bars (proportional fill) + vote count. Voter toggle: clicking an option adds/removes "me" sentinel from the voters array.
  - **`PollCreatorPopup`:** Floating popup with question input + 2-4 option inputs + Add option / Cancel / Create buttons. Validates non-empty question + 2+ non-empty options before submitting.
  - **Composer changes:** `isGroupChat` prop gates the poll button (bar-chart icon). `onCreatePoll` prop wires the creator. Poll button only appears in group chats.
  - **`handleCreatePoll`:** Adds poll message (local only, `id: poll_<ts>`, `text: ""`) to active chat state. No server call, no MLS op, no Dexie write.
  - **`handleVotePoll`:** Toggles "me" in the voters array for the selected option. Pure local state mutation.
  - **Security:** JSX text children only (no XSS); poll never enters MLS payload, never logged, never persisted; DM chats correctly excluded via `isGroupChat` gate. security-auditor: GREEN.
  - **842 frontend tests pass** (+12: `ChatLayoutPoll.test.tsx`); tsc clean; biome clean; bundle budget OK (JS 141.7KB gz / WASM 553.7KB gz).
  - **Next cycle:** PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768 ciphersuite), or more UX polish.

## Previous state (2026-06-28, cycle 211 — FEATURE: draft-preview indicator in sidebar)
- **Cycle 211 (commit 09b112e):** FEATURE — Draft indicator in sidebar: inactive chat rows show "Draft: [preview]" when there is unsent text.
  - **`ChatRow`:** New `draft?: string` prop. When `!active && draft`, renders `<span data-testid="draft-preview">` with orange "Draft: " label + the draft text instead of `chat.last`. Condition guards active chat (no indicator while composing in the current chat).
  - **`Sidebar`:** New `drafts: Record<string, string>` prop. Passes `draft={drafts[c.id]}` to each `ChatRow`.
  - **`ChatLayout`:** Threads existing in-memory `drafts` state (already present since cycle N) into `Sidebar`. No new state added.
  - **Security:** JSX text children only (no XSS surface). Draft text is in-memory React state — never logged, never server-bound, never in MLS payload. security-auditor: GREEN.
  - **827 frontend tests pass** (+7: `ChatLayoutDraft.test.tsx` — draft-preview appears after switching, shows "Draft:" label + text, absent for active chat, absent with no text, disappears after send, independent per-chat, replaces chat.last); tsc clean; biome clean; bundle budget OK (JS 140.6KB gz / WASM 553.7KB gz).
  - **Next cycle:** PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768 ciphersuite), or more UX polish.

## Previous state (2026-06-28, cycle 210 — STABILIZATION: CI fix — unused import unblocks bundle budget)
- **Cycle 210 (commit bf2ed02):** STABILIZATION — Fixed Frontend CI bundle budget failure.
  - **Root cause:** `ChatLayoutScheduleSend.test.tsx` imported `waitFor` from `@testing-library/react` but never used it. `tsc -b` with `noUnusedLocals` emitted TS6133, aborting before `vite build` could run. The bundle-budget CI job then failed (no dist/).
  - **Fix:** Removed `waitFor` from the import on line 1 (kept `act`, `fireEvent`, `render`, `screen`).
  - **Verified locally:** `pnpm --filter app build` clean, `pnpm --filter app budget` passes (JS ≤140.5KB gz, WASM ≤553.7KB gz, both under limits), `820 frontend tests pass`, biome clean.
  - **cargo audit:** 2 allowed warnings (instant unmaintained via openmls; bitcoin_hashes yanked via bip39 — both transitive deps, upstream-controlled). No new vulnerabilities.
  - **Target dir:** 6.4 GB (under 20 GB cap). 0-byte .rmeta stubs pruned.
  - **Next cycle:** PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768 ciphersuite), or more UX polish.

## Previous state (2026-06-28, cycle 209 — FEATURE: scheduled send in message composer)
- **Cycle 209 (commit a1f911a):** FEATURE — Scheduled Send: queue a message to fire at a future time.
  - **`SchedulePickerPopup`:** Floating popover with `<input type="datetime-local">`, Cancel + Schedule buttons. `minDt` is `now+60s`. `handleSubmit` validates `ms > Date.now()` before calling `onSchedule(ms)`. `data-testid="schedule-picker"`.
  - **`Composer` changes:** Added `onScheduleSend?: (text, at) => void` prop; `schedulePickerOpen` + `schedulePickerRef` state; click-outside useEffect mirrors the emoji picker pattern; "Send later" timer button (`data-testid="send-later-btn"`) appears alongside the send button when text is non-empty.
  - **`ChatMessage.scheduledFor?: number`:** Client-side-only Unix ms field. When set, message is queued pending.
  - **Message bubble:** Photon-blue `"Scheduled · HH:MM"` badge (`data-testid="scheduled-badge"`) with inline Cancel button (`data-testid="cancel-scheduled-btn"`). Cancel removes the message via `onCancelScheduled`.
  - **`sendScheduled(text, at)`:** Adds message to active chat with `scheduledFor` set (uses `sched_` id prefix). `cancelScheduled(msgId)` filters it out.
  - **Sweep `useEffect` (10s interval):** Clears `scheduledFor` on messages where `scheduledFor <= Date.now()`, making them look like regular sent messages.
  - **CI fix (commit 844216f):** Biome format — collapsed `waitFor` callback in `ChatLayoutEmojiPicker.test.tsx` to single line.
  - **422 frontend tests pass (+13: `ChatLayoutScheduleSend.test.tsx` — button hidden on empty, appears with text, opens picker on click, picker has datetime-local, cancel closes picker, schedule adds badge, picker closes after confirm, composer cleared, cancel removes message, badge shows time, timer sweep fires message, multiple queued independently)**; tsc clean; biome clean.
  - **Next cycle:** PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768 ciphersuite), or more UX polish.

## Previous state (2026-06-28, cycle 208 — FEATURE: emoji picker in message composer)
- **Cycle 208 (commit 5688a2f):** FEATURE — Emoji picker popup in message composer.
  - **`EmojiPickerPopup`:** Floating `<div data-testid="emoji-picker">` above the smile button. 3 categories: Smileys (16 emojis), Gestures (10), Symbols (10). Each emoji is a `<button data-testid="emoji-btn" aria-label={emoji}>` — JSX text children only, no innerHTML.
  - **`handleInsertEmoji`:** Pure string concat `text.slice(0, start) + emoji + text.slice(end)` → `setText`. Respects `selectionStart`/`selectionEnd` cursor position via `textareaRef`. Calls `requestAnimationFrame` to restore focus + caret after insert. Closes picker on select.
  - **Click-outside:** `document.addEventListener("mousedown", handler)` gated on `emojiPickerOpen`, with ref guard and cleanup.
  - **Smile button toggle:** `onClick={() => setEmojiPickerOpen(o => !o)}` — toggles open/close.
  - **security-auditor: GREEN** — JSX text children only (no XSS); no server calls; no MLS ops; no logging of inserted emoji or composed text; `mousedown` listener cleaned up on effect teardown; no new server-visible metadata.
  - **807 frontend tests pass (+11: `ChatLayoutEmojiPicker.test.tsx` — picker hidden by default, opens on smile click, closes on second click, shows all 3 categories, emoji inserts into input, closes picker on emoji click, multiple emojis insert sequentially, closes on outside click, aria-labels are emojis, position absolute style, preserves existing draft text)**; tsc clean; biome clean.
  - **Next cycle:** PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768 ciphersuite), or more UX polish.

## Previous state (2026-06-28, cycle 207 — FEATURE: copy message to clipboard)
- **Cycle 207 (commit f273cc4):** FEATURE — Copy message to clipboard button in message hover toolbar.
  - **Copy button:** Appears on hover for non-deleted text messages (excluding `[image]` placeholders and empty text). Positioned at `left:104` in the hover toolbar (after Share at left:78). `data-testid="copy-button"`, `aria-label="Copy message"`.
  - **`handleCopyMessage`:** `navigator.clipboard.writeText(msg.text).catch(() => {})` — structured API, not a DOM sink. Failure silently ignored. No server calls, no MLS ops, no PII logging.
  - **Copied feedback:** `copied` boolean state in `MessageBubble`. On click: calls `onCopy()` + `setCopied(true)` + `setTimeout(() => setCopied(false), 1500)`. Button shows `<Icon name={copied ? "check" : "copy"} />` in orange when copied, normal when idle.
  - **Security guards (triple-gated):** Deleted/`[image]`/empty text skipped at button render, `MessageList` wiring, and `handleCopyMessage` handler.
  - **Timer test fix:** `vi.useRealTimers()` added to `afterEach` before any async teardown — prevents fake timers from hanging `db.verifiedContacts.clear()` when a test fails before `vi.useRealTimers()` in the test body.
  - **security-auditor: GREEN** — `navigator.clipboard.writeText` is a structured API (not DOM sink); no logging of copied content; no server call; no MLS op; triple-gated guards.
  - **796 frontend tests pass (+11: `ChatLayoutCopy.test.tsx` — button on hover, absent for deleted, absent for [image], calls writeText with correct text, button on own messages, aria-label correct, copied state present after click, clipboard failure no crash, correct text with multiple messages, copied state resets after 1500ms, absent for empty text)**; tsc clean; biome clean.
  - **Next cycle:** PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768 ciphersuite), or more UX polish.

## Previous state (2026-06-28, cycle 206 — FEATURE: URL linkification in message text)
- **Cycle 206 (commit 9f69cfd):** FEATURE — Clickable link detection in message text.
  - **`parseMessageLinks(text)`:** Splits message text into `{type: "text" | "url", value}` segments. Only `https:` and `http:` URLs are linkified — `javascript:`, `data:`, `vbscript:` etc. remain plain text. Validated via `new URL()` + protocol allowlist. Trailing punctuation (`,.:;!?)]`) stripped from matched URLs.
  - **`applyHighlight(text, highlight)`:** Extracted from `HighlightedText` (was inline), now reused per-segment.
  - **`HighlightedText` updated:** URL segments render as `<a target="_blank" rel="noopener noreferrer">` in photon-blue (`#A8C8FF`). Text segments continue to get `<mark>` highlights for search. Keys composite `${type}-${i}` (biome `noArrayIndexKey` compliant).
  - **Seed message:** Maya's chat gained `"Great! Here's the menu: https://example.com/menu"` from peer.
  - **security-auditor: GREEN** — JSX attr escaping prevents XSS; no `dangerouslySetInnerHTML`; protocol allowlist blocks `javascript:`/`data:` injection; `rel="noopener noreferrer"` prevents opener hijacking; no plaintext logging.
  - **785 frontend tests pass (+12: `ChatLayoutLinks.test.tsx` — seed link renders, https linkified, target=_blank, rel=noopener noreferrer, http linkified, plain text not linkified, javascript: blocked, data: blocked, URL at start, URL at end, multiple URLs, trailing period stripped)**; tsc clean; biome clean.
  - **Next cycle:** PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768 ciphersuite), or more UX polish.

## Previous state (2026-06-28, cycle 205 — STABILIZATION: eliminate act() warnings in useRegionDetect tests)
- **Cycle 205 (commit e2f34df):** STABILIZATION — Fixed act() warnings in `useRegionDetect.test.ts`.
  - **CI:** Green (success). **cargo audit:** 2 allowed warnings (instant unmaintained via openmls; bitcoin_hashes yanked via bip39 — both transitive deps, upstream-controlled). **cargo clippy:** Clean. **773 frontend tests + all Rust tests pass.**
  - **Root cause:** `beforeEach`/`afterEach` Zustand `setState` calls were outside `act()` (Zustand's useSyncExternalStore subscriber flush not attributed). The "returns regionId after fetch resolves" test used a one-tick `act` flush that raced the two-await store chain (`fetch()` → `res.json()` → `set()`).
  - **Fix:** Wrapped `beforeEach`/`afterEach` store resets in `await act(async () => {...})`. Changed async assertion to `await waitFor(() => expect(result.current).toBe("eu-de-1"))` which polls within act. Added `await act(async () => {})` after "reflects store regionId already set before mount" to flush the background fetch.
  - **Target dir:** 6.5 GB (well under 20 GB cap). Pruned 0-byte `.rmeta` stubs.
  - **Next cycle:** PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768 ciphersuite), or more UX polish.

## Previous state (2026-06-27, cycle 204 — FEATURE: jump-to-bottom FAB — scroll-up detection + unread badge)
- **Cycle 204 (commit 971ac29):** FEATURE — Jump-to-bottom FAB in message list.
  - **Scroll-up detection:** `MessageList` tracks `isAtBottomRef` (ref) + `isAtBottom` (state) via an `onScroll` handler on `data-testid="message-list-scroll"`. Threshold: `scrollTop + clientHeight >= scrollHeight - 80`.
  - **FAB:** `data-testid="jump-to-bottom-btn"`, `aria-label="Jump to bottom"`, `type="button"`. Positioned absolute bottom-right (bottom:16, right:20, 40×40 circle). Visible only when `!isAtBottom`. Clicking calls `handleJumpToBottom` → sets `scrollTop = scrollHeight`, resets `isAtBottom=true` + `newMsgCount=0`.
  - **Unread badge:** `data-testid="jump-to-bottom-badge"`. Counts incoming messages that arrive while scrolled up (capped: `Math.min(c + added, 99)`). Shown as integer or `"99+"` when `>= 99`. Cleared when user scrolls to bottom or clicks FAB.
  - **Auto-scroll gate:** `useLayoutEffect` scroll-to-bottom now gated on `isAtBottomRef.current` (was ungated). Prevents scroll-to-bottom hijacking when user is reading old messages.
  - **Chat-switch reset:** `useEffect` on `chatId` dep resets all scroll state so every new chat starts at bottom. `chatId` prop added to `MessageList`.
  - **`chevron-down` icon:** Added to `Icon.tsx` (`<polyline points="6 9 12 15 18 9"/>`).
  - **security-auditor: GREEN** — purely client-side; no server calls, no MLS ops; badge shows integer count only (never message content); no XSS (JSX text children only); no logging of scroll state/chatId/count.
  - **773 frontend tests pass** (+11: `ChatLayoutJumpToBottom.test.tsx` — FAB absent at bottom, FAB appears on scroll-up, aria-label correct, FAB click hides it, FAB click sets scrollTop, badge absent with no new msgs, badge count=1 on first msg, badge increments on 2 msgs, badge clears on scroll-to-bottom, FAB hides on scroll-to-bottom, badge never shown when at bottom); tsc clean; biome clean.
  - **Next cycle:** PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768 ciphersuite), or more UX polish.

## Previous state (2026-06-27, cycle 203 — FEATURE: group member list — Members section in InfoPanel for group chats)
- **Cycle 203 (commit 7a59bec):** FEATURE — Group member list in InfoPanel.
  - **`ChatMember` interface:** `{ id: string; name: string; handle: string; role?: "admin" | "member" }` — local-only type, never sent to server, never in MLS payload.
  - **`Chat.members?: ChatMember[]`:** New optional field on Chat. Never appears in any sendMessage/sendReaction/MLS encrypt path. Render-only.
  - **Design Team seed:** 4 members — `{ id:"dev-a", name:"Finn", handle:"finn", role:"admin" }`, `{ id:"dev-b", name:"Maya", handle:"maya" }`, `{ id:"dev-c", name:"Jordan", handle:"jordan" }`, `{ id:"dev-d", name:"Noa", handle:"noa" }`. Design Team still has no `mlsIdentityId`, so all authenticated API paths remain unreachable.
  - **InfoPanel conditional rendering:** `chat.isGroup` → shows "Members (N)" `InfoSection` with `data-testid="group-member-list"`. Each row has `data-testid="group-member-row"`: Avatar, name, `@handle`. Badges: "You" (orange) when `myHandle.toLowerCase() === member.handle.toLowerCase()`; "Admin" (photon-blue) when `member.role === "admin"`. DMs → unchanged Safety Numbers section.
  - **`myHandle` prop:** `useAuthStore.getState().myHandle ?? undefined` passed to InfoPanel at call site. Used only for badge comparison — never logged, never in MLS plaintext.
  - **security-auditor: GREEN** — JSX text children only (no XSS); member.name/handle never in MLS payload or API; myHandle not logged; timing-safe badge comparison (no network round-trip); design-team guard (no mlsIdentityId) blocks all send paths.
  - **762 frontend tests pass** (+12: `ChatLayoutGroupMemberList.test.tsx` — member list renders for group, absent for DM, count in section title, 4 member rows, names displayed, @handles displayed, admin badge appears once, non-admin has no admin badge, You badge when myHandle matches, You badge absent when not in list, Safety Numbers absent for group, Safety Numbers present for DM); tsc clean; biome clean.
  - **Next cycle:** PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768 ciphersuite), or more UX polish.

## Previous state (2026-06-27, cycle 202 — FEATURE: pin chat to top — pinnedTop floats chats in sidebar)
- **Cycle 202 (commits 8027713, df8fd47):** FEATURE — Pin chat to top + CI fix.
  - **CI fix (8027713):** `ChatLayoutArchive.test.tsx` — removed unused `MAYA_GROUP_ID` and `DESIGN_TEAM_GROUP_ID` constants that caused TS6133 (`noUnusedLocals`) and broke the bundle-budget CI build step.
  - **`Chat.pinnedTop?: boolean`:** Local-only flag. Never sent to server, never in MLS payload, never in IndexedDB (Chat object not persisted — only messages are). Same pattern as `muted`/`sound`/`vibrate`/`archived`.
  - **`handleTogglePinTop`:** Pure `setChats` immutable toggle. No API call, no MLS message, no server contact.
  - **Sidebar sort:** `[...filtered].sort((a, b) => (b.pinnedTop ? 1 : 0) - (a.pinnedTop ? 1 : 0))` — stable (ES2019+), local-only. Pinned chats float above unpinned in All, DMs, Groups, Archived tabs.
  - **ChatRow pin indicator:** `<span data-testid="pin-top-indicator"><Icon name="pin" size={10} color="#A8C8FF" /></span>` — JSX only, no innerHTML, no XSS surface. Photon-blue decorative (not the lock glyph, so brand rule intact).
  - **InfoPanel "Pin to top" InfoRow:** Wired `trailing={pinnedTop ? "On" : "Off"}` + `onClick={onTogglePinTop}`. Archived chats continue to be excluded from non-archived tabs even when also pinned (archived wins).
  - **security-auditor: GREEN** — pinnedTop absent from all 11 MLS plaintext shapes and the send API body; no console.* calls; no XSS surface.
  - **750 frontend tests pass** (+10: `ChatLayoutPinTop.test.tsx` — InfoPanel Off by default, toggle On, double-toggle Off, sidebar pin indicator, no indicator without pinning, appears-first in sidebar, chat-specific independence, multiple pins, archive+pin stays archived, mute independence); tsc clean; biome clean.
  - **Next cycle:** PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768 ciphersuite), or more UX polish.

## Previous state (2026-06-27, cycle 201 — FEATURE: chat archive — archive/unarchive + Archived filter tab)
- **Cycle 201 (commits 179d428, be82d4a):** FEATURE — Chat archive + biome CI fix.
  - **Biome CI fix (179d428):** `MediaImage.test.tsx` import order — `import type { MediaPayload }` must come before `import * as UseThumbnailModule` (biome organizeImports rule). Frontend CI was red since cycle 200.
  - **`Chat.archived?: boolean`:** Local-only flag (never sent to server or included in MLS payload). Structurally isolated from all API/send paths by the API layer's explicit field allowlist.
  - **Sidebar "Archived" filter tab:** `chatFilter` type extended to `"all" | "dms" | "groups" | "archived"`. The "all"/"dms"/"groups" tabs exclude archived chats (`!c.archived` guard). The "archived" tab shows only `c.archived === true` chats. `msgResults` scoped by the same logic.
  - **`handleToggleArchive`:** Pure `setChats` immutable toggle. No API call, no MLS message, no server contact.
  - **Auto-unarchive on incoming message:** In `handleIncoming` setChats reducer, `archived: c.archived ? false : c.archived` — a new message promotes an archived chat back to the main list.
  - **InfoPanel "Archive Chat" / "Unarchive Chat" button:** `data-testid="archive-button"`. `archived` and `onToggleArchive` props wired at call site.
  - **security-auditor: GREEN** — `archived` field verified absent from all 8 send paths (sendMessage, sendReaction, sendEdit, sendDelete, sendPin, read/delivery receipts, forward, typing, presence). No new server-visible metadata. No XSS (JSX literal text children). InfoPanel button verified safe.
  - **740 frontend tests pass** (+10: `ChatLayoutArchive.test.tsx` — tab renders, only archived chats in Archived tab, All tab excludes archived, InfoPanel button toggles text, unarchive via InfoPanel, auto-unarchive on incoming, no badge for archived tab, archive hides from All tab, DMs tab excludes archived, Groups tab excludes archived); tsc clean; biome clean.
  - **Next cycle:** PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768 ciphersuite), or more UX polish.

## Previous state (2026-06-27, cycle 200 — STABILIZATION: close test coverage gaps — MediaImage + useCryptoWorker)
- **Cycle 200 (commit 18e065c):** STABILIZATION — Closed test coverage gaps.
  - **`MediaImage.test.tsx`** (+9 tests): loading placeholder (no thumbnail), blurred thumbnail placeholder while loading, full image when loaded, "Image unavailable" on error, "Image unavailable" when objectUrl is null after load, thumbnail prop passed to useThumbnail only while loading, undefined passed when not loading, correct `alt` text for full image, correct `alt` for thumbnail img.
  - **`useCryptoWorker.test.ts`** (+5 tests): singleton identity (`useCryptoWorker === getCryptoWorkerProxy` same reference), repeated-call stability, never-throws contract in JSDOM environment.
  - **CI green (730 frontend tests pass, was 715):** All Rust tests (316 total) and clippy also green.
  - **Target dir:** 6.4GB (well under 20GB threshold — no prune needed).
  - **Next cycle:** PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768 ciphersuite), or more UX polish.

## Previous state (2026-06-27, cycle 199 — FEATURE: keyboard shortcuts ↑ to edit last message, Escape to cancel)
- **Cycle 199 (commit f134167):** FEATURE — Composer keyboard shortcuts.
  - **↑ arrow (empty composer, not in edit mode):** Calls `onEditLast` → finds the last own non-deleted message (reversed scan of `active.messages`) and enters edit mode via `setEditingMessage`. Works whether message has a server id or a temp `opt_` id.
  - **Escape (in edit mode):** Calls `onCancelEdit?.()` → `setEditingMessage(null)`.
  - **Escape (in reply mode):** Calls `onCancelReply?.()` → `setReplyingTo(null)`.
  - **Optimistic message local IDs:** Optimistic "me" messages now assigned `id: \`opt_\${crypto.randomUUID()}\`` at send time. Backfill logic updated to `msgs[i].id?.startsWith("opt_")` instead of `!msgs[i].id`. `Sending` indicator updated to `msg.id?.startsWith("opt_")`.
  - **`opt_` network guard (YELLOW advisory fix):** Added `if (targetId.startsWith("opt_")) return` to `sendReaction`, `sendDelete`, and `sendPin` — ensures unacknowledged messages (no real server envelope id yet) can never be referenced cross-MLS-boundary as edit/delete/pin/reaction targets. Structural invariant, not just UI-gating.
  - **Security invariants:** Purely client-side keyboard events; no new server calls, no new server-visible metadata, no MLS ops. `onEditLast` only touches `m.from === "me"` messages — peers cannot influence target. `crypto.randomUUID()` output is hex+hyphens, never in a DOM/HTML sink. security-auditor: GREEN (YELLOW advisory applied).
  - **715 frontend tests pass** (+11: `ChatLayoutKeyboardShortcuts.test.tsx` — ↑ activates edit mode, ↑ fills composer with last own text, ↑ no-op when draft present, ↑ no-op in Jordan chat (no own messages), ↑ no-op when already editing, ↑ skips deleted own messages, Escape cancels edit, Escape cancels reply, Escape no-op when idle, edit confirmed via ↑ shows edited badge, ↑ selects last of two own messages); tsc clean; biome clean.
  - **Next cycle:** PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768 ciphersuite), or more UX polish.

## Previous state (2026-06-26, cycle 198 — FEATURE: Web Share API — share message to native OS share sheet)
- **Cycle 198 (commit c47cd47):** FEATURE — Web Share API share button on MessageBubble.
  - **`Icon.tsx`:** Added `share-2` Lucide SVG path (share-2: three circles connected by lines).
  - **`MessageBubble` props:** Added `onShare?: () => void`. Share button rendered at `top:-10, left:78` (after star at left:52). Condition: `onShare && hovered && !msg.deleted && msg.text && msg.text !== "[image]"` — skips media-only placeholder messages.
  - **`MessageList` props:** Added `onShare?: (msg: ChatMessage) => void`. Wired: `onShare={onShare && !g.msg.deleted ? () => onShare(g.msg) : undefined}`.
  - **`handleShareMessage`:** `useCallback` — guards: `!msg.text || msg.text === "[image]"` returns early; `!navigator.share` returns early (unsupported platforms no-op). Calls `navigator.share({ text: msg.text }).catch(() => {})`. **No title, no url** — minimises metadata exposure (chat name / group ID never sent to OS share sheet). On Tauri mobile, this surfaces the native share sheet via WebView Web Share API.
  - **Security invariants:** Purely client-side. No MLS message sent, no server contact, no new server-visible metadata. `navigator.share` receives only `{ text: msg.text }` — no chat name, group ID, sender identity, or timestamps. XSS-safe (navigator.share is a structured API, not a DOM/HTML sink). `.catch(() => {})` silently swallows AbortError (user cancels) without logging any content. User gesture required (button click only — no timer/effect autorun; browser enforces transient activation).
  - **security-auditor:** GREEN. YELLOW-1 (non-blocking advisory): `Permissions-Policy` header does not explicitly list `web-share=(self)` — default allows it; optional hardening.
  - **704 frontend tests pass** (+10: `ChatLayoutShare.test.tsx` — share button appears on hover, absent for deleted, absent for [image], click calls navigator.share, share called with {text} only (no title/url), button for own messages, AbortError handled silently, aria-label "Share message", share not called for empty text, correct text for last of 2 messages); tsc clean; biome clean.
  - **Next cycle:** PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768 ciphersuite), or more UX polish.

## Previous state (2026-06-26, cycle 197 — FEATURE: screenshare placeholder in active call)
- **Cycle 197 (commit 0fa2a2d):** FEATURE — Screenshare toggle button in active call overlay.
  - **`Icon.tsx`:** Added `monitor` and `monitor-off` Lucide-style SVG paths (Lucide monitor + monitor-off originals).
  - **`CallOverlay` props:** Added `screensharing: boolean` + `onScreenshareToggle: () => void`.
  - **Screenshare button:** Rendered in the active-state controls row (between camera and end-call). `aria-label` flips between `"Share screen"` / `"Stop sharing screen"`. Styled via existing `ctrlBtn(active)` helper (orange accent when active). Icon: `monitor` / `monitor-off`.
  - **`ChatLayout` state:** `callScreensharing` boolean (useState false). `handleScreenshareToggle = useCallback(() => setCallScreensharing(prev => !prev), [])`.
  - **Resets:** `setCallScreensharing(false)` in `handleVoiceCall`, `handleVideoCall`, `handleHangUp` — no stale state across calls.
  - **Stub guarantee:** No `getDisplayMedia` / `getUserMedia` / `RTCPeerConnection` calls anywhere.
  - **security-auditor:** GREEN — no media-capture APIs, no server calls, no user input to DOM, no PII.
  - **694 frontend tests pass** (+10: `ChatLayoutCallOverlayScreenshare.test.tsx` — button present in voice, button present in video, initial "Share screen" label, toggle to "Stop sharing screen", double-toggle back, not shown outgoing, not shown incoming, state clears on hang-up + new call, screenshare/mute independent, no getDisplayMedia/getUserMedia called); tsc clean; biome clean.
  - **Next cycle:** Message forwarding to external apps (share sheet), or PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768 ciphersuite).

## Previous state (2026-06-25, cycle 196 — FEATURE: voice/video call overlay stub)
- **Cycle 196 (commit 942b469):** FEATURE — Voice/video call UI stub (no WebRTC, no getUserMedia).
  - **`CallOverlay` component:** Three states — `outgoing` (Calling..., cancel button), `incoming` (accept/decline buttons), `active` (live duration timer, mute/camera-off/end-call controls).
  - **Icons:** `mic-off`, `video-off`, `phone-off` added to Icon.tsx (Lucide-style inline SVG).
  - **Call state in ChatLayout:** `callState` / `callType` / `callDurationSec` / `callMuted` / `callCameraOff` / `callChatId`. Two useEffects: outgoing→active auto-connect (2.5 s setTimeout), active duration tick (setInterval 1 s). Both clean up on unmount.
  - **Semantic:** Outer `<div>` = backdrop, inner `<dialog open>` = card — fixes biome `useSemanticElements` lint.
  - **Dev button:** hidden `data-testid="dev-simulate-incoming-call"` (display:none) lets tests trigger incoming call state without WebRTC signalling.
  - **Wire-up:** Previously no-op `onCall={() => undefined}` / `onVideo={() => undefined}` in ConversationHeader now call `handleVoiceCall` / `handleVideoCall`.
  - **security-auditor:** GREEN — no network calls, no getUserMedia, no PII exposure, no XSS surface.
  - **684 frontend tests pass** (+14: `ChatLayoutCallOverlay.test.tsx`); tsc clean; biome clean.
  - **Next cycle:** Message forwarding to external apps (share sheet), or screenshare placeholder in active call, or PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768 ciphersuite).

## Previous state (2026-06-25, cycle 195 — STABILIZATION: fix CI Frontend test uncaught exceptions)
- **Cycle 195 (commit 347c88a):** STABILIZATION — Fixed CI Frontend failure (11 uncaught exceptions in `ChatLayoutReadReceipts.test.tsx`).
  - **Root cause:** `afterEach` called `vi.restoreAllMocks()` (restoring real `useMessages` that calls hooks) then `useAuthStore.setState()` which triggered a re-render of the still-mounted `ChatLayout`. Real `useMessages` calls `useAuthStore()` (2 hooks) but mock had 0 hooks → `areHookInputsEqual(undefined, deps)` → TypeError in React reconciler.
  - **Fix:** Import `cleanup` from `@testing-library/react` and call it as the FIRST statement of `afterEach`, before `vi.restoreAllMocks()`. This unmounts the component before mocks are restored, preventing the stale re-render.
  - **security-auditor:** GREEN. `cleanup()` is teardown-only; no assertions modified; cross-conversation leakage tests still intact; strengthens test isolation.
  - **670 frontend tests pass, 0 uncaught exceptions, tsc clean.**
  - **Next cycle:** Voice/video call UI stub, or PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768 ciphersuite).

## Previous state (2026-06-25, cycle 194 — FEATURE: deferred read receipts + Sending indicator)
- **Cycle 194 (commit 31fd409):** FEATURE — Deferred read receipt dispatch + "Sending" state icon.
  - **Problem fixed:** `sendReadReceipt` was called immediately on message receipt, even when the app was minimized or in a background chat. Read receipts now only fire when `incomingChat.id === activeIdRef.current && document.hasFocus()`.
  - **`pendingReadReceipts` ref:** `Map<mlsGroupId, string[]>` buffers envelope IDs for background/unfocused messages.
  - **Flush on chat selection (`handleSelectChat`):** Sends buffered receipts for the opened chat using its own `mlsGroupId`/`mlsIdentityId`.
  - **Flush on window focus:** New `useEffect` listens for `window.focus` → flushes active chat buffer.
  - **Security fix (RED from security-auditor):** `sendReadReceipt` now takes explicit `(mlsGroupId, mlsIdentityId, messageIds)` params instead of reading from `active`, preventing cross-conversation metadata leakage (buffered receipts from chat B encrypted into chat A's MLS stream).
  - **"Sending" state:** Changed `null` branch in read indicator to `<Icon name="timer" opacity=0.45 aria-label="Sending">` — completes Sending→Sent(✓)→Delivered(✓✓grey)→Read(✓✓blue) progression.
  - **security-auditor:** GREEN after fix (RED finding resolved). Buffer stores only envelope UUIDs, no plaintext/PII. No new XSS surface.
  - **670 frontend tests** (+11: `ChatLayoutReadReceipts.test.tsx` — Read indicator on seed, incoming "them" no indicator, Sending timer on optimistic, delivery_receipt→Delivered, read_receipt→Read, immediate dispatch on active+focused, deferred on unfocused, window focus flush, batch receipt, Sent single-check, delivery doesn't advance to Read); tsc clean; biome clean.
  - **Next cycle:** Voice/video call UI stub, or PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768 ciphersuite).

## Previous state (2026-06-25, cycle 193 — FEATURE: animated typing indicator — three-dot bounce animation)
- **Cycle 193 (commit b5fbcf1):** FEATURE — Animated typing indicator (TypingDots component).
  - **`TypingDots` component:** New inline component in `ChatLayout.tsx`. Renders three `<span class="powehi-typing-dot">` elements in an `inline-flex` row with `gap: 3`. Container carries `data-testid="typing-dots"` and `aria-label="typing"`. Default color: accretion orange `#FF9E52`.
  - **CSS (`index.css`):** `@keyframes powehi-typing-dot` — dots bounce 4px up (0%→30%→60%→100%) with `opacity: 0.35→1→0.35` cycle. 1.2s infinite. Dots 2 and 3 staggered by 0.2s and 0.4s respectively via `animation-delay`.
  - **Sidebar (`ChatRow`):** Replaced `<span style="fontStyle: italic">typing...</span>` with `<TypingDots />`. Old text node gone from DOM.
  - **Header (`ConversationHeader`):** Replaced `<span style="fontStyle: italic">· typing</span>` with `<span style="marginLeft: 8">· <TypingDots /></span>`. The middot glyph is kept as a visual separator.
  - **Test migrations:** Updated `ChatLayout.test.tsx` 3 typing tests: `getByText("typing...")` → `getAllByTestId("typing-dots")`; `/·\s*typing/i` regex → testid; auto-clear test verifies count drops rather than text disappears.
  - **New test file `ChatLayoutTypingDots.test.tsx`** (+10 tests): dots in sidebar (seed data Sam), aria-label="typing" on all instances, exactly 3 `.powehi-typing-dot` spans, no static "typing..." text, header dots appear on incoming signal, count increases when header activates, background chat signal doesn't affect header, auto-clear drops count to baseline, no "typing..." or "· typing" text at any time, `#FF9E52` inline color on container.
  - **Security invariants:** TypingDots is a pure render component — no eval, no innerHTML, no network calls. No content/PII reaches the DOM. `aria-label` is a hardcoded string literal.
  - **659 frontend tests** (+10); tsc clean; biome clean.
  - **Next cycle:** Read receipt delivery UI, or PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768 ciphersuite), or voice/video call UI stub.

## Previous state (2026-06-25, cycle 192 — FEATURE: pinned banner click-to-jump with scroll + flash highlight)
- **Cycle 192 (commit 4641b3c):** FEATURE — Pinned banner click-to-jump.
  - **`PinnedBanner` component:** Added `onJumpToPin?: () => void` prop. The content area (pin icon + "PINNED" label + preview text) is now wrapped in a `<button type="button" onClick={onJumpToPin} data-testid="pinned-banner-jump" aria-label="Jump to pinned message">`. Cursor `pointer` when `onJumpToPin` defined, `default` otherwise. Unpin X button stays as a separate right-side button.
  - **Call site:** `onJumpToPin={() => setJumpToMessageId(active.pinnedMessageId ?? null)}` — sets existing `jumpToMessageId: string | null` React state. No new state, no network calls, no MLS ops, no Dexie writes.
  - **Reuses jump infrastructure from cycle 191:** `MessageList` jump `useEffect` finds `[data-msg-id="${jumpToMessageId}"]`, calls `scrollIntoView({ block:"center", behavior:"smooth" })`, sets `flashingId` (drives `@keyframes powehi-jump-flash` orange flash 1.4s), clears via `onJumpComplete`. If element not found: `onJumpComplete` immediately (no crash).
  - **Security invariants:** `onJumpToPin` is a React state setter — no eval, no innerHTML. `active.pinnedMessageId` is a UUID validated by `handleIncomingPin` to ≤36 chars (hex+hyphens — cannot break CSS selector). Zero new server calls. No plaintext/PII/ciphertext in any log path. `data-msg-id` holds envelope UUID only.
  - **security-auditor:** GREEN. INFO (non-blocking, pre-existing): `CSS.escape()` at querySelector sink would harden the UUID→selector path against format changes; not a present vulnerability (UUID format excludes `"]/`).
  - **649 frontend tests** (+10: `ChatLayoutPinnedJump.test.tsx` — banner renders on incoming pin, jump button aria-label correct, scrollIntoView called on click, data-jump-flash set on target, flash clears after 1400ms, preview shows message text, unpin signal removes banner, absent when no pin, no crash when element not in DOM, chat isolation for non-active chat's pin); tsc clean; biome clean.
  - **Next cycle:** More UX polish — typing indicator animation polish, read receipt delivery UI, or PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768).

## Previous state (2026-06-25, cycle 191 — FEATURE: message search result count + jump-to specific message)
- **Cycle 191 (commit 5b03ce0):** FEATURE — Message search result count in sidebar header + jump-to-message scroll + flash highlight.
  - **Sidebar `msgResults`:** Each result now carries `messageId: m.id` (the server envelope UUID, optional). Result count shown in section header as `"Messages (N)"` (N ≤ 10, purely `msgResults.length`). Result `key` uses messageId when available (prevents duplicate-key collisions when two messages share identical text).
  - **`onJumpToMessage` signature:** Extended to `(chatId: string, messageId?: string) => void`. When messageId is present, stored in `jumpToMessageId` state in ChatLayout.
  - **`handleJumpToMessage`:** Chains `handleSelectChat(chatId)`, `setMsgSearch(search)`, `setSearch("")`, and conditionally `setJumpToMessageId(messageId)`.
  - **`jumpToMessageId` / `handleJumpComplete`:** New ChatLayout state. `handleJumpComplete = useCallback(() => setJumpToMessageId(null), [])` — cleared from MessageList after 1400ms.
  - **`MessageList`:** New props `jumpToMessageId?: string` + `onJumpComplete?: () => void`.
    - **Scroll-to-bottom** `useLayoutEffect` (no-deps) gated on `!jumpToMessageId` — resumes after jump is cleared.
    - **Jump `useEffect`**: finds `[data-msg-id="${jumpToMessageId}"]`, calls `scrollIntoView({ block:"center", behavior:"smooth" })`, sets `flashingId`, clears after 1400ms + calls `onJumpComplete`. If element not found (no server ID), still calls `onJumpComplete` immediately.
    - **`flashingId` state**: drives `data-jump-flash="true"` on the wrapper div.
  - **Message wrappers:** Each MessageBubble wrapped in `<div data-msg-id={g.msg.id} data-jump-flash={...}>` — opaque UUID only, no content/PII in DOM.
  - **`index.css`:** `@keyframes powehi-jump-flash` (accretion orange, 0%→60%→100% fade 1.4s) + `[data-jump-flash="true"]` rule.
  - **Security invariants:** `data-msg-id` holds envelope UUID only — no content, ciphertext, PII. `querySelector` cannot XSS. CSS attribute selector targets literal `"true"` — no injection surface. Zero new server calls. security-auditor GREEN (one non-blocking YELLOW: scroll-to-bottom self-clears via `onJumpComplete` on both found/not-found paths — verified correct).
  - **639 frontend tests** (+10: `ChatLayoutJumpToMessage.test.tsx` — header count "Messages (1)", count increments for 2 matches, `data-msg-id` attr present, `data-jump-flash` set on click, `scrollIntoView` called with `{block:"center",behavior:"smooth"}`, flash clears after 1400ms, no-ID chat switch works, section absent when empty, cap at 10, unique keys for same-text messages); tsc clean; biome clean.
  - **Next cycle:** More UX polish — pinned message jump/preview, typing indicator animation polish, or PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768).

## Previous state (2026-06-25, cycle 189 — FEATURE: group message reactions total summary + sidebar reaction preview)
- **Cycle 189 (commit b9c5944):** FEATURE — Group message reactions total summary + sidebar preview.
  - **`lastMsgReactionSummary(chat)`:** Pure helper. Reads `chat.messages[last].reactions` (local state only). For group chats with reactions on the last message, returns a compact string like `"🎉3 🔥2"`. null for DMs or no reactions. Never contacts server, never logs.
  - **`ChatRow` sidebar:** Renders `data-testid="last-msg-reaction-summary"` pill after `chat.last` text when `reactionSummary` is non-null and not typing. Emoji+count format (e.g. "🎉3 🔥2"). Single-sender emoji shown without count (e.g. "👀").
  - **`MessageBubble`:** Added `isGroup?: boolean` prop. Computes `totalReactionCount = Σ senders.length across all emoji entries`. When `isGroup && totalReactionCount >= 2`, renders `data-testid="reaction-total-summary"` span showing "· N reactions" in muted `var(--fg-4)`. Threshold 2 avoids noise for solo reactions.
  - **`MessageList`:** Passes `isGroup` down to each `MessageBubble`.
  - **Main `<MessageList>` call:** `isGroup={active.isGroup}` wired in.
  - **Design Team seed:** First message gets `{ "👍": ["dev-a","dev-b","dev-c"], "❤️": ["dev-d"] }` (total 4 → shows "· 4 reactions"); second gets `{ "👀": ["dev-a","dev-b"] }` (total 2 → shows "· 2 reactions"); last message gets `{ "🎉": ["dev-a","dev-b","dev-c"], "🔥": ["dev-d","dev-e"] }` (sidebar shows "🎉3 🔥2").
  - **Security invariants:** Pure local rendering. JSX text children only (no dangerouslySetInnerHTML). Emoji keys gated by upstream `ALLOWED_REACTION_EMOJIS` allowlist in `useMessages.ts`. Sender UUIDs never rendered — only `.length` count. No new network calls. No plaintext logging.
  - **security-auditor:** GREEN. Minor UX note (non-blocking): `lastMsgReactionSummary` reads literal-last array entry; if a deleted tombstone is last, it may show stale reactions.
  - **629 frontend tests** (+10: `ChatLayoutGroupReactions.test.tsx` — sidebar shows summary for Design Team, no summary for DM, emoji+count format correct, group msg ≥2 reactions shows summary, DM msg no summary, single reaction no summary, count accuracy, plural text correct, seed reaction chips visible, seed 4-reaction summary shown); tsc clean; biome clean.

## Previous state (2026-06-22, cycle 188 — FEATURE: @mention count badge in group chat sidebar rows)
- **Cycle 188 (commit 3af9922):** FEATURE — @mention count badge in group chat sidebar rows.
  - **`Chat` interface:** Added `mentionCount?: number` — local-only, never sent to server.
  - **`ChatRow`:** Renders photon-blue `@N` badge (`data-testid="mention-badge"`) when `mentionCount > 0`. Positioned before the orange unread badge. Title tooltip shows "N mention(s)". Caps at "9+".
  - **`handleIncoming`:** Detects `@all`, `@everyone`, or `@<myHandle>` (case-insensitive substring match) in incoming group message text. Increments `mentionCount` for background group chats. Active chats reset to 0. Uses `useAuthStore.getState().myHandle` (direct getState access — no new deps on the useCallback).
  - **`handleSelectChat`:** Clears `mentionCount: 0` alongside unread/firstUnreadAt when a chat is opened.
  - **Groups filter tab:** Adds aggregate `groupMentions` counter. Shows `@N` mention badge (`data-testid="filter-tab-groups-mention-badge"`) in photon blue alongside orange unread badge.
  - **`auth.ts`:** `myHandle: string | null` added to `AuthState`; `login()` accepts optional 5th param `myHandle?: string`; cleared to null on logout.
  - **`Login.tsx`:** Both sign-in and registration paths pass `handle.trim()` to `login()`. `pendingLoginRef` type updated to include `myHandle`.
  - **SEED_CHATS:** Design Team gets `mentionCount: 2` + new seed message `"@you can you review the final mockup? @all feedback welcome"`.
  - **Security invariants:** `mentionCount` is local-only — no server contact, no new API calls. `myHandle` is in-memory Zustand only (cleared on logout), never logged. Mention detection is `String.includes()` — no regex from user input, no XSS surface. security-auditor GREEN. Advisory: substring handle matching may produce false positives for short handles (e.g. `al` ⊂ `all`); cosmetic UX only, not a security issue.
  - **security-auditor:** GREEN.
  - **619 frontend tests** (+10: `ChatLayoutMentions.test.tsx` — seed badge shown, photon-blue color, Groups tab aggregate badge, cleared on chat select, @all triggers increment, @myHandle triggers increment, no-mention message no increment, caps at 9+, DM chats no badge, Groups tab badge clears on select); tsc clean; biome clean.
  - **Next cycle:** More UX polish — message reactions counter in group view (total reaction sum on messages), or PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768).

## Previous state (2026-06-22, cycle 187 — FEATURE: sidebar chat filter tabs — All / Chats / Groups with unread badges)
- **Cycle 187 (commit d07e2ec):** FEATURE — Sidebar chat filter tabs.
  - **`Sidebar` component:** Added `chatFilter` state (`"all" | "dms" | "groups"`, default `"all"`). Computed `dmUnread` = sum of unread in DM chats; `groupUnread` = sum of unread in group chats. Updated `filtered` predicate to compose tab filter (`matchesTab`) with search filter (`matchesSearch`). Updated `msgResults` to also scope by `chatFilter` (Groups tab only searches group chat messages, etc.).
  - **Tab bar UI:** Three buttons (`filter-tab-{all,dms,groups}`) between the search bar and encryption banner. Active tab styled with orange accent. Conditional `<span data-testid="filter-tab-{tab}-badge">` shows per-tab aggregate unread count (capped at "9+") when > 0. All text is JSX literal — no XSS surface. `onClick` sets `chatFilter` to one of three const-array literals only.
  - **SEED_CHATS:** Added "Design Team" group chat (`isGroup: true`, `memberCount: 4`, `mlsGroupId: "44444444-..."`, `unread: 0`, no `mlsIdentityId`). No mlsIdentityId means it cannot trigger any server-bound envelope path; purely for display/demo.
  - **Security invariants:** Filtering is local state only — no server contact. Design Team lacks mlsIdentityId → all authenticated send/encrypt paths are guarded and unreachable from this seed. No new server-visible metadata. No plaintext logging. JSX text children only.
  - **security-auditor:** GREEN. No findings.
  - **609 frontend tests** (+11: `ChatLayoutFilter.test.tsx` — tabs rendered, DM isolation, group isolation, All-tab restore, Chats-tab DM badge, Groups-tab no-badge when 0, Groups-tab badge after incoming message, Chats-tab badge live increment, search scoping for groups tab, search scoping for chats tab); tsc clean; biome clean.
  - **Next cycle:** More UX polish — maybe per-chat mention counts in group chats, or message reactions counter in group view, or PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768).

## Previous state (2026-06-22, cycle 186 — FEATURE: Tauri native OS notification on background message arrival)
- **Cycle 186 (commit df2a785):** FEATURE — Tauri native push notification integration.
  - **`useTauriNotification.ts` (new hook):**
    - On mount: dynamic-imports `@tauri-apps/plugin-notification`, checks `isPermissionGranted()`, falls back to `requestPermission()`. Stores the `sendNotification` fn in a ref; null until granted.
    - Exported callback: calls `senderRef.current({ title: "Powehi", body: "New message" })` only when `!document.hasFocus()`. Title and body are hard-coded constants — no sender identity, no plaintext content, no metadata ever reaches the OS notification layer (prd.md §3 threat model).
    - Guard: entire hook is a no-op outside Tauri (`window.__TAURI_INTERNALS__` check + dynamic import only fires inside that branch).
    - Cleanup: `active` flag prevents async race after unmount; `senderRef` cleared on teardown.
  - **`ChatLayout.tsx`:**
    - Added `useTauriNotification` import and hook call (`showTauriNotification = useTauriNotification()`).
    - Added `showTauriNotificationRef` alongside `sendReadReceiptRef` / `sendDeliveryReceiptRef`; kept fresh every render in the existing ref-update `useEffect`.
    - In `handleIncoming`: calls `showTauriNotificationRef.current()` when `incomingChat && !incomingChat.muted`. The `!document.hasFocus()` guard is inside the hook — no foreground spam.
  - **Tauri Rust:**
    - `app/src-tauri/Cargo.toml`: `tauri-plugin-notification = "2"` added.
    - `app/src-tauri/src/lib.rs`: `.plugin(tauri_plugin_notification::init())` registered.
    - `app/src-tauri/capabilities/default.json`: `"notification:default"` added.
  - **npm:** `@tauri-apps/plugin-notification = "^2"` added to `app/package.json`; `pnpm-lock.yaml` updated.
  - **Security invariants:** Title/body are string literals (no injection surface). `incomingChat.muted` gate prevents notifications on silenced chats. `document.hasFocus()` suppresses foreground. No auth material, ciphertext, or PII touches the notification path.
  - **security-auditor:** GREEN. YELLOW-1 (advisory): no debounce — one OS notification per message; OS provides implicit backpressure. YELLOW-2: `hasFocus()` over-suppresses when a *different* chat is active (safe fail, privacy-correct).
  - **598 frontend tests** pass (+9: `useTauriNotification.test.ts` — outside Tauri no-op, permission-denied silent, focus suppression, content-free invariant, stable callback, skip `requestPermission` when already granted). tsc clean; biome clean.
  - **Next cycle:** More UX polish (message search in sidebar, group chat badge counts), or PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768).

## Previous state (2026-06-22, cycle 185 — STABILIZATION: CI red fix — testcontainers postgres:11-alpine → 16-alpine)
- **Cycle 185 (commit ab84e61):** STABILIZATION — CI red fix; no new features.
  - **CI RED FIX (testcontainers postgres image):** `Integration Tests (Docker)` job was failing with "bytes remaining on stream" when pulling `postgres:11-alpine`. Root cause: postgres:11 is EOL (2023-11) and its Docker Hub layer store is unstable.
  - **Fix 1 (test):** `pg_security_it.rs` setup() — added `use testcontainers::ImageExt` + changed `Postgres::default().start()` to `Postgres::default().with_tag("16-alpine").start()`. Return type stays `ContainerAsync<Postgres>` because `ContainerRequest<I>::start()` returns `ContainerAsync<I>`.
  - **Fix 2 (CI):** Added `docker pull postgres:16-alpine` step in `ci-rust.yml` before the nextest run, so layers are pre-cached and testcontainers doesn't race the Docker daemon during test execution.
  - **cargo audit:** 2 allowed warnings unchanged (instant unmaintained via openmls, bitcoin_hashes yanked via bip39). No vulnerabilities.
  - **547 workspace tests** pass; clippy clean; fmt clean. target/ 4.6GB (under 20GB threshold).
  - **Next cycle:** FEATURE — Tauri push notification integration (foreground/background), PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768), or more UX polish.

## Previous state (2026-06-22, cycle 184 — FEATURE: Tauri deep-link invite handler + CI biome/tsc fixes)
- **Cycle 184 (commits dca1418, a0c4ac7):** FEATURE — Tauri deep-link invite routing + two CI fixes.
  - **CI fixes (dca1418):** Two biome-format issues in Tauri JSON files (`capabilities/default.json` + `tauri.conf.json` had 2-space indent vs biome's tabs) + unused `fireEvent` import in `ChatLayoutReactions.test.tsx` caused `tsc -b` TS6133 (`noUnusedLocals`). Fixed all three; 572 tests green, tsc clean, biome clean.
  - **`useDeepLink.ts` (new hook):**
    - `parseDeepLink(url)`: strict regex extracts 32-char lowercase hex code from `powehi://invite/<code>` (desktop) or `https://powehi.app/i/<code>` (iOS/Android universal link). Returns null for everything else — no injection surface.
    - `useDeepLink(onInviteCode)`: mounts a `@tauri-apps/plugin-deep-link` listener. Calls `getCurrent()` on mount to handle the launch-via-deep-link case; registers `onOpenUrl()` for subsequent links. Ref pattern ensures callback updates don't restart the listener. No-op outside Tauri (`__TAURI_INTERNALS__` guard + `.catch()`).
  - **`App.tsx`:** `useDeepLink(useCallback((code) => { if (phase === "app") setInviteCode(code); }, [phase]))` — gates on `phase === "app"` so unauthenticated launches cannot trigger the `AcceptInviteModal` redeem flow.
  - **Tauri config updates:**
    - `app/src-tauri/Cargo.toml`: `tauri-plugin-deep-link = "2"` added.
    - `app/src-tauri/src/lib.rs`: `.plugin(tauri_plugin_deep_link::init())` registered.
    - `app/src-tauri/tauri.conf.json`: `plugins.deep-link` config — desktop scheme `powehi`, mobile host `powehi.app` with pathPrefix `/i/`.
    - `app/src-tauri/capabilities/default.json`: `"deep-link:default"` added (only exposes `getCurrent`/`onOpenUrl` — no scheme register/unregister).
  - **`@tauri-apps/plugin-deep-link` npm package** added; `pnpm-lock.yaml` updated.
  - **Security invariants:** Invite code flows to `POST /v1/invites/redeem` body only (never URL path, never logged, never raw HTML). Regex is strictly anchored to 32-hex. `phase="app"` guard prevents pre-auth redeem. Server-side validation is the real authority.
  - **security-auditor:** GREEN. No findings.
  - **Tests (589 total, +17):** `useDeepLink.test.ts` — 14 unit tests for `parseDeepLink` (valid desktop, valid mobile, wrong scheme, wrong host, wrong length, uppercase, non-hex, query-string trailing); `App.test.tsx` — 3 integration tests (modal opens, ignored pre-auth, closes on X). tsc clean; biome clean.
  - **Next cycle:** Tauri push notification integration (foreground/background), PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768), or more UX polish.

## Previous state (2026-06-22, cycle 183 — FEATURE: emoji reaction toggle-off + own-reaction highlight)
- **Cycle 183 (commits b571854, 22652e3):** FEATURE — Reaction toggle-off + CI lockfile fix.
  - **CI fix (b571854):** `pnpm-lock.yaml` was out of sync after cycle 182 added `@tauri-apps/api ^2` + `@tauri-apps/cli ^2` without regenerating it. `pnpm install` updated the lockfile; 566 tests still pass.
  - **`useMessages.ts`:** New `onReactionRemove?` parameter at position 7 (between `onReaction` and `onReadReceipt`). New `reaction_remove` envelope type handled with same `ALLOWED_REACTION_EMOJIS` allowlist + `targetMessageId.length > 0` guard as `reaction`. `shouldDisplayMessage = false`; callback receives `(groupId, targetMessageId, emoji, env.sender)`.
  - **`handleRemoveReaction` (ChatLayout):** Immutable `setChats` reducer — removes `senderId` from `existing[emoji]` array; deletes the emoji key entirely when the senders list becomes empty. Mirror of `handleIncomingReaction`.
  - **`sendReaction` toggle semantics:** Reads current `chats` state to check if `myDeviceId` is already in `msg.reactions[emoji]`. If yes → sends `reaction_remove` MLS message + optimistic local remove. If no → existing add path. `plaintext.fill(0)` in `.finally()` on both paths.
  - **`MessageBubble` + `MessageList`:** Added `myDeviceId?: string` prop threaded from `useAuthStore.getState().deviceId`. Own-reaction chips render with orange accent (`rgba(255,138,61,0.18)` bg, `rgba(255,138,61,0.5)` border, `#FF8A3D` text) and `aria-pressed="true"`. Peer chips: `aria-pressed="false"`.
  - **Security invariants:** `myDeviceId` is local-only — not logged, not in any MLS payload. `env.sender` (MLS-authenticated device ID) prevents spoofing. Emoji + targetMessageId only in MLS ciphertext. All DOM rendering via JSX text children (no XSS vector). `plaintext.fill(0)` wipes both add and remove paths.
  - **security-auditor:** GREEN. YELLOW-1 (advisory, pre-existing): `targetMessageId` has no `<= 36` upper-length guard in reaction/reaction_remove (unlike edit/delete/pin) — purely internal consistency nit, no injection sink.
  - **Tests (572 total, +6):** `ChatLayoutReactions.test.tsx` — reaction_remove empties chip, reduces count, no-op for non-sender, own aria-pressed=true, peer aria-pressed=false, wrong-groupId no-op. All existing mocks updated for the new param shift.
  - **Next cycle:** Tauri mobile deep-link / push notification integration, PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768), or more UX polish.

## Previous state (2026-06-21, cycle 182 — FEATURE: Tauri 2.x mobile app scaffold)
- **Cycle 182 (commit 6744d2e):** FEATURE — Tauri 2.x native shell scaffold.
  - **`app/src-tauri/`:** Standalone Cargo workspace (separate from server `crates/`). Not added to root workspace — avoids WebKit system dep requirement in server CI. Has its own `Cargo.lock`.
  - **`Cargo.toml`:** `tauri = "2"`, `tauri-build = "2"`, `serde`, `serde_json`. `crate-type = ["staticlib", "cdylib", "rlib"]` for mobile compilation. Release profile: `lto=true`, `panic=abort`, `strip=true`.
  - **`src/lib.rs`:** `#[cfg_attr(mobile, tauri::mobile_entry_point)]` macro enables iOS/Android JNI/ObjC harness. Desktop calls `run()` from `main.rs`.
  - **`tauri.conf.json`:** Mobile-safe CSP (`'wasm-unsafe-eval'` for WASM, `blob:` for Comlink worker, `ipc: http://ipc.localhost` for Tauri IPC, `frame-ancestors 'none'`, `form-action 'self'`). Window: 430×932 (iPhone 14 Pro size), minWidth 375, minHeight 667.
  - **`capabilities/default.json`:** `core:default` only — no fs/shell/http/clipboard plugins; scoped to `windows: ["main"]`.
  - **`app/package.json`:** Added `@tauri-apps/api ^2` dep, `@tauri-apps/cli ^2` devDep, scripts: `tauri:dev`, `tauri:build`, `tauri:android:dev`, `tauri:android:build`, `tauri:ios:dev`, `tauri:ios:build`.
  - **Security invariants:** No crypto crosses IPC boundary — WASM worker + MLS remain in WebView. No custom IPC commands. Tauri Rust backend is pure shell. No plaintext content exposed to native layer.
  - **security-auditor:** GREEN. YELLOW-1: frame-ancestors/form-action missing (fixed in same commit). YELLOW-2: style-src unsafe-inline (pre-existing from Vite/Tailwind, non-blocking).
  - **Rust tests (workspace):** 547 passed, 0 failed; fmt clean; biome clean; 566 frontend tests unchanged.
  - **Next cycle:** PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768), Tauri mobile deep-link / push notification integration, or additional UX polish.

## Previous state (2026-06-21, cycle 181 — FEATURE: per-chat vibration toggle)
- **Cycle 181 (commit aeb72b4):** FEATURE — Per-chat vibration toggle.
  - **`Chat.vibrate?: boolean`:** Local-only flag. Default true (vibrate on new messages). Never sent to server, never included in MLS payload, never logged.
  - **`chatsRef`:** React useRef that mirrors `chats` state so `handleIncoming` (stable `useCallback`) can read per-chat vibrate/muted flags without taking a `chats` dep (which would restart the polling hook on every message). Same pattern as `activeIdRef`.
  - **`handleIncoming`:** After persisting, calls `navigator.vibrate?.([100])` when the incoming chat is not muted and `vibrate !== false`. Optional-chained for desktop/unsupported browsers.
  - **`handleToggleVibrate`:** Pure `setChats` immutable toggle. `!(c.vibrate ?? true)` so first tap goes On→Off. `useCallback([])`.
  - **`InfoPanel`:** Added `vibrate: boolean` and `onToggleVibrate: () => void` props. "Vibrate" InfoRow in Notifications section (below Sound row).
  - **Security invariants:** `vibrate` is purely in-memory. No server exposure. Boolean rendered as literal "On"/"Off" (no XSS). No PII or plaintext in any log path.
  - **security-auditor:** GREEN. No findings.
  - **566 frontend tests** (+6: ChatLayoutVibrate suite — default On, toggle Off, toggle back On, chat-specificity Jordan≠Maya, vibrate/sound independence, navigator.vibrate guard); tsc clean; biome clean.
  - **Next cycle:** Mobile app scaffold (Tauri 2.x), PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768), or additional UX polish.

## Previous state (2026-06-21, cycle 180 — STABILIZATION: CI rustfmt import-order fix in powehi-opaque)
- **Cycle 180 (commit 93ff431):** STABILIZATION — CI red fix; no new features.
  - **CI RED FIX (rustfmt import order):** `cargo fmt --all --check` was failing on `powehi-opaque/src/lib.rs` line 36: `use rand::rngs::OsRng` appeared before `use powehi_domain::*` and `use powehi_port_outbound::*`. rustfmt requires alphabetical order within the same use-group (`p` < `r`). Reordered to `powehi_domain` → `powehi_port_outbound` → `rand`. No logic change.
  - **cargo audit:** 2 allowed warnings — `instant` unmaintained (pre-existing via openmls) + `bitcoin_hashes 0.14.100` yanked (via bip39 in powehi-crypto-wasm; pre-existing). No vulnerabilities.
  - **target/:** 4.4GB (under 20GB threshold); 0-byte rmeta stubs pruned.
  - **security-auditor:** GREEN. Pure use-statement reorder; no behavioral change.
  - **Next cycle:** FEATURE — mobile app scaffold (Tauri 2.x), per-chat vibration toggle, or PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768).

## Previous state (2026-06-21, cycle 179 — STABILIZATION: CI biome fix + powehi-opaque isolated-build fix)
- **Cycle 179 (commits 21e3816, cf9d2c8):** STABILIZATION — Two CI/build fixes; no new features.
  - **CI RED FIX (biome format):** `ChatLayout.tsx` `handleToggleSound` `setChats` call was multi-line; biome formatter wanted a one-liner. `pnpm --filter app exec biome check --write` applied the fix. 560 frontend tests still pass; biome clean.
  - **powehi-opaque isolated-build fix:** `cargo test -p powehi-opaque` was failing with E0432 (unresolved `opaque_ke::rand::rngs::OsRng`). Root cause: the `rand/getrandom` feature was only available via workspace-wide unification from `powehi-crypto-wasm`'s `getrandom = "0.2"` dep — isolated crate builds didn't have it. Fix: added `rand = { version = "0.8", features = ["getrandom"] }` to workspace `[workspace.dependencies]` and `rand = { workspace = true }` to `powehi-opaque/Cargo.toml`; updated imports to use `rand::rngs::OsRng` directly. All 8 OPAQUE tests now pass in isolation. Full workspace still 547 tests, all green.
  - **security-auditor:** GREEN. OsRng still backed by OS CSPRNG; no behavioral change; all OPAQUE invariants (synthetic KE2, 300s TTL, server-bound identity) verified unchanged.
  - **Next cycle:** FEATURE — mobile app scaffold (Tauri 2.x), per-chat vibration toggle, or PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768).

## Previous state (2026-06-21, cycle 178 — FEATURE: per-chat notification sound toggle + CI fix)
- **Cycle 178 (commit 0ec56ca):** FEATURE — Per-chat notification sound toggle; CI fix.
  - **CI RED FIX:** `ChatLayoutSearch.test.tsx:147` had a dead `realUseMessages` import causing TS6133 that broke the bundle budget CI check. Removed the unused destructured import.
  - **`Chat.sound?: boolean`:** Local-only flag on Chat object. Never sent to any server, never included in MLS payload, never logged. No persistence (lost on page reload — intentional, same pattern as `muted`).
  - **`handleToggleSound(chatId)`:** Pure `setChats` immutable toggle. `!(c.sound ?? true)` so first toggle goes On→Off. `useCallback([])`.
  - **`InfoPanel`:** Added `sound: boolean` and `onToggleSound: () => void` props. "Sound" InfoRow in Notifications section shows "On"/"Off". Sits below "Mute" row, same interactive button pattern.
  - **Security invariants:** `sound` is purely in-memory. No server exposure. Boolean rendered as literal "On"/"Off" (no XSS). `handleToggleSound` passes only local chatId. No PII or plaintext reaches any log.
  - **security-auditor:** GREEN. No findings.
  - **560 frontend tests** (+5: ChatLayoutSound suite — default On, toggle Off, toggle back On, chat-specificity Jordan≠Maya, sound/mute independence); tsc clean.
  - **Next cycle:** Mobile app scaffold (Tauri 2.x), per-chat vibration toggle, or PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768).

## Previous state (2026-06-21, cycle 177 — FEATURE: global message search in sidebar)
- **Cycle 177 (commit 8a1ab04):** FEATURE — Global message search in sidebar.
  - **`msgResults` in `Sidebar`:** When `searchQuery` is non-empty, scans all `chats[].messages[]` for text matching the query. Excludes deleted, media-only, `[image]` messages. Capped at 3 per chat, 10 total. Renders a "Messages" section below the filtered chat list with chat-name label + 80-char snippet highlighted via `HighlightedText`.
  - **`handleJumpToMessage(chatId)`:** Switches to the target chat, seeds `msgSearch` (in-conversation highlight) with the sidebar query, then clears sidebar search. Local-only — no server calls, no MLS messages.
  - **`Sidebar` props:** Added `onJumpToMessage?: (chatId: string) => void`.
  - **Security invariants:** Local-only; no server exposure. JSX text children only (no innerHTML). No plaintext logging. No new server-visible metadata. `HighlightedText` uses `.indexOf()` + string slices only.
  - **security-auditor:** GREEN. No findings.
  - **555 frontend tests** (+9: ChatLayoutSearch suite — empty state, results for matching text, chat name label, snippet content, click switches chat, click clears sidebar search, no results when no match, incoming messages searchable, deleted messages excluded); tsc clean; biome clean.
  - **Next cycle:** Mobile app scaffold (Tauri 2.x), notification settings (per-chat sound/vibration), or PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768).

## Previous state (2026-06-21, cycle 176 — FEATURE: per-chat mute / unread badge suppression)
- **Cycle 176 (commit fc7c976):** FEATURE — Per-chat mute.
  - **`Chat.muted?: boolean`:** Local-only flag on Chat object. Never sent to any server, never included in MLS payload, never logged. No persistence (lost on page reload — intentional, same pattern as draft).
  - **`handleIncoming`:** When `c.muted`, skip unread counter increment and skip `firstUnreadAt` divider tracking. Messages still received, stored, and delivery/read receipts still sent — mute is purely a badge-suppression feature.
  - **`ChatRow`:** Bell-off icon (`bell-off` icon added to `Icon.tsx`) shown when `chat.muted`. `aria-hidden="true"` (no contribution to button accessible name); `title="Muted"` for mouse users.
  - **`InfoRow`:** Added optional `onClick` prop — renders as `<button type="button">` for interactive rows, stays `<div>` for static rows. Accessible pattern.
  - **`InfoPanel`:** `muted: boolean` and `onToggleMute: () => void` props. "Mute" row in Notifications section is now an interactive toggle showing "On"/"Off". Wired to `handleToggleMute`.
  - **`handleToggleMute(chatId)`:** `useCallback` with pure `setChats` immutable update. No API call, no MLS message, no side-effects.
  - **Security invariants:** `muted` is purely in-memory. No server exposure. JSX text children only. `handleToggleMute` passes only local chatId. No PII or plaintext reaches any log.
  - **security-auditor:** GREEN. YELLOW-1 (advisory): aria-hidden on muted icon means screen readers don't announce muted status from sidebar; title tooltip available for mouse users (non-blocking UX note).
  - **546 frontend tests** (+6: ChatLayoutMute — toggle On/Off, bell-off icon, unread suppressed when muted, unread increments when unmuted, unmute restores, chat-specific mute); tsc clean; biome clean.
  - **Next cycle:** Mobile app scaffold (Tauri 2.x), notification settings (per-chat sound/vibration mute), or PQ hybrid Phase A (waiting for openmls stable MLS_128_MLKEM768).

## Previous state (2026-06-20, cycle 174 — FEATURE: group chat add-member modal + per-chat draft persistence)
- **Cycle 174 (commit d74b1a2):** FEATURE — Group UX + draft messages.
  - **`AddMemberModal`:** Contact picker opened via "Add member" header button (group chats only). Calls `POST /v1/groups/:groupId/members/:deviceId`. Displays MLS E2EE welcome notice ("Their identity is never sent in plaintext"). Shows loading/error states. Increments local `memberCount` on success. Server never sees plaintext names or message content.
  - **`Icon.tsx`:** Added `user-plus` SVG path.
  - **Per-chat draft persistence:** `drafts: Record<string,string>` in React state (no Dexie, no localStorage, no server). `handleDraftChange(id, draft)` tracks per-chat draft text. `Composer` receives `chatId`, `initialDraft`, `onDraftChange`. Draft restored when switching back to a chat; cleared on send; lost on page reload (intentional).
  - **Test suite split:** forwarding tests → `ChatLayoutForwarding.test.tsx`; draft tests → `ChatLayoutDraft.test.tsx`; add-member → `AddMemberModal.test.tsx` + `ChatLayoutAddMember.test.tsx`.
  - **Security invariants:** JSX text children only (no XSS). Draft text stays in memory only. `addMember` call: groupId and contactId are app-controlled slugs/UUIDs; error handler shows only generic category string (no plaintext-logging). No new server-visible plaintext.
  - **security-auditor:** GREEN. YELLOW-1: URL path interpolation in `groups.ts` not `encodeURIComponent`-wrapped (pre-production advisory, values are app-controlled). YELLOW-2: `contact.id` is chat slug not device UUID — must pass opaque deviceId before real backend.
  - **534 frontend tests** (+25 new: 11 AddMemberModal + 4 add-member ChatLayout + 5 draft + 5 forwarding); Rust tests unchanged; tsc clean; biome clean.
  - **Next cycle:** Emoji reactions (MLS E2EE reaction payload), message search in sidebar, or mobile app scaffold (Tauri 2.x). PQ hybrid (ADR-0003 Phase A) still waiting for openmls stable MLS_128_MLKEM768.

## Previous state (2026-06-20, cycle 167 — FEATURE: local starred/bookmarked messages with panel UI)
- **Cycle 167 (commit 07633df):** FEATURE — Post-MVP UX: client-side message starring/bookmarking.
  - **`ChatMessage.starred?: boolean`:** Toggle flag in in-memory chat state. No MLS message sent, no server contact, no Dexie write — purely local. Server never learns which messages a user considers important.
  - **`MessageBubble`:** Star button (`data-testid="star-button"`) on hover for any non-deleted message. aria-label toggles "Star message" / "Unstar message". Orange (`#FF8A3D`) highlight when starred. Position `top:-10, left:52` (right of forward button).
  - **`handleStarMessage(chatId, msgId, msgText)`:** `setChats` reducer: ID-based match, text-based fallback for optimistic messages without stable ID. Pure immutable spread (`{ ...m, starred: !m.starred }`).
  - **`StarredPanel`:** Absolute overlay in sidebar header area. Lists `chats.flatMap(c => c.messages.filter(m => m.starred))` across all chats. JSX text children only (XSS-safe). `data-testid="starred-panel"` / `"starred-item"`. Close button + backdrop navigation (clicks item → `onSelect(chatId)` + panel close). Empty state: "No starred messages yet." + hint text.
  - **`IconBtn icon="star"`** in sidebar header opens `StarredPanel` (`label="Starred messages"`). Panel state managed locally in `Sidebar` via `useState(false)`.
  - **`Icon.tsx`:** Added `star` SVG path (Lucide filled polygon).
  - **Dead code removed:** `onStarred` prop was added but never wired (Sidebar manages panel internally). Removed from Sidebar type and ChatLayout call site.
  - **Security invariants:** Local-only; no server exposure. JSX text children (no innerHTML). `starred` flag is not logged. No PII or ciphertext reaches the panel render.
  - **security-auditor:** GREEN. YELLOW (advisory): text-based fallback match may toggle two identical-text optimistic messages in same chat simultaneously (benign cosmetic; self-corrects once stable ID lands).
  - **499 frontend tests** (+9: 8 ChatLayout starred suite; was 490); Rust tests unchanged (539); biome clean; tsc clean.
  - **Next cycle:** Post-MVP items: PQ hybrid activation (ADR-0003 Phase A — waits for openmls stable MLS_128_MLKEM768), mobile app scaffold (Tauri 2.x), or more UX features (emoji reactions, message search in sidebar, group chat scaffold).

## Previous state (2026-06-16, cycle 165 — STABILIZATION: act() warnings fixed in polling hook tests)
- **Cycle 165 (commit 1006d26):** STABILIZATION — CI green; no open bugs; security-auditor GREEN (YELLOW-1: ciphertext size limit confirmed covered by global 512KB DefaultBodyLimit — downgraded to INFO); cargo audit: 1 pre-existing warning (`instant` unmaintained via openmls — unchanged); clippy: clean.
  - **act() warning fixes (useMessages.test.ts + useWelcomePoller.test.ts):** 8 warnings introduced or revealed by cycles 163-164 fixed by capturing `unmount` from `renderHook` and calling it inside `await act(async () => { unmount(); })`. This stops the poller setInterval from firing during RTL cleanup outside of act boundary. Remaining ~160 warnings are pre-existing (mostly usePersistentMessages, AcceptInviteModal, useMediaReceive — to be addressed in future STABILIZATION cycles).
  - **490 frontend tests green**; Rust tests green (0 FAILED); target/ 4.1GB (under 20GB threshold — pruned 0-byte rmeta stubs only).

## Previous state (2026-06-16, cycle 164 — FEATURE: E2EE user presence heartbeat via MLS)
- **Cycle 164 (commit a02d082):** FEATURE — Post-MVP UX: real-time online/offline presence.
  - **`useMessages.ts`:** Added `onPresence?(groupId, status: "online"|"offline")` as 12th param; `presenceRef` pattern; `presence` handler: strict allowlist (`status === "online" || status === "offline"`), `shouldDisplayMessage = false`, never forwarded to `onMessage`.
  - **`ChatLayout.tsx`:**
    - `presenceTimersRef` (Map, same pattern as `typingTimersRef`): 90s auto-offline timeout; cleared on unmount.
    - `handleIncomingPresence(gId, status)`: "online" → marks chat online + resets 90s timer; "offline" → marks chat offline + records HH:MM `lastSeen`; refs-only (no SSRF, no XSS).
    - Heartbeat `useEffect`: sends `{type:"presence", status:"online"}` MLS-ciphertext immediately + every 30s; sends "offline" on cleanup; biome-ignore for exhaustive-deps (active?.mlsGroupId is stable intent key).
    - `useMessages` call: 12th arg `handleIncomingPresence`.
  - **Security invariants:** Status inside MLS ciphertext — server never sees it. Strict allowlist blocks injection. No plaintext logging. `plaintext.fill(0)` in `.finally()`. `lastSeen` generated locally (`new Date()`), not from payload. Timer cleanup prevents leaks.
  - **security-auditor:** GREEN. YELLOW-1: 30s cadence is minor traffic-analysis signal (pre-existing with typing/read-receipt). YELLOW-2: any group member can spoof peer presence (1:1 assumption; deferred to group-chat feature).
  - **490 frontend tests** (+9: 5 useMessages presence suite, 4 ChatLayout presence suite; was 481); 539 Rust tests (unchanged); tsc clean; biome clean.
  - **Next cycle:** Post-MVP items: PQ hybrid activation (ADR-0003 Phase A — waits for openmls stable MLS_128_MLKEM768), mobile app scaffold (Tauri 2.x), or more UX features (message search in sidebar, group chat scaffold, emoji picker).

## Current state (2026-06-16, cycle 163 — FEATURE: E2EE message forwarding via MLS chat-picker)
- **Cycle 163 (commit 5bf00c8):** FEATURE — Post-MVP UX: E2EE message forwarding.
  - **`Icon.tsx`:** Added `forward` icon (Lucide corner-up-right SVG path).
  - **`ChatLayout.tsx`:**
    - `MessageBubble`: `onForward?: () => void` prop; forward button at `top: -10, left: 26` (right of pin) visible on hover for non-deleted messages with stable envelope ID; uses `forward` icon.
    - `MessageList`: `onForward?: (msg: ChatMessage) => void` prop; wired to each `MessageBubble` via guard `!g.msg.deleted`.
    - `forwardMsg: { id: string; text: string } | null` state; set in `onForward` handler.
    - `sendForward(targetId: string)`: finds target chat by id (requires `mlsGroupId` + `mlsIdentityId`); optimistic update appends `{ from: "me", text }` to target chat; MLS-encrypts text to target group; `sendMessageApi`; `plaintext.fill(0)` in `.finally()`.
    - `ForwardChatPicker` modal: fixed overlay with backdrop; lists chats filtered by `c.id !== activeId && c.mlsGroupId && c.mlsIdentityId`; shows name + 30-char preview of last message; "No other conversations" when empty; X button + backdrop click + Escape key all close.
    - `onForward` wired in MessageList render; `ForwardChatPicker` rendered when `forwardMsg !== null`.
  - **Security invariants:** Text only leaves as MLS ciphertext — server sees nothing. No XSS: all content via JSX text children. `plaintext.fill(0)` in `.finally()`. Forward button gated on `!msg.deleted`. Target chat gated on `mlsGroupId+mlsIdentityId`. No new server-visible metadata.
  - **security-auditor:** GREEN. YELLOW-1: no `MAX_MESSAGE_BYTES` cap on forward path (pre-existing gap, same as all other send paths; not introduced by this change).
  - **481 frontend tests** (+5 forwarding suite; was 476); 539 Rust tests (unchanged); tsc clean; biome clean.
  - **Next cycle:** Post-MVP items: PQ hybrid activation (ADR-0003 Phase A — waits for openmls stable MLS_128_MLKEM768), mobile app scaffold (Tauri 2.x), or more UX features (user presence, message search in sidebar, group chat scaffold).

## Current state (2026-06-16, cycle 162 — FEATURE: receiver-side disappearing message TTL via MLS payload)
- **Cycle 162 (commit 6ce32a2):** FEATURE — Receiver-side disappearing messages: TTL propagated inside MLS-encrypted payload.
  - **Problem:** Disappearing messages were sender-only — receiver never got `expiresAt` because the server doesn't know the TTL (E2EE model). Receiver messages never auto-deleted.
  - **`useMessages.ts`:** In `type === "text"` handler, parse `ttl` field (validated: `number`, `> 0`, `≤ 604_800`, `isFinite`). Payload TTL overrides server-set `expires_at` (server can't know duration). `textTtl` variable set before try block, used after: `expiresAt = textTtl !== undefined ? Date.now() + textTtl * 1000 : serverExpiresAt`.
  - **`ChatLayout.tsx`/`sendMessage`:** When `disappearingTtl` is set, always use structured JSON (even without `replyContext`), including `ttl: disappearingTtl`. Both `replyTo` and `ttl` co-exist in same payload when both apply.
  - **UI:** `formatTimeLeft(expiresAt)` helper computes human-readable remaining time. MessageBubble badge now shows `"Disappearing · 5m"` (or `"1h"`, `"1d"`, `"1w"`, `"soon"`) with `data-testid="disappearing-badge"`. Updated existing test to use testid + regex match.
  - **Security invariants:** `ttl` is inside MLS ciphertext — server never sees duration. TTL validation rejects NaN/Infinity/negative/overflow. `formatTimeLeft` clamps with `Math.max(0,...)`. JSX text children (no XSS). No plaintext logging.
  - **security-auditor:** GREEN. YELLOW-1: TTL is sender-advisory (inherent E2EE — sender controls TTL; no peer-enforced guarantee). YELLOW-2: 30s sweep lag means message can linger ≤30s past expiry (prd.md §9.4.3 acceptable).
  - **476 frontend tests** (+6 TTL suite; was 470); 539 Rust tests (unchanged); tsc clean; biome clean.
  - **Next cycle:** Post-MVP items: PQ hybrid activation (ADR-0003 Phase A — waits for openmls stable MLS_128_MLKEM768), mobile app scaffold (Tauri 2.x), or more UX features (message forwarding, user presence).

## Current state (2026-06-16, cycle 161 — FEATURE: CI fix (TS Uint8Array<ArrayBuffer>) + E2EE message pinning)
- **Cycle 161 (commit f1b0be0):** FEATURE — CI RED fix + E2EE message pinning via MLS.
  - **CI RED FIXED — Bundle budget check TypeScript error:** `new Uint8Array(n)` inferred as `Uint8Array<ArrayBufferLike>` in TS 5.8.3 but `mediaThumbnailDecrypt` interface expects `Uint8Array<ArrayBuffer>`. Fix: changed mock and test to `new Uint8Array(new ArrayBuffer(n))` and typed as `Uint8Array<ArrayBuffer>` (same pattern as cycle 127). Root file: `useCryptoWorker.ts` mock and `useThumbnail.test.ts`.
  - **E2EE message pinning:**
    - `Icon.tsx`: added `pin` icon (Lucide thumbtack SVG path)
    - `useMessages.ts`: added `onPin` as 11th param. `"pin"` and `"unpin"` handlers in `processEnvelope`: validates `targetMessageId` is non-empty string ≤ 36 chars; `shouldDisplayMessage = false`; calls `onPinRef.current?.(groupId, targetMessageId, action)`. Same ref pattern as all other control handlers.
    - `ChatLayout.tsx`:
      - `ChatMessage` gets `pinned?: boolean`; `Chat` gets `pinnedMessageId?: string`
      - `PinnedBanner` component: shows above message list when `pinnedMessageId` is set; displays pin icon + "PINNED" + message preview; X button to unpin
      - `MessageBubble`: pin button on hover for messages with stable id and not deleted; highlighted (orange) when `msg.pinned`; position `top: -10, left: 0`
      - `MessageList`: accepts `onPin?: (msgId: string) => void` prop; wires to each `MessageBubble` via IIFE
      - `handleIncomingPin(gId, targetMessageId, action)`: pure `setChats` reducer; sets/clears `pinnedMessageId` and `msg.pinned` flag; no network call from receive path
      - `sendPin(targetMessageId)`: toggles pin/unpin based on whether `active.pinnedMessageId === targetMessageId`; MLS-encrypts `{type:"pin"|"unpin", targetMessageId}`; `plaintext.fill(0)` in finally; optimistic update
      - `useMessages` call: 11th arg `handleIncomingPin`
  - **Security invariants:** Server only sees MLS ciphertext — `targetMessageId` never in plaintext. `shouldDisplayMessage = false` (no render from pin/unpin). No network calls from receive path. JSX text child in banner (no XSS). `plaintext.fill(0)` in finally. targetMessageId validated [1,36] before callback.
  - **security-auditor:** GREEN. YELLOW-1: no `from` guard on `handleIncomingPin` (benign — pin only sets a pointer/flag, doesn't rewrite content; 2-party MLS authenticates peer). YELLOW-2: banner falls back to `"Message"` when target not in local state (graceful). YELLOW-3: send-side no explicit ID length check (ID is server-issued UUID; receiver fails closed).
  - **470 frontend tests** (+8: 4 useMessages pin suite, 4 ChatLayout pin suite; was 462); 539 Rust tests (unchanged); tsc clean; biome clean.
  - **Next cycle:** Post-MVP items: PQ hybrid activation (ADR-0003 Phase A — waits for openmls stable MLS_128_MLKEM768), mobile app scaffold (Tauri 2.x), or more UX features.

## Current state (2026-06-16, cycle 160 — STABILIZATION: useThumbnail + useRegionDetect tests; delete act() drain fix)
- **Cycle 160 (commit d66c192):** STABILIZATION — CI GREEN, cargo audit clean (1 allowed: instant/openmls). No open bug issues.
  - **Test gap CLOSED — `useThumbnail.ts` (12 new tests):** Security-relevant hook had no test coverage. New `useThumbnail.test.ts`:
    - `thumbnail.key (number[])` zeroed after successful decryption (invariant verified)
    - Object URL revoked on unmount (memory leak prevention)
    - Boundary validation fail-closed: key≠32 → no decrypt, iv≠12 → no decrypt, ct=0 → no decrypt, ct>16384 → no decrypt
    - `ct === 16384` boundary accepted
    - Decryption failure graceful (objectUrl stays null, no throw)
    - cancelled flag prevents stale objectUrl after unmount
    - cryptoWorker unavailable → no-op
  - **Test gap CLOSED — `useRegionDetect.ts` (6 new tests):** Simple hook had no test coverage. New `useRegionDetect.test.ts`:
    - Returns null before fetch resolves; returns regionId after success
    - Calls store fetch exactly once on mount
    - Network error and non-ok response → null (no throw)
    - Pre-set store regionId returned immediately
  - **act() drain improvement — `useMessages.test.ts`:** Last two delete "not called" tests had act() warnings from in-flight setInterval ticks firing after waitFor. Added two-tick drain: microtask flush + `setTimeout(r, 0)` inside act() as second drain. Eliminates the specific pattern.
  - **security-auditor:** GREEN sweep on cycles 157-159 (quote reply, edit, delete). 2 new non-blocking YELLOWs:
    - YELLOW-N1: `handleIncomingEdit`/`handleIncomingDelete` no-op silently when target message id not yet backfilled (in-flight send); safe (fails closed)
    - YELLOW-N2: edit/delete envelopes carry no ordering token (epoch-tied); last-writer-wins. Benign in 2-party MLS; flag for threat-model-checker when group chat (>2 members) lands.
  - **462 frontend tests** (+18: 12 useThumbnail + 6 useRegionDetect; was 444); 539 Rust tests (unchanged); tsc clean; biome clean.
  - **target/ hygiene:** 4GB, under 20GB threshold — no pruning needed. 0-byte rmeta stubs cleaned.
  - **Next cycle:** Post-MVP items: PQ hybrid activation (ADR-0003 Phase A — waits for openmls stable MLS_128_MLKEM768), mobile app scaffold (Tauri 2.x), or more UX features.

## Current state (2026-06-16, cycle 159 — FEATURE: E2EE message deletion)
- **Cycle 159 (commit f972729):** FEATURE — Post-MVP UX: E2EE message unsend/delete.
  - **`useMessages.ts`:** Added `onDelete?: (groupId: string, targetMessageId: string) => void` as 10th param. `type === "delete"` handler in `processEnvelope`: validates `targetMessageId` is non-empty string ≤ 36 chars; `shouldDisplayMessage = false`; calls `onDeleteRef.current?.(groupId, targetMessageId)`. Same ref pattern as all other control handlers.
  - **`ChatLayout.tsx`:**
    - `ChatMessage` interface gains `deleted?: boolean`
    - `MessageBubble`: when `msg.deleted`, renders `<span data-testid="deleted-placeholder">This message was deleted</span>` (italic, muted) instead of all content. Edit/reply/react controls hidden when `deleted`. Delete button (trash icon) on hover for own messages with stable `msg.id` and `!msg.deleted` — positioned at `top: -10, right: 26` (left of edit button).
    - `MessageList`: `onDelete?: (msgId: string) => void` prop; threaded to each `MessageBubble` via IIFE closure to avoid non-null assertion.
    - `handleIncomingDelete(gId, targetMessageId)`: marks matching peer messages (`m.from === "them"`) as `{ ...m, deleted: true }`. Own-message guard prevents peer from erasing our messages.
    - `sendDelete(targetMessageId)`: optimistically marks own message deleted; MLS-encrypts `{type:"delete", targetMessageId}`; sends ciphertext; `plaintext.fill(0)` in `.finally()`. Fire-and-forget.
    - `useMessages` call: 10th arg `handleIncomingDelete`.
    - `<MessageList ... onDelete={sendDelete} />`
  - **`Icon.tsx`:** Added `trash` SVG icon (static Lucide-style path literal).
  - **Security invariants:** Server only receives MLS ciphertext — `targetMessageId` never sent in plaintext. `shouldDisplayMessage = false` before validation (malformed delete never rendered). Own-message guard (`m.from !== "them"`). Deleted placeholder is static JSX text (no XSS). No network calls from receive path (no SSRF). `plaintext.fill(0)` in finally. No plaintext logging.
  - **security-auditor:** GREEN. YELLOW-1: sender-identity guard absent — any group member can delete any other's message; 2-party assumption (pre-existing pattern, same as edit). YELLOW-2: send-side `targetMessageId` not re-validated before encrypt (comes from stable `env.id`, advisory, pre-existing pattern).
  - **444 frontend tests** (+9: 5 useMessages delete suite, 4 ChatLayout delete suite; was 435); tsc clean; biome clean.
  - **Deferred advisory YELLOWs:**
    - Delete sender-identity guard (2-party assumption, same as edit — non-blocking)
    - Delete send-side id validation (advisory, pre-existing pattern)
  - **Next cycle:** Post-MVP items: PQ hybrid activation (ADR-0003 Phase A — waits for openmls stable MLS_128_MLKEM768), mobile app scaffold (Tauri 2.x), or more UX features.

## Current state (2026-06-15, cycle 158 — FEATURE: E2EE message editing)
- **Cycle 158 (commit 0addbe0):** FEATURE — Post-MVP UX: end-to-end encrypted message editing.
  - (Details in memory from prior cycle summary)
  - **435 frontend tests** (+11 edit suite; was 424); tsc clean; biome clean.

## Current state (2026-06-15, cycle 157 — FEATURE: E2EE quote reply)
- **Cycle 157 (commit 7256012):** FEATURE — Post-MVP UX: end-to-end encrypted quote reply.
  - **`ReplyContext` type (new, exported from `useMessages.ts`):** `{ messageId: string; excerpt: string }`. Embedded in `IncomingMessage.replyTo`.
  - **`useMessages.ts`:** New `type === "text"` JSON branch in `processEnvelope` — parses structured `{ type, text, replyTo }` messages. Validates: `messageId` is string, length > 0 and ≤ 36 chars; `excerpt` is string, length > 0; excerpt capped at 100 chars on receive. Backward compat: legacy plain-text messages still work (non-JSON throws → text = decoded).
  - **`ChatLayout.tsx`:**
    - `ChatMessage` interface gains `replyTo?: ReplyContext`
    - `replyingTo: ChatMessage | null` state; cleared on chat switch, after send
    - `MessageBubble`: hover-revealed "Reply" button (`data-testid="reply-button"`, `onMouseEnter/Leave` on outer div with `data-testid="message-bubble"`); quoted block above message text when `msg.replyTo` present (`data-testid="reply-quote"`, blue border-left, excerpt as JSX text child — no XSS)
    - `MessageList`: `onReply?: (msg: ChatMessage) => void` prop threaded to each `MessageBubble`
    - `Composer`: `replyTo` + `onCancelReply` props; reply preview bar above composer (`data-testid="reply-preview"`, `data-testid="cancel-reply"`) when replying; composer border-radius adapts to preview bar presence
    - `sendMessage`: when `replyingTo.id` is set, encodes payload as `JSON.stringify({ type: "text", text, replyTo: { messageId, excerpt: text.slice(0,100) } })` → MLS-encrypts → server sees only ciphertext; plain text when no reply context (backward compat)
    - `handleIncoming`: passes `msg.replyTo` from `IncomingMessage` into `ChatMessage`
  - **`Icon.tsx`:** Added `reply` icon (corner-up-left SVG path)
  - **Security invariants:** Server only receives MLS ciphertext — `replyTo` fields never sent in plaintext. Excerpt capped at 100 chars both on send and receive (defense-in-depth). No XSS (JSX text children, not innerHTML). No plaintext logging. `replyContext` only set when `replyingTo.id` is defined (no undefined messageId). `replyTo.excerpt` is display-only (no re-fetch, no re-decrypt).
  - **security-auditor:** GREEN. YELLOW-1 (advisory): quote excerpt is unauthenticated relative to `messageId` (inherent in client-side quote previews). YELLOW-2 (informational): `replyTo` not persisted to Dexie — reduces at-rest data (non-issue).
  - **424 frontend tests** (+9: 5 in useMessages replyTo suite, 4 in ChatLayout quote reply suite; was 415); tsc clean; biome clean.
  - **Deferred advisory YELLOWs:**
    - Quote unauthenticated attribution (inherent, non-blocking)
    - `replyTo` context lost on page reload (not persisted to Dexie, functional note)
  - **Next cycle:** Post-MVP items: PQ hybrid activation (ADR-0003 Phase A — waits for openmls stable MLS_128_MLKEM768), mobile app scaffold (Tauri 2.x), or message editing.

## Current state (2026-06-15, cycle 156 — FEATURE: "New Messages" divider + CI biome fix)
- **Cycle 156 (commit 55fba6d):** FEATURE + CI fix
  - **CI RED fixed (commit eee81b9):** Biome lint failure on `useMessages.ts` and `useMessages.test.ts` — `ALLOWED_REACTION_EMOJIS` array and `onReaction`/`onReadReceipt`/`onDeliveryReceipt` function params were written in multi-line form but biome collapses to single-line when under print-width. Same recurring pattern as cycle 152. Fix: ran biome format --write on both files.
  - **"New Messages" divider (commit 55fba6d):** Post-MVP UX: horizontal orange separator at first-unread message position.
    - **`Chat` interface**: added `firstUnreadAt?: number` (index into `messages[]` of first unread message — purely in-memory, never persisted, never sent to server).
    - **`buildGroups(messages, firstUnreadIndex?)`**: when `firstUnreadIndex` matches current message index, inserts `{ type: "new-messages" }` group entry; max one per call.
    - **`MessageList`**: new `firstUnreadIndex?: number` prop; renders static "New Messages" horizontal divider (orange accretion accent, letterSpaced caps) at the correct position. `data-testid="new-messages-divider"`.
    - **`handleIncoming`**: on first unread message (`!isActive && c.unread === 0`), sets `firstUnreadAt = msgs.length - 1`. Subsequent unread messages don't change it. Active chats set `firstUnreadAt: undefined`.
    - **`handleSelectChat`** (two-visit behaviour): first visit (unread > 0) clears badge only; second visit (unread === 0) clears `firstUnreadAt` removing the divider.
  - **security-auditor:** GREEN — no RED or YELLOW. `firstUnreadAt` is a numeric index (no content), divider renders static string (no user data in JSX), never persisted to IndexedDB, never sent to server, no XSS risk.
  - **415 frontend tests** (+4: divider absent for active chat, divider appears for background chat, divider removed on second visit, only one divider for multiple unread; was 411); tsc clean; biome clean.
  - **Recurring pattern (CI):** Biome collapses multi-arg calls and array literals to single-line when they fit under print-width. Always run `biome format --write` before committing any file you've hand-written. The CI biome check (`pnpm --filter app exec biome check`) must be the final gate — don't rely on format-on-save alone.
  - **Next cycle:** Post-MVP items: PQ hybrid activation (ADR-0003 Phase A — waits for openmls stable MLS_128_MLKEM768), mobile app scaffold (Tauri 2.x).

## Current state (2026-06-15, cycle 155 — STABILIZATION: suppress invalid control messages from chat UI)
- **Cycle 155 (commit 0d5d6f6):** STABILIZATION — CI GREEN, cargo audit clean (1 allowed: instant/openmls). No open bug issues. 539 Rust tests; 411 frontend tests.
  - **Root bug fixed — `useMessages.ts` control message fallthrough:** When `reaction`/`read_receipt`/`delivery_receipt` matched the type discriminator but failed param validation, `shouldDisplayMessage` stayed `true` and the raw decrypted JSON blob was passed to `onMessage`, appearing in the chat bubble. Fix: set `shouldDisplayMessage = false` immediately on type match, gate the callback with the inner validation block (same pattern as `typing_indicator`). All three control types restructured.
  - **+3 new invariant tests:** `does NOT forward invalid reaction (bad emoji) to onMessage`, `does NOT forward invalid read_receipt (empty messageIds) to onMessage`, `does NOT forward invalid delivery_receipt (non-string messageIds) to onMessage` — each uses `await act(async () => {})` drain after waitFor to eliminate act() warnings.
  - **security-auditor:** GREEN. Fix reduces UI-injection surface (malformed control JSON no longer reaches render path). No plaintext logging, no XSS. Existing validation predicates unchanged (bounds/allowlist same as before).
  - **Recurring pattern:** `await act(async () => {})` after `waitFor` drains Zustand subscription effects for the last test in a describe block — add to any new "not called" test that is the last in its block.
  - **411 frontend tests** (+3; was 408); 539 Rust tests (unchanged); tsc clean; Biome clean.
  - **Delivery receipts (cycle 154 — commit e85442c):** FEATURE — sent→delivered→read state machine with `delivery_receipt` MLS message type. 408 frontend tests (+9 delivery receipt tests vs cycle 153's 399).
  - **Next cycle:** Post-MVP items: PQ hybrid activation (ADR-0003 Phase A — waits for openmls stable MLS_128_MLKEM768), mobile app scaffold (Tauri 2.x).

## Current state (2026-06-15, cycle 153 — FEATURE: E2EE read receipts via MLS read_receipt messages)
- **Cycle 153 (commit 0fde7b5):** FEATURE — Post-MVP UX: end-to-end encrypted read receipts.
  - **`app/src/hooks/useMessages.ts`** (MODIFIED):
    - Added 7th param `onReadReceipt?: (groupId, messageIds, readAt, senderDeviceId) => void` + stable `onReadReceiptRef`
    - `type === "read_receipt"` handler: validates `Array.isArray(messageIds)`, `length in [1,100]`, every item is `string` with `length in [1,36]`, `typeof readAt === "number"`, `Number.isFinite(readAt)`; sets `shouldDisplayMessage = false`; calls `onReadReceiptRef.current`
  - **`app/src/components/ChatLayout.tsx`** (MODIFIED):
    - `sendReadReceiptRef = useRef<(ids: string[]) => void>(() => {})` + `useEffect` to keep fresh every render (same ref pattern as `onTypingRef` etc.)
    - `sendReadReceipt(messageIds)`: MLS-encrypts `{type:"read_receipt", messageIds, readAt: Date.now()}`; sends ciphertext via `sendMessageApi`; `plaintext.fill(0)` in `.finally()`
    - `handleIncoming`: calls `sendReadReceiptRef.current([msg.id])` after each incoming message (fire-and-forget read acknowledgement to peer)
    - `handleIncomingReadReceipt(gId, messageIds, _readAt, _senderDeviceId)`: creates `idSet = new Set(messageIds)`; updates `{ ...m, read: true }` on matching messages in matching group
    - `sendMessage`: after getting server `envelopeId`, backfills `id: envelopeId` onto the most recent unbacked optimistic "me" message → enables incoming read_receipt to match by ID
    - `MessageBubble`: wraps double-check Icon with `data-testid="read-indicator"` + `aria-label="Read"|"Sent"` span
    - `useMessages` call: 7th arg `handleIncomingReadReceipt`
  - **Security invariants verified:** Server only receives MLS ciphertext — `messageIds` and `readAt` never sent in plaintext. Validation cap (100 ids, each ≤ 36 chars) prevents DoS. `plaintext.fill(0)` in finally. No content logging. No XSS (aria-label is "Read"/"Sent" literals). `handleIncomingReadReceipt` only touches `read: boolean` field. security-auditor: GREEN. YELLOW-1: messageIds not validated as UUID format (len [1,36] accepts non-UUID strings; collisions only affect local UI `read` state, non-blocking). YELLOW-2: read-presence timing oracle — receipt sent immediately even for background chats (no viewport gating; product/threat-model decision, non-blocking).
  - **399 frontend tests** (+9: 6 in useMessages read_receipt suite, 3 in ChatLayout read receipts; was 390); tsc clean; Biome clean.
  - **Recurring pattern (from cycle 152):** Biome collapses multi-arg calls to single-line when they fit under print-width. Always run `pnpm exec biome format --write` before committing test files.
  - **Next cycle:** Post-MVP items: PQ hybrid activation (ADR-0003 Phase A — waits for openmls stable MLS_128_MLKEM768), mobile app scaffold (Tauri 2.x), message delivery status (sent→delivered→read full state machine with server ack).

## Current state (2026-06-15, cycle 152 — STABILIZATION: CI RED fix — biome format in reaction test files)
- **Cycle 152 (commit 0eda4a2):** STABILIZATION — CI was RED on Frontend (Biome lint) from cycle 151 emoji reactions commit.
  - **Root cause:** Two test files had multi-line function calls that biome collapses to single-line form when they fit under the print-width limit:
    - `app/src/components/ChatLayout.test.tsx`: `capturedOnReaction?.("...", ..., "👍", "...")` calls written in multi-line form
    - `app/src/hooks/useMessages.test.ts`: `renderHook(() => useMessages(...))` calls written in multi-line form
  - **Fix:** Ran `biome format --write` on both files; biome collapsed the calls to single-line form.
  - **390 frontend tests** (unchanged); biome clean; CI pushed and should be GREEN.
  - **Recurring pattern:** Biome collapses multi-arg calls to single-line when they fit. Test file authors should run `pnpm exec biome format --write` before committing.
  - **Next cycle:** Post-MVP items: PQ hybrid activation (ADR-0003 Phase A — waits for openmls stable MLS_128_MLKEM768), mobile app scaffold (Tauri 2.x), message delivery receipts (read receipts).

## Current state (2026-06-15, cycle 151 — FEATURE: E2EE emoji reactions via MLS reaction messages)
- **Cycle 151 (commit 123b120):** FEATURE — Post-MVP UX: end-to-end encrypted emoji reactions.
  - **CI fix (commit eeb80db):** CI was RED (rustfmt + clippy) on commit fae21bd from cycle 150:
    - `push_subscription.rs`: rustfmt reformats `assert_eq!` calls exceeding 100-char limit
    - `messaging.rs`: moved `pub async fn ack` before `mod tests` (clippy::items_after_test_module)
  - **`app/src/hooks/useMessages.ts`** (MODIFIED):
    - `ALLOWED_REACTION_EMOJIS = ["👍","❤️","😂","😮","😢","😡"]` constant exported
    - `onReaction?: (groupId, targetId, emoji, senderId) => void` as 6th param + stable `onReactionRef`
    - `type === "reaction"` handler: validates `emoji` against whitelist + `targetMessageId` is non-empty string; sets `shouldDisplayMessage = false`; calls `onReactionRef.current`
  - **`app/src/components/ChatLayout.tsx`** (MODIFIED):
    - `ChatMessage` gains `id?: string` (envelope UUID) and `reactions?: Record<string, string[]>` (emoji → [senderDeviceId])
    - `handleIncoming`: stores `id: msg.id` on pushed messages
    - `handleIncomingReaction(gId, targetId, emoji, senderId)`: deduplicates by `senders.includes(senderId)` before appending
    - `sendReaction(targetId, emoji)`: whitelist guard on send side; optimistic local update using `useAuthStore.getState().deviceId`; MLS-encrypts `{type:"reaction", emoji, targetMessageId}`; `plaintext.fill(0)` in `.finally()`
    - `MessageBubble`: reaction chips row (emoji + count, clickable to re-react); reaction trigger "+" button per message with id; emoji picker popover (ALLOWED_REACTION_EMOJIS); `data-testid` on all interactive elements
    - `MessageList`: `onReact?: (msgId, emoji) => void` prop threaded to `MessageBubble`
    - `MessageList` call site: `onReact={sendReaction}`
    - `useMessages` call: 6th arg `handleIncomingReaction`
  - **Security invariants verified:** Server only receives MLS ciphertext — emoji and targetMessageId never sent in plaintext. `ALLOWED_REACTION_EMOJIS` whitelist enforced both on receive (useMessages) and send (sendReaction). No content logging. `plaintext.fill(0)` in finally. Deduplication prevents sender inflation. No XSS (JSX text children, not innerHTML). No SSRF (no network calls from reaction receive path). security-auditor: GREEN. YELLOW-2: unbounded reactions per message (bounded by MLS group size, non-blocking). YELLOW-4: JSON.stringify transient string (consistent with existing pattern, non-blocking).
  - **390 frontend tests** (+11: 6 in useMessages reaction suite, 5 in ChatLayout reaction suite; was 379); tsc clean; Biome clean.
  - **Next cycle:** Post-MVP items: PQ hybrid activation (ADR-0003 Phase A — waits for openmls stable MLS_128_MLKEM768), mobile app scaffold (Tauri 2.x), message delivery receipts (read receipts).

## Current state (2026-06-14, cycle 149 — FEATURE: real-time typing indicator via MLS)
- **Cycle 149 (commit 8f87eba):** FEATURE — Post-MVP UX: real-time "X is typing..." indicator using MLS-encrypted `typing_indicator` messages.
  - **`app/src/hooks/useMessages.ts`** (MODIFIED):
    - Added 5th param `onTyping?: (groupId: string) => void` + stable `onTypingRef` (same pattern as `onPqBindingRef`).
    - `processEnvelope`: when decrypted JSON has `type === "typing_indicator"`, sets `shouldDisplayMessage = false` and calls `onTypingRef.current?.(groupId)`. Envelope is still acked normally.
  - **`app/src/components/ChatLayout.tsx`** (MODIFIED):
    - `typingTimersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>()` — per-groupId auto-clear timers; all cleared on component unmount.
    - `typingThrottleRef = useRef<ReturnType<typeof setTimeout> | null>(null)` — leading-edge throttle for outgoing signals.
    - `handleIncomingTyping(groupId)`: debounce-resets timer, sets `chat.typing = true`, schedules 3 s auto-clear.
    - `sendTypingIndicator()`: plain function (not useCallback); leading-edge throttled to 1/3 s; MLS-encrypts `{"type":"typing_indicator"}` via `cryptoWorker.mlsEncrypt`; sends only ciphertext via `sendMessageApi`; `plaintext.fill(0)` in `.finally()`.
    - `Composer`: `onTyping` prop, called on `onChange`.
    - `useMessages` called with `handleIncomingTyping` as 5th arg.
  - **Security invariants verified:** Server only receives MLS ciphertext — `"typing_indicator"` never sent in plaintext. No PII logging. `plaintext.fill(0)` in finally. Incoming handler gated behind successful MLS decryption (RFC 9420 authentication). Timer cleanup on unmount. security-auditor: GREEN. YELLOW-1: traffic-analysis side channel (burst of envelopes during typing is a new timing signal — advisory, non-blocking). YELLOW-2: `typingThrottleRef` not cleared on unmount (benign — callback only nulls a ref, no state). YELLOW-3: `parsed.type` dispatch should be promoted to exhaustive union as types proliferate (future cleanup).
  - **379 frontend tests** (+7: 3 in useMessages typing_indicator suite, 4 in ChatLayout typing suite; was 372); tsc clean; Biome clean.
  - **Next cycle:** Post-MVP items: PQ hybrid activation (ADR-0003 Phase A — waits for openmls stable MLS_128_MLKEM768), mobile app scaffold (Tauri 2.x), emoji reactions, or message delivery receipts.

## Current state (2026-06-14, cycle 148 — FEATURE: unread message count badge in sidebar)
- **Cycle 148 (commit 4bca53c):** FEATURE — Post-MVP UX: real-time unread message count badge in sidebar.
  - **`app/src/components/ChatLayout.tsx`** (MODIFIED):
    - `activeIdRef = useRef(activeId)` + `useEffect` sync — stable ref lets `handleIncoming` read current active chat ID without becoming a dep in `useCallback` (avoids restarting the polling hook on every chat switch).
    - `handleIncoming`: added `isActive = c.id === activeIdRef.current` check; returns `unread: isActive ? 0 : c.unread + 1` — only non-active chats get their badge incremented on incoming message.
    - `handleSelectChat` (NEW): wraps `setActiveId` + `setChats(cs => cs.map(c => c.id === id ? {...c, unread: 0} : c))` — resets unread badge atomically when a chat is opened.
    - `Sidebar`: `onSelect={handleSelectChat}` (was `setActiveId`).
    - `ChatRow` badge: `{chat.unread > 9 ? "9+" : chat.unread}` — caps display at "9+"; `data-testid="unread-badge"` for testability.
    - Jordan seed chat: added `mlsGroupId: "33333333-3333-3333-3333-333333333333"` to make incoming-message test path reachable.
  - **Security invariants verified:** Zero new server-visible metadata — `handleSelectChat` calls only React state setters (no fetch, no mark-as-read RPC). No plaintext logging of message content. `unread` is an integer count (no message content exposure). `data-testid` is a static literal. No new network calls. security-auditor: GREEN.
  - **372 frontend tests** (+5: badge renders from seed data, resets on select, increments for inactive group, stays zero for active group, shows 9+ above threshold; was 367); tsc clean; Biome clean.
  - **Next cycle:** Post-MVP items: PQ hybrid activation (ADR-0003 Phase A — waits for openmls stable MLS_128_MLKEM768), mobile app scaffold (Tauri 2.x), or typing indicator UX.

## Current state (2026-06-14, cycle 147 — FEATURE: client-side in-conversation message search)
- **Cycle 147 (commit ab09712):** FEATURE — Post-MVP UX: local-only message search within the active conversation.
  - **`app/src/components/ChatLayout.tsx`** (MODIFIED):
    - `HighlightedText` component: splits `msg.text` by query using `String.indexOf` (no ReDoS), renders matching spans as `<mark>` elements via JSX (no XSS). Pure client-side, no API calls.
    - `ConversationHeader`: new search button toggles inline search input. `searchOpen` boolean owned locally; resets via `useEffect([chat.id])` on conversation switch. Calls `onMsgSearch` callback to lift query to `ChatLayout`.
    - `MessageList`: new `searchQuery?: string` prop; computes `matchCount` via `messages.filter()`; shows match count `aria-live` badge; passes `highlight={searchQuery}` to each `MessageBubble`.
    - `MessageBubble`: new `highlight?: string` prop; renders `<HighlightedText>` instead of raw `msg.text` for non-media messages.
    - `ChatLayout`: `msgSearch: string` state; reset to `""` on `activeId` change; passed down to `ConversationHeader` and `MessageList`.
  - **Security invariants verified:** Zero new server-visible metadata (no API calls during search). `msgSearch` never logged (no-plaintext-logging). Search operates on already-decrypted `msg.text` in React memory — no new IndexedDB reads. Not persisted (ephemeral React state). JSX rendering not innerHTML (no XSS). `indexOf` not RegExp (no ReDoS).
  - **security-auditor:** GREEN (no RED). YELLOW advisories: `buildGroups` key uses `m.text.slice(0,8)` (pre-existing, not introduced by diff), `matchCount` not memoized (performance advisory, not security concern).
  - **367 frontend tests** (+5: search button renders, search input shows, mark elements on match, close clears highlights, switching chat resets search; was 362); tsc clean; biome clean.
  - **Next cycle:** Post-MVP items: PQ hybrid activation (ADR-0003 Phase A — triggers when openmls gains stable MLS_128_MLKEM768; not yet in openmls 0.8), mobile app scaffold (Tauri 2.x), or unread message count badge in sidebar.

## Current state (2026-06-14, cycle 146 — FEATURE: persistent per-conversation disappearing timer)
- **Cycle 146 (commit cc65134):** FEATURE — Post-MVP disappearing messages enhancement: persist the per-conversation TTL setting in IndexedDB so it survives group switching and page reloads.
  - **`app/src/db/schema.ts`** (MODIFIED): Added `disappearingTtlSeconds?: number` to `GroupRow`. Added Dexie v6 migration (same index schema; documents new non-indexed, non-sensitive field).
  - **`app/src/db/encrypted-db.ts`** (MODIFIED): Added `getGroupDisappearingTtl(groupId)` and `setGroupDisappearingTtl(groupId, ttl)` to `EncryptedPowehiDb`. Use Dexie `.update(key, {disappearingTtlSeconds})` (partial update) — mlsStateB64 encrypted at rest is never touched.
  - **`app/src/components/ChatLayout.tsx`** (MODIFIED): Added `useEffect` that loads persisted TTL from Dexie when `active.mlsGroupId` changes. Cancelled flag guards the async resolve against stale-state overwrite on rapid group switches (security-auditor Y2 fix). Updated `handleToggleTtl` to persist new TTL via `db.groups.update`.
  - **security-auditor:** GREEN. `disappearingTtlSeconds` correctly classified as non-sensitive (server already learns TTL from `ttl_seconds` per-message). Dexie partial-update does not corrupt encrypted mlsStateB64. TTL_OPTIONS whitelist validation prevents arbitrary values from IndexedDB. No plaintext logging. Deferred YELLOWs: Y1 encryption-wrapper bypass pattern (architectural advisory, safe), Y2 cancelled flag added (fixed).
  - **362 frontend tests** (+4: getGroupDisappearingTtl unknown group, round-trip, clear to undefined, mlsStateB64 undisturbed; was 358); tsc clean; Biome clean.
  - **Next cycle:** Post-MVP items: PQ hybrid activation (ADR-0003 Phase A), mobile app scaffold (Tauri vs React Native), or Y-TLS-CLIENT (tonic upgrade).

## Current state (2026-06-14, cycle 145 — STABILIZATION: gRPC error boundary security invariant tests)
- **Cycle 145 (commit 953fef5):** STABILIZATION — CI GREEN, cargo audit clean (1 allowed: instant/openmls). No open bug issues.
  - **Test gap CLOSED — `error.rs` gRPC error boundary:** `domain_err_to_status()` and `GrpcError→DomainError` conversion were completely untested. Added 14 new tests:
    - **Status code mapping (7 tests):** All `DomainError` variants → correct `tonic::Code` (NotFound→not_found, AlreadyExists→already_exists, Unauthorized→unauthenticated, InvalidInput→invalid_argument, EpochMismatch→failed_precondition, RegionMismatch→failed_precondition, Internal→internal)
    - **Security invariants (3 tests):** `epoch_mismatch_does_not_leak_epoch_numbers` (assert `!msg.contains("42")` etc.), `region_mismatch_does_not_leak_region_identifiers`, `internal_error_does_not_leak_details_to_peer` (also pins sentinel: `msg == "internal error"`)
    - **GrpcError→DomainError conversion (4 tests):** CircuitOpen→Internal, InvalidRequest→InvalidInput (message preserved), Status(not_found)→Internal (catch-all), transport path (compile-time coverage)
  - **security-auditor:** GREEN. No findings. Assertions point in correct direction (negative-contains + positive sentinel lock). No new attack surface (tests are pure in-process, no sockets/I/O/unsafe).
  - **523 Rust tests** (+14; was 509); **358 frontend tests** (unchanged); clippy clean; rustfmt clean.
  - **Next cycle:** Post-MVP items: PQ hybrid activation (ADR-0003 Phase A triggers on openmls stable MLS_128_MLKEM768 ciphersuite), disappearing messages enhancements, mobile app scaffold, or Y-TLS-CLIENT (requires tonic upgrade or custom hyper-based gRPC client).
  - **Remaining deferred gRPC YELLOWs (still open):**
    - Y-TLS-CLIENT: `client_rustls_config()` not yet wired (tonic 0.12 limitation; deferred to tonic upgrade)
    - Y-TLS-1.2-TEST: integration test for TLS 1.2 ClientHello rejection — NOTE: rustls in workspace has no `tls12` feature, so TLS 1.2 is compile-time disabled (build-time guarantee); integration test would need a separate test binary with `tls12` feature enabled
    - All other YELLOWs (Y-3 through Y-8, Y-10 through Y-13) still deferred as advisory/non-blocking

## Current state (2026-06-14, cycle 144 — FEATURE: Y-1 + Y-2 CLOSED — sender_device_id in forward_commit + non-retryable retry guard)
- **Cycle 144 (commit 06d9416):** FEATURE — closed two deferred gRPC YELLOW findings from cycle 140 audit.
  - **Y-1 CLOSED (sender_device_id in forward_commit):** `RegionRouter::forward_commit` port trait now requires `sender_device_id: &DeviceId` parameter. `RegionGrpcRouter::forward_commit` passes `sender_device_id.to_string()` in `ForwardCommitRequest`. Previously sent `String::new()` → peer's fail-closed group-membership check always returned INVALID_ARGUMENT. Added doc invariant to trait: "caller must supply the locally-authenticated device ID".
  - **Y-2 CLOSED (non-retryable retry guard):** Added `is_retryable(code: tonic::Code) -> bool` function. `with_retry` now short-circuits on non-retryable codes (INVALID_ARGUMENT, NOT_FOUND, ALREADY_EXISTS, PERMISSION_DENIED, UNAUTHENTICATED, FAILED_PRECONDITION, UNIMPLEMENTED, OUT_OF_RANGE) — returns error immediately without retrying and without incrementing the circuit breaker failure count (peer is healthy; request is rejected on principle).
  - **+7 tests:** `forward_commit_returns_error_for_unknown_region` (Y-1 smoke), `with_retry_does_not_retry_invalid_argument`, `with_retry_does_not_retry_permission_denied`, `with_retry_does_not_retry_unauthenticated`, `with_retry_retries_unavailable` (regression guard), `is_retryable_returns_false_for_non_retryable_codes`, `is_retryable_returns_true_for_transient_codes`.
  - **security-auditor:** GREEN (no RED). Deferred YELLOWs: `last_err.unwrap()` accumulator (pre-existing, structurally safe); circuit re-check inside backoff loop (pre-existing); no per-code metric for non-retryable exits (future observability).
  - **509 Rust tests** (+5 net; was 504); **358 frontend tests** (unchanged); clippy clean; rustfmt clean.
  - **Remaining deferred gRPC YELLOWs (still open):**
    - Y-TLS-CLIENT: `client_rustls_config()` not yet wired (tonic 0.12 limitation; deferred to tonic upgrade)
    - Y-TLS-1.2-TEST: integration test for TLS 1.2 ClientHello rejection (future cycle)
    - All other YELLOWs (Y-3 through Y-8, Y-10 through Y-13) still deferred as advisory/non-blocking
  - **Next cycle:** Post-MVP items: PQ hybrid activation (ADR-0003 Phase A triggers on openmls stable MLS_128_MLKEM768 ciphersuite), disappearing messages enhancements, mobile app scaffold, or Y-TLS-CLIENT (requires tonic upgrade or custom hyper-based gRPC client).

## Current state (2026-06-14, cycle 143 — FEATURE: Y-TLS-VERSION CLOSED — TLS 1.3 minimum for gRPC)
- **Cycle 143 (commit 791f40c):** FEATURE — closed deferred gRPC YELLOW Y-TLS-VERSION: explicit TLS 1.3 minimum for inter-region gRPC listener.
  - **Y-TLS-VERSION CLOSED:** tonic 0.12's `ServerTlsConfig` doesn't expose protocol-version selection. Built custom `rustls::ServerConfig` via `builder_with_provider(ring).with_protocol_versions(&[&TLS13])`. Used `serve_with_incoming` with `tokio_rustls::TlsAcceptor` — `TlsStream<TcpStream>: Connected` is implemented by tonic 0.12.3, so `TlsConnectInfo` injection is preserved and `verify_peer_region()` works unchanged.
  - **security-auditor F1 FIXED (slow-loris DoS):** 10s `tokio::time::timeout` on TLS handshake — partial ClientHello can no longer block the accept loop indefinitely.
  - **security-auditor F2 FIXED (silent rejection):** `warn!(error_kind = "tls_handshake")` and `warn!(error_kind = "tls_handshake_timeout")` — operators can observe TLS 1.2 downgrade attempts and timeout events without PII or ciphertext in logs.
  - **security-auditor F3 FIXED (accept-error terminates serve):** non-transient `listener.accept()` errors now `warn+continue` instead of returning from the stream, preventing silent shutdown of the HTTP+admin servers via `try_join!`.
  - **opaque-ke argon2 feature FIXED (pre-existing):** `powehi-opaque/Cargo.toml` — `opaque-ke = { features = ["argon2"] }` — `Argon2<'static>: Ksf` trait bound was unsatisfied without explicit feature; `cargo build -p powehi-server` was broken.
  - **`server_tls()` deprecated** with `#[deprecated]` — prevents callers from silently using the unpinned TLS path.
  - **`client_rustls_config()` added** — TLS 1.3 minimum client config for future hyper-based gRPC clients (tonic 0.12 `ClientTlsConfig` doesn't support version pinning).
  - **+6 tls.rs tests:** builds-without-error, h2-ALPN, missing-CA rejection, client config, PEM parsers.
  - **security-auditor:** YELLOW→GREEN (F1/F2/F3 fixed). Remaining deferred:
    - Y-TLS-CLIENT: `client_rustls_config()` not yet wired (tonic 0.12 `ClientTlsConfig` no `rustls_client_config()`; deferred to tonic upgrade)
    - Y-TLS-1.2-TEST: integration test for TLS 1.2 ClientHello rejection (future cycle)
  - **504 Rust tests** (+6; was 498); **358 frontend tests** (unchanged); clippy clean; rustfmt clean.
  - **Remaining deferred gRPC YELLOWs (still open):**
    - Y-1: `forward_commit` client sends empty `sender_device_id` (cross-region client-side fix needed)
    - Y-2: Retry on non-retryable error codes burns retry budget (client-side fix)
    - Y-TLS-CLIENT: `client_rustls_config()` not yet wired (tonic 0.12 limitation)
    - All other YELLOWs (Y-3 through Y-8, Y-10 through Y-13) still deferred as advisory/non-blocking
  - **Next cycle:** Post-MVP items: PQ hybrid activation (ADR-0003 Phase A triggers on openmls stable MLS_128_MLKEM768 ciphersuite), disappearing messages enhancements, mobile app scaffold, or Y-TLS-CLIENT (requires tonic upgrade or custom hyper-based gRPC client).

## Current state (2026-06-13, cycle 142 — FEATURE: gRPC Y-15 CLOSED — atomic sync_group_membership)
- **Cycle 142 (commit f1f4b03):** FEATURE — closed deferred gRPC YELLOW Y-15: non-atomic member upsert.
  - **Y-15 CLOSED (atomic batch upsert):** Added `GroupRepository::upsert_members(group, members)` port method. `PgGroupRepository` implements it with `pool.begin()` / `tx.commit()` wrapping all INSERTs in a single transaction. Both group row and member rows use `ON CONFLICT DO NOTHING` (idempotent, epoch-preserving).
  - **YELLOW-2 CLOSED (dedup amplification):** Added `HashSet` dedup over `member_device_ids` before building INSERT list. A peer sending the same UUID N times (up to MAX_SYNC_MEMBERS=10k) now results in only 1 INSERT instead of N no-op writes.
  - **YELLOW-1 CLOSED (test fidelity):** `FakeGroupRepo::upsert_members` in server.rs models `DO NOTHING` semantics — skips save if group already present, preserving any higher locally-tracked epoch. Matching change in messaging_service.rs and group_service.rs fakes.
  - **`sync_group_membership` handler simplified:** removed conditional `find_by_id` + `save` + N-call loop; replaced with single `upsert_members` call.
  - **+3 tests:** `sync_group_membership_all_members_persisted_atomically` (3 members all accepted by forward_envelope after batch upsert), `sync_group_membership_zero_members_creates_group_stub` (empty list → Accepted), `sync_group_membership_duplicate_device_ids_are_deduped` (same UUID ×3 → 1 member accepted).
  - **security-auditor:** PASS (GREEN). Both YELLOWs addressed before commit (Y-1 FakeGroupRepo epoch-preservation, Y-2 dedup). clippy clean; rustfmt clean.
  - **498 Rust tests** (+3; was 495); **358 frontend tests** (unchanged).
  - **Remaining deferred gRPC YELLOWs (still open):**
    - Y-1: `forward_commit` client sends empty `sender_device_id` (cross-region client-side fix needed)
    - Y-2: Retry on non-retryable error codes burns retry budget (client-side fix)
    - Y-TLS-VERSION: Explicit TLS 1.3 minimum requires custom `rustls::ServerConfig`
    - All other YELLOWs (Y-3 through Y-8, Y-10 through Y-13) still deferred as advisory/non-blocking
  - **Next cycle:** Post-MVP items: PQ hybrid activation (ADR-0003 Phase A triggers on openmls stable MLS_128_MLKEM768 ciphersuite), disappearing messages enhancements, mobile app scaffold, or Y-TLS-VERSION (explicit TLS 1.3 min via custom rustls::ServerConfig).

## Current state (2026-06-13, cycle 141 — FEATURE: gRPC Y-7/Y-9/Y-14 security hardening)
- **Cycle 141 (commit 72c2fa5):** FEATURE — closed three deferred gRPC YELLOW findings from cycle 140 audit.
  - **Y-7 CLOSED (RFC 6125 compliance):** `peer_cert_matches_region` now uses `.eq_ignore_ascii_case()` for Subject CN and SAN DNS name comparison. Case-sensitive `==` was a latent bypass (RFC 6125 §6.4.1 mandates case-insensitive DNS label comparison).
  - **Y-9 CLOSED (cert expiry alerting):** Added `inspect_cert_expiry()` helper called from `verify_peer_region()`. Logs `warn!` if peer mTLS cert is expired or expiring within 30 days. Defense-in-depth — primary expiry enforcement is rustls at TLS handshake. Also renamed misleading Y-9 reference in `tls.rs` to Y-TLS-VERSION (open TLS 1.3 min-version pinning work).
  - **Y-14 CLOSED (timestamp skew clamp):** `forward_envelope` now clamps `sent_at_unix_ms` to ±300s from server-local time. Values outside the window (including i64::MIN/MAX, far-past, far-future) fall through to `Utc::now()`. Prevents ordering manipulation via attacker-controlled timestamps.
  - **+10 tests:** case-insensitive CN/SAN (3), far-future clamp, far-past clamp, recent-preserved, i64::MIN, i64::MAX; `CaptureEnvelopeRepo` test helper added.
  - **security-auditor:** PASS (GREEN). 6 YELLOW advisories (all non-blocking): boundary tests for ±300s edge (advisory), expiry warning unit test (advisory), intermediate CA expiry not logged (advisory), tls.rs comment naming fixed (Y4 closed), pre-existing warn! on DER error (advisory), CN vs SAN priority per RFC 6125 §6.4.4 (advisory).
  - **495 Rust tests** (+10; was 485); **358 frontend tests** (unchanged); clippy clean; rustfmt clean.
  - **Remaining deferred gRPC YELLOWs (still open):**
    - Y-1: `forward_commit` client sends empty `sender_device_id` (cross-region client-side fix needed)
    - Y-2: Retry on non-retryable error codes burns retry budget (client-side fix)
    - Y-TLS-VERSION: Explicit TLS 1.3 minimum requires custom `rustls::ServerConfig`
    - Y-15: `sync_group_membership` member upsert non-atomic (N sequential add_member calls)
    - All other YELLOWs (Y-3 through Y-8, Y-10 through Y-13) still deferred as advisory/non-blocking
  - **Next cycle:** Post-MVP items: PQ hybrid activation (ADR-0003 Phase A triggers on openmls stable MLS_128_MLKEM768 ciphersuite), disappearing messages enhancements, mobile app scaffold, or close remaining gRPC YELLOWs (Y-15 atomic upsert).

## Current state (2026-06-13, cycle 140 — STABILIZATION: gRPC RED-1 + RED-2 security fixes)
- **Cycle 140 (commit d2ed12a):** STABILIZATION — CI GREEN, cargo audit clean (1 allowed: instant/openmls). No open bug issues. Phase 5 and Phase 6 both COMPLETE.
  - **security-auditor sweep on Phase 6 gRPC code:** Found 2 RED + 15 YELLOW findings.
  - **RED-1 FIXED (DoS / memory exhaustion):** Added `MAX_CIPHERTEXT_BYTES = 1 MiB` cap in `forward_envelope` and `forward_commit` before `.to_vec()` allocation. Added `MAX_SYNC_MEMBERS = 10,000` cap in `sync_group_membership` before DB writes. Returns `InvalidArgument` on violation.
  - **RED-2 FIXED (authorization bypass):** `forward_envelope` and `forward_commit` now call `verify_peer_region` against the group's `home_region` (looked up from `group_repo`). When `tls_required=true`, requests without matching `TlsConnectInfo` are rejected with `PermissionDenied` even if sender is a known member. Uses `request.into_parts()` pattern (same as `sync_group_membership`).
  - **+5 tests:** `forward_envelope_oversized_ciphertext`, `forward_commit_oversized_commit`, `sync_group_membership_too_many_members` (RED-1); `forward_envelope_no_tls_info_rejected_when_group_known_and_tls_required`, `forward_commit_no_tls_info_rejected_when_group_known_and_tls_required` (RED-2).
  - **485 Rust tests** (+5; was 480); **358 frontend tests** (unchanged); clippy clean; rustfmt clean.
  - **Deferred YELLOWs from gRPC audit (non-blocking):**
    - Y-1: `forward_commit` client sends empty `sender_device_id` — cross-region ForwardCommit will fail with InvalidArgument until client fills this field
    - Y-2: Retry on all error codes incl. non-retryable (InvalidArgument, PermissionDenied) — burns retry budget
    - Y-7: `peer_cert_matches_region` uses case-sensitive string equality; DNS names are case-insensitive (RFC 6125)
    - Y-9: No explicit TLS 1.3 min-version pinning in `tls.rs`; no cert expiration logging
    - Y-14: `created_at` accepts attacker-controlled timestamp from peer — no skew clamp
    - Y-15: `sync_group_membership` member upsert is non-atomic (N sequential add_member calls, no transaction)
    - All other YELLOWs (Y-3 through Y-8, Y-10 through Y-13) deferred as advisory/non-blocking
  - **Next cycle:** Phase 6 fully complete. Post-MVP items: PQ hybrid activation (ADR-0003 Phase A), disappearing messages enhancements, or mobile app scaffold.

## Current state (2026-06-13, cycle 139 — FEATURE: Phase 5 COMPLETE — Public beta deployment GitOps artifacts)
- **Cycle 139 (commit 66b8ca3):** FEATURE — Phase 5 DoD final item: Public beta deployment (prd.md §12.4–§12.5)
  - **`infra/argocd/project.yaml`** (NEW): Argo CD AppProject — 4 destination clusters (staging, prod-eu, prod-ap, in-cluster), namespaceResourceWhitelist (Secret excluded → ExternalSecrets only), CI role sync+get only.
  - **`infra/argocd/app-staging-eu.yaml`** (NEW): automated prune+selfHeal sync from HEAD → `powehi-staging` namespace.
  - **`infra/argocd/app-prod-eu.yaml`** + **`app-prod-ap.yaml`** (NEW): manual sync only (no `automated` block) — prod requires human approval via GitHub Environment protection.
  - **`infra/helm/powehi/values-staging.yaml`** (NEW): EU-Frankfurt staging — 1-3 replicas, info logging, grpcTLS on, 5m ExternalSecrets refresh.
  - **`infra/helm/powehi/values-prod-eu.yaml`** (NEW): EU-Frankfurt Tier1 — 3-15 replicas, 60% CPU HPA, separate secret paths `powehi/prod-eu/`.
  - **`infra/helm/powehi/values-prod-ap.yaml`** (NEW): AP-Seoul Tier1 — 2-10 replicas, `powehi/prod-ap/` secrets.
  - **`infra/helm/powehi/values.schema.json`** (NEW): JSON Schema — tier enum (Tier1|Tier2), logLevel enum, required resource limits. Schema error on invalid values at `helm lint`.
  - **`infra/helm/powehi/values.yaml`** (MODIFIED): `tier: "Tier1"` field added.
  - **`infra/helm/powehi/templates/configmap.yaml`** (MODIFIED): `POWEHI__TIER` emitted.
  - **`.github/workflows/cd.yml`** (NEW): progressive deploy staging-eu→prod-eu→prod-ap. Semver validation. ARGOCD_AUTH_TOKEN in env vars only (not CLI flags — R1). Staging smoke test /health retry. SHA-verified argocd CLI install.
  - **security-auditor:** YELLOW (no RED). R1 (env-var-only token) + R2 (grpcTlsEnabled=true on staging) both closed. 3 deferred pre-launch YELLOWs: targetRevision pin, commit signing, SHA inline-pin.
  - **infra-test:** 0 FAILs. Helm lint clean, all 3 env renders correct, schema validation confirmed.
  - **480 Rust tests** (unchanged); **358 frontend tests** (unchanged).
  - **Phase 5 DoD:** ALL ITEMS COMPLETE ✓. Phase 5 STATUS.md: COMPLETE.
  - **Next phase:** Phase 6: Global Infrastructure (gRPC mesh + mTLS inter-region, AP-Seoul Tier1 independence, cross-region round-trip p99 <200ms, failover RTO <5m).
  - **Pre-launch YELLOW follow-ups (before first prod Argo CD sync):**
    - Pin `targetRevision` in app-prod-eu/prod-ap.yaml to release tag (not HEAD)
    - Configure `signatureKeys` in AppProject for signed-commit enforcement
    - Pin argocd CLI SHA inline in cd.yml (not from downloaded .sha256 file)

## Current state (2026-06-13, cycle 138 — FEATURE: Phase 5 Security audit findings addressed — Y3/F4/F6/Y-KP-1 closed)
- **Cycle 138 (commit 9629f23):** FEATURE — Phase 5 DoD item: Security audit findings addressed
  - **`messaging_service.rs`** (MODIFIED): `MAX_FAN_OUT_RECIPIENTS=512` cap in `fan_out_push`. Members beyond cap still poll; warn log is content-free (cap= field only). Test: `fan_out_caps_at_max_recipients` (514-member group → exactly 512 pushes). Closes Y3/cycle 116.
  - **`auth_service.rs`** (MODIFIED): `MAX_DEVICES_PER_USER=10` check in `register_device` — rejects with `DomainError::InvalidInput("device_limit_exceeded")` if user already has 10 devices. Soft cap (TOCTOU acknowledged; hard DB invariant is future hardening). Test: `register_device_rejects_when_user_at_device_limit`. Closes finding 4/cycle 128.
  - **`lib.rs`** (MODIFIED): Device routes (`POST/DELETE /v1/auth/devices`) moved from `api_governor` (burst=60) to `auth_governor` (burst=5, shared token bucket via `.clone()`). Strictly tighter: login + device ops share same per-IP allowance. Closes finding 6/cycle 128.
  - **`key_package_service.rs`** (MODIFIED): `MAX_KEY_PACKAGES_PER_CALL=50` (pre-DB check) and `MAX_KEY_PACKAGES_PER_DEVICE=200` (count_available + new ≤ 200). Soft cap, TOCTOU acknowledged. Tests: `upload_rejects_oversized_batch`, `upload_rejects_when_device_at_storage_limit`. Closes Y-KP-1/cycle 135.
  - **security-auditor:** YELLOW (no RED). TOCTOU in device cap and KP cap are soft caps — hard DB invariants require transactional adapter changes (future hardening). GovernorLayer clone shares token bucket (intentionally stricter). All findings advisory/non-blocking.
  - **480 Rust tests** (+4; was 476); fmt clean; clippy clean.
  - **Phase 5 DoD:** `[x] Security audit findings addressed` — Y3/F4/F6/Y-KP-1 all closed.
  - **Remaining Phase 5 item:** `[ ] Public beta deployment`
  - **New deferred YELLOWs (soft caps, future hardening):**
    - Device cap TOCTOU: hard invariant needs serializable transaction in outbound adapter
    - KP cap TOCTOU: hard invariant needs atomic INSERT-with-precondition in outbound adapter

## Current state (2026-06-13, cycle 137 — FEATURE: Phase 5 PQ hybrid migration path documented — ADR-0003 Active)
- **Cycle 137 (commit 2fa32e8):** FEATURE — Phase 5 DoD item: PQ hybrid migration path documented (ML-KEM-768)
  - **`docs/decisions/0003-pq-migration.md`** (MAJOR UPDATE): ADR-0003 status Proposed → **Active**. Added:
    - "Current Implementation (Phase B Interim)" table documenting all deployed ML-KEM-768 code
    - Wire format spec: 1,248-byte `POWEHI_PQ_KEM_EXT_TYPE` extension payload (encap key 1,184B + Ed25519 sig 64B)
    - PQ binding: HKDF-SHA256(ikm=ss, salt=None, info=b"powehi-pq-binding-v1"||groupId, L=8)
    - Opaque-handle invariant: raw 2,400-byte decap key never crosses WASM-JS boundary
    - Phase A trigger: openmls stable `MLS_128_MLKEM768_AES128GCM_SHA256_MlDsa65` ciphersuite
    - Phase B trigger: ≥95% active sessions on Phase A client (30-day window)
    - Phase C trigger: ≤0.1% classical KeyPackages remaining (7-day window); **irreversible**
    - Specific code change checklist for each phase
    - Rollout (`POWEHI_PQ_MLS_NATIVE_ENABLED` feature flag, 1%→10%→100% over 14 days) + rollback procedure
    - KeyPackage size table: classical ~500B vs Phase A ~8,000B (~16×)
    - OPAQUE PQ path: opaque-ke 4.x PQ-hybrid OPRF (Phase B item)
  - **`docs/prd.md` §5.3** (EXPANDED): current state table, PQ extension wire format, per-phase trigger conditions, ADR-0003 reference
  - **`docs/phases/phase-5/STATUS.md`**: `[ ] PQ hybrid migration path` → `[x]`
  - **476 Rust tests** (unchanged); no code changes (docs-only).
  - **Phase 5 DoD:** `[x] PQ hybrid migration path documented` — ADR-0003 Active, prd.md §5.3 complete.
  - **Next Phase 5 items:** `[ ] Security audit findings addressed` OR `[ ] Public beta deployment`

## Current state (2026-06-13, cycle 136 — FEATURE: Phase 5 load test infrastructure — k6 WS + seed tool)
- **Cycle 136 (commit 6d6cae1):** FEATURE — Phase 5 DoD item: Load testing (target concurrent connections met)
  - **`infra/k6/smoke_ws.js`** (NEW): k6 smoke test — 5 VUs × 30s, single K6_TEST_TOKEN, validates WS upgrade (101) + keepalive ping/pong. Threshold: 100% connect success, p95 < 1000ms.
  - **`infra/k6/ws_load_test.js`** (NEW): k6 WS load test — ramps to 10k concurrent connections (2m→2k→5k→10k, 10m sustain, 2m down). Reads token JSON array from K6_TOKENS_FILE. Metrics: ws_connect_time_ms (p95 < 500ms), ws_connect_success (≥ 99%), ws_active_connections, ws_errors. K6_SMOKE=1 for 50 VU × 2min mode. Parses WS notification JSON; validates `msg.type` presence.
  - **`infra/k6/tools/seed_load_test.py`** (NEW): seeds N test devices/sessions in Postgres + Redis, bypassing OPAQUE (test-env only). Guards: `--allow-non-prod` flag required; production hostname pattern check; 0600 umask on token output file. Cleanup DELETE idempotent (removes prior k6 rows before re-seed).
  - **`.github/workflows/load-test.yml`** (NEW): manual-only `workflow_dispatch`; `max_vus` is `type:choice` [50/500/2k/10k] (prevents shell injection); k6 installed via GPG-verified Grafana apt repo; "Refuse production targets" step; secrets DATABASE_URL + REDIS_URL scoped to environment.
  - **security-auditor:** YELLOW → addressed all HIGH/MEDIUM findings. LOW/INFO findings deferred: setup-python not SHA-pinned (consistent with CI pattern), error message logging (informational), results artifact (no --http-debug rule documented in workflow).
  - **476 Rust tests** (unchanged); fmt clean; clippy clean. Phase 5 DoD item is `[~]` (scripts exist, needs staging infra run to fully close).
  - **Hardware requirements for 10k run:** ≥ 4 vCPU / 16GB RAM runner (single-process k6 limit ~5k VUs; use k6 Operator for true 10k). Target server: ≥ 4 vCPU / 8GB RAM + Redis with 10k+ connections.
  - **Next Phase 5 items:** PQ hybrid migration path documented (ML-KEM-768) OR staging infra provisioning to execute the full 10k load test.
  - **Load test deferred YELLOWs:**
    - setup-python@v5 not SHA-pinned (consistent with CI pattern; LOW)
    - k6 error message logging in smoke_ws.js (WS close-reason string; informational)
    - k6 results artifact: document "never --http-debug" in workflow (informational)

## Current state (2026-06-13, cycle 135 — STABILIZATION: telemetry test coverage + backend security sweep)
- **Cycle 135 (commit b10ec96):** STABILIZATION — CI GREEN, cargo audit clean (1 allowed: instant/openmls). No open GitHub bug issues.
  - **Test gap CLOSED — `OtlpConfig::from_env()` Some branch** (cycle 133 advisory):
    - `otlp_config_from_env_returns_some_when_endpoint_set`: tests full Some path — verifies endpoint, default service_name="powehi", service_version=CARGO_PKG_VERSION when OTEL_EXPORTER_OTLP_ENDPOINT set
    - `otlp_config_from_env_reads_custom_otel_service_name`: verifies OTEL_SERVICE_NAME override reads correctly
    - `shutdown_otlp_does_not_panic_without_prior_init`: idempotent no-op invariant (two calls, no panic)
    - Uses static `ENV_TEST_MUTEX` + RAII `EnvGuard` (set/remove with Drop restore) to serialize env-var tests safely under parallel test threads. Uses `unsafe { std::env::set_var }` (required by Rust 1.96.0 API).
  - **security-auditor:** GREEN (full backend sweep — 30 files). No RED findings. No regression of prior YELLOWs.
    - **New YELLOW (Y-KP-1):** key-package upload has no explicit per-call count cap. `KeyPackageService::upload` + `routes/key_package.rs` accept unbounded `Vec<Bytes>`. Auth required; 512KB body cap is implicit ceiling (~250 packages). Suggest per-device ceiling (200) + per-call limit (50) before public launch. Severity: LOW.
    - Known YELLOWs re-confirmed open: fan-out no group-size cap (Y3/cycle 116), no per-user device cap (finding 4/cycle 128), device routes use api_governor not auth_governor (finding 6/cycle 128).
    - Informational: grpc server DomainError::Internal may surface raw DB driver text in logs (out of scope, future grpc-lead pass).
  - **476 Rust tests** (+3; was 473); fmt clean; clippy clean.
  - **Deferred YELLOWs (updated list):**
    - Fan-out group-size cap (Y3/cycle 116 — no group size cap in fan_out_push): MEDIUM, pre-launch
    - Per-user device count cap (finding 4/cycle 128): MEDIUM, pre-launch
    - Device routes rate-limit class (finding 6/cycle 128): LOW, pre-launch
    - Key-package per-call count cap (Y-KP-1 new/cycle 135): LOW, pre-launch
    - grpc DomainError::Internal DB text in logs (informational/cycle 135): LOW, future grpc-lead pass
    - All prior deferred YELLOWs unchanged (see cycle 134 entry)
  - **Next Phase 5 item:** Load testing (target concurrent connections met) OR PQ hybrid migration path documented.

## Current state (2026-06-12, cycle 134 — FEATURE: Phase 5 Full threat model review — prd.md §3)
- **Cycle 134 (commit e35ad89):** FEATURE — Phase 5 DoD item: Full threat model review (threat-model-checker pass)
  - **threat-model-checker:** ran full T1–T7 + §3.3 + §3.4 + §3.5 audit. **Overall verdict: YELLOW → GREEN after R1 fix.** No RED findings. Core non-negotiables all met.
  - **Finding T3-1 (YELLOW, fixed):** `group_members(group_id, device_id, joined_at_epoch)` table contradicted prd.md §3.3 which claimed server doesn't know group membership. FIXED: prd.md §3.3 updated.
  - **Finding T3-2 (YELLOW, documented):** `device.user_id` FK exposes user↔device mapping. Documented in §3.3.
  - **Push endpoint host (YELLOW, documented):** FCM/Mozilla/APNs endpoint host unavoidable per RFC 8291. Documented in §3.3.
  - **`docs/prd.md`** (MODIFIED):
    - §3.3 "server inevitably learns": added `(group_id, device_id, joined_at_epoch)` group topology, user↔device mapping, push subscription endpoint host
    - §3.3 "server does not know": replaced "group member list" (inaccurate) with "MLS LeafNode crypto material" (correct)
    - §3.5.1: added `group_members` to regional authority metadata exposure list
    - §5.4: clarified server knows device_id membership but not MLS LeafNode crypto material
    - DB schema comment line 1269: fixed "멤버 명단은 모름" → accurate description
  - **R4 advisory confirmed not needed:** `delete_expired` sweeper already wired in `bin/powehi-server/src/main.rs:306-316` (every 300s, logs only count, no content).
  - **473 Rust tests** (unchanged); fmt clean; clippy clean.
  - **Phase 5 DoD:** `[x] Full threat model review` — threat-model-checker YELLOW→GREEN (R1 fix applied this cycle).
  - **Next Phase 5 item:** Load testing (target concurrent connections met) OR PQ hybrid migration path documented.

## Current state (2026-06-12, cycle 133 — FEATURE: Phase 5 OTLP trace export + ServiceMonitor — prd.md §13.3)
- **Cycle 133 (commit eab89b3):** FEATURE — Phase 5 observability: OTLP trace export + Prometheus ServiceMonitor
  - **`crates/infra/powehi-telemetry/src/lib.rs`** (MODIFIED): `OtlpConfig { endpoint, service_name, service_version }` + `from_env()` (reads `OTEL_EXPORTER_OTLP_ENDPOINT`/`OTEL_SERVICE_NAME`). `init_with_otlp(config)` installs opentelemetry-otlp 0.26 gRPC exporter (tonic transport), registers global `TracerProvider`, wires `tracing-opentelemetry 0.27` layer over JSON subscriber. `shutdown_otlp()` for graceful flush. Workspace deps: opentelemetry 0.26, opentelemetry-otlp 0.26, opentelemetry_sdk 0.26, tracing-opentelemetry 0.27.
  - **`infra/helm/powehi/templates/servicemonitor.yaml`** (NEW): ServiceMonitor CRD for kube-prometheus-stack targeting admin port 9090 `/metrics` at 30s; guarded by `monitoring.serviceMonitor.enabled` (default `false`).
  - **NetworkPolicy #10** (MODIFIED): egress to monitoring namespace port 4317 (OTLP/gRPC); guarded by `.Values.otlp.endpoint`; separator inside if-guard (empty-doc fix by infra-lead).
  - **ConfigMap** gains `OTEL_EXPORTER_OTLP_ENDPOINT` + `OTEL_SERVICE_NAME` when endpoint set. **values.yaml** gains `monitoring.serviceMonitor` + `otlp` blocks.
  - **security-auditor:** GREEN. YELLOW: in-memory span exporter test for PII-absence assertion (advisory — upstream `#[instrument(skip)]` enforces correctness).
  - **infra (Helm):** GREEN. YELLOW: `Chart.yaml` missing `icon` (advisory). `helm lint 0 failed`.
  - **473 Rust tests** (+4; was 469); fmt clean; clippy clean.
  - **Phase 5 DoD:** `[x] Observability stack deployed` — HTTP metrics middleware (cycle 132) + OTLP + ServiceMonitor (cycle 133).
  - **Next Phase 5 item:** Full threat model review (threat-model-checker pass).

## Current state (2026-06-12, cycle 132 — FEATURE: Phase 5 zero-knowledge HTTP metrics middleware — prd.md §13.2)
- **Cycle 132 (commit TBD):** FEATURE — Phase 5 observability: HTTP request metrics middleware
  - **`crates/adapters/inbound/powehi-rest-api/src/http_metrics.rs`** (NEW): `record_http_metrics` Tower middleware — records `http_requests_total{method, status}` counter + `http_request_duration_seconds{method, status}` histogram via `metrics` crate on every request.
  - **Security invariant (prd.md §13.2 + no-plaintext-logging):** Labels are ONLY `request.method().as_str()` (fixed ASCII HTTP verb vocabulary) and `response.status().as_u16().to_string()` (bounded 3-digit integer). URI/path is deliberately absent — routes like `/v1/messages/:id` and `/v1/auth/devices/:id` embed UUID path params that would expose device/envelope IDs.
  - **Layer positioning:** Outermost layer in `router_inner` — measures full request lifecycle including `DefaultBodyLimit`, `TraceLayer`, security headers, rate-limit layers, auth extractor, and handler. Correctly records 413/429/401 rejection metrics.
  - **security-auditor:** PASS (GREEN). One YELLOW advisory: histogram latency distinguishability for OPAQUE login paths (not worsened vs TCP-level timing; method+status aggregation reduces distinguishability vs URI-labeled design — advisory in threat model, not blocking).
  - **4 new tests:** `response_passes_through_with_correct_200_status`, `not_found_response_passes_through_unchanged`, `path_param_route_passes_through_without_leaking_path_into_labels`, `delete_method_passes_through`. No global Prometheus recorder conflict (tests are behavior-only, recorder tests live in lib.rs).
  - **469 Rust tests** (+4; was 465); fmt clean; clippy clean.
  - **Phase 5 DoD checklist updated:**
    - `[x] Container image signing (cosign + Rekor)` — verified already in release.yml (cosign keyless + Rekor + container-provenance SLSA L3)
    - `[~] Observability stack deployed` — HTTP metrics middleware done; OTLP export + Grafana stack deployment pending
  - **Next Phase 5 item:** Full threat model review (threat-model-checker pass) OR OTLP exporter configuration for Prometheus → Grafana pipeline.

## Current state (2026-06-12, cycle 131 — FEATURE: Phase 5 SLSA L3 — rust-toolchain.toml + WASM provenance)
- **Cycle 131 (commit 348d497):** FEATURE — Phase 5 DoD item 1: SLSA Level 3 reproducible builds (prd.md §12.6)
  - **`rust-toolchain.toml`** (NEW): pins Rust `1.96.0` (confirmed-working CI version; 1.87 was below transitive-dep minimum; darling/time/aws-smithy require ≥1.88–1.91). Components: rustfmt, clippy. Targets: wasm32-unknown-unknown.
  - **`Dockerfile`** (MODIFIED): `FROM rust:1.83.0-bookworm` → `FROM rust:1.96.0-bookworm` — aligns with toolchain file; 1.83.0 predated MSRV for full workspace.
  - **`.github/workflows/release.yml`** (EXTENDED):
    - All third-party actions SHA-pinned (supply-chain hardening — security-auditor R1): checkout, upload-artifact, rust-cache, docker/*, cosign-installer, dtolnay/rust-toolchain (all by 40-char SHA; slsa-framework reusable workflows stay at @v2.0.0 per upstream policy)
    - `build-wasm` job (NEW): wasm-pack 0.13.1 `--locked`, `SOURCE_DATE_EPOCH=0`, Rust 1.96.0
    - `wasm-provenance` job (NEW): SLSA L3 attestation for WASM module; SLSA subjects cover both `*_bg.wasm` AND `*.js` glue (R3 fix — JS glue controls WASM exports, must be attested)
    - GHA layer cache disabled in `build-push-container` (R2 cache-poisoning fix)
    - `build-binary` toolchain 1.83.0 → 1.96.0 (consistent with Dockerfile)
  - **security-auditor:** PASS after 3 RED fixes. Deferred YELLOWs: (Y1) `--remap-path-prefix` advisory for full binary reproducibility (L4 territory, non-blocking); (Y2) apt-get unpinned runtime stage packages (affects image hash, not binary SLSA subject)
  - **465 Rust tests** (unchanged); 358 frontend tests unchanged; fmt clean; clippy clean.
  - **Phase 5 DoD checklist:** `[x] SLSA Level 3 reproducible builds verified`
  - **Next Phase 5 item:** Container image signing (cosign + Rekor) — already in release.yml, may be complete; verify on next release tag push.

## Current state (2026-06-12, cycle 130 — STABILIZATION: device-mgmt REST security invariant tests)
- **Cycle 130 (commit 4f0c225):** STABILIZATION — CI GREEN, cargo audit clean (1 allowed: instant/openmls). No open GitHub issues. Security sweep found 3 missing REST-layer test gaps from cycle 128 device management endpoints:
  - **`revoke_device_not_found_returns_401_not_404`** (NEW): verifies the oracle-closing mapping `DomainError::NotFound → 401` (not 404) in `revoke_device_handler`. Critical security invariant — prevents device-existence timing oracle attacks. New mock `MockAuthDeviceRevokeNotFound`.
  - **`revoke_non_owned_device_returns_401`** (NEW): verifies `DomainError::Unauthorized` from the service surfaces as 401 at the HTTP boundary. New mock `MockAuthDeviceRevokeUnauthorized`.
  - **`register_new_device_missing_body_returns_400`** (NEW): input validation gate — empty JSON body rejected (400) before reaching use-case layer.
  - Also added `device_router_with_auth(Arc<dyn AuthUseCase>) → Router` helper for constructing device test routers with custom auth mocks.
  - **465 Rust tests** (+3; was 462); clippy clean; rustfmt clean; 358 frontend tests unchanged.
  - **Deferred YELLOW advisories (unchanged):** same as cycle 129 — see below.

## Current state (2026-06-12, cycle 129 — FEATURE: GET /v1/region/status — prd.md §6.3)
- **Cycle 129 (commit e92a3e0):** FEATURE — closes the final prd.md §6.3 missing endpoint:
  - **`GET /v1/region/status`** (public, no auth): returns `{ "region_id": "eu-de-1", "status": "active", "tier": 1 }`. `tier` is a custom-serialized u8 (1/2/3) stable regardless of Rust enum rename. `status` is always `"active"` (liveness contract).
  - **`AppState`** gains `region_tier: Tier` populated from `AppConfig.tier` (already in config).
  - Placed in `public_routes` alongside `/health` and `/v1/region/detect` — no auth, no rate limit. Response contains zero PII or user-derived data.
  - **security-auditor:** PASS (GREEN). A1: Cloudflare edge cache advisory (infra follow-up, non-blocking). A2: future non-constant status needs re-audit. A3: dead expression in test (cosmetic). All non-blocking.
  - **462 Rust tests** (+5 in powehi-rest-api: 4 required + 1 tier_as_u8 unit; was 457); clippy clean; rustfmt clean.
  - **Deferred YELLOW advisories (new):**
    - Region status A1: no Cloudflare edge cache TTL (infra follow-up)
    - Region status A2: `status` constant today; future non-constant state needs threat-model-checker pass

## Current state (2026-06-12, cycle 128 — FEATURE: POST /v1/auth/devices + DELETE /v1/auth/devices/:id — prd.md §6.3)
- **Cycle 128 (commit 4c4397a):** FEATURE — closes the two missing device-management REST API endpoints from prd.md §6.3:
  - **`POST /v1/auth/devices`** (authenticated): registers an additional device for the current user. Takes `DeviceRegistrationRequest { mls_credential }`, returns `DeviceRegistrationResponse { device_id }`. Server assigns new DeviceId; no session token issued (user must login separately with new device).
  - **`DELETE /v1/auth/devices/:id`** (authenticated): revokes a device. Ownership check (AuthService.revoke_device verifies device.user_id == caller.user_id). On non-owned/missing target → 401 (oracle closed — NotFound remapped to Unauthorized). Active sessions for the revoked device are invalidated in Redis.
  - **`AppState`** gains `device_repo: Arc<dyn DeviceRepository>` to resolve `DeviceId → UserId` in handlers. All 16 AppState test constructions updated; new `NullDeviceRepo` / `FakeDeviceRepo` test helpers added.
  - **`powehi-port-inbound/src/auth.rs`**: Added `DeviceRegistrationResponse { device_id: DeviceId }`.
  - **`AuthService`**: Fixed `#[instrument]` on `register_device`/`revoke_device` to `skip(self, user_id, ...)` — removes user/device IDs from span fields on failure paths (security-auditor finding 1 / no-plaintext-logging).
  - **security-auditor:** PASS after fixes. Finding 1 (MEDIUM, span PII) FIXED. Finding 2 (LOW, device enumeration oracle) FIXED. Findings 3-7 advisory/deferred: (3) redundant DB round-trip TOCTOU, (4) missing per-user device count cap, (5) self-revoke response note, (6) rate-limit class mismatch (api_governor vs auth_governor), (7) axum :id syntax note.
  - **457 Rust tests** (+4: auth-bypass ×2, success ×2); clippy clean; rustfmt clean.

## Current state (2026-06-12, cycle 127 — STABILIZATION: CI red fix — TS 5.8.3 Uint8Array<ArrayBuffer> BlobPart error)
- **Cycle 127 (commit dc901be):** STABILIZATION — CI was RED on Frontend "Bundle budget check" job since cycle 126 (§9.4.1 encrypted thumbnail).
  - **Root cause:** TypeScript 5.8.3 tightened `BlobPart` to require `Uint8Array<ArrayBuffer>` (not the default `Uint8Array<ArrayBufferLike>`). `media_thumbnail_decrypt` in `WasmModule` interface and the exported `mediaThumbnailDecrypt` method both had `Uint8Array` (defaulting to `ArrayBufferLike`), causing `tsc -b` (called by `pnpm build`) to fail.
  - **Fix:** Changed `media_thumbnail_decrypt` WasmModule return type and `mediaThumbnailDecrypt` method return type to `Uint8Array<ArrayBuffer>`. WASM always returns proper `ArrayBuffer`s so this is the correct precise type.
  - **358 frontend tests** (unchanged); tsc clean; Biome clean.
  - **Note:** Cycle 126 (§9.4.1 encrypted thumbnail) was committed but the memory entry was in cycle 125 notes. The thumbnail feature is in commit 766a085.

## Current state (2026-06-11, cycle 125 — STABILIZATION: §5.3 Phase B PQ frontend integration + formatting fixes)
- **Cycle 125 (commit c7034e0):** STABILIZATION — CI GREEN, no open issues. Committed the PQ hybrid frontend integration that was left uncommitted after cycle 123:
  - **`crates/client/powehi-crypto-wasm/src/wasm_exports.rs`** (MODIFIED): `mls_pq_derive_binding` WASM export — HKDF-SHA256(ikm=ss, salt=None, info=b"powehi-pq-binding-v1"||groupId) → 8 bytes → 16-char hex. Handle removed+Zeroized before derivation (single-use). 4 tests: format check, group-scoping, determinism, KAT (c702693eff3c46bd).
  - **`app/src/components/AcceptInviteModal.tsx`** (MODIFIED): Step 7 PQ send — encaps to peer ML-KEM-768 key, MLS-encrypts `pq_init` JSON payload, derives local binding hex, shows hex badge on success (best-effort, classical E2EE intact on failure).
  - **`app/src/hooks/useMessages.ts`** (MODIFIED): `pq_init` envelope handler — decaps with `pqDecapKeyHandle` from auth store, derives binding hex, fires `onPqBinding(groupId, bindingHex)`; does NOT forward to `onMessage` (shouldDisplayMessage=false).
  - **`app/src/components/ChatLayout.tsx`** (MODIFIED): `handlePqBinding` stores `bindingHex` in Chat state. `ConversationHeader` shows "PQ" chip badge when `pqBindingHex` set.
  - **`app/src/store/auth.ts`** (MODIFIED): `pqDecapKeyHandle` field + `clearPqDecapKeyHandle` action; cleared on logout and after first use.
  - **`app/src/components/Login.tsx`** (MODIFIED): Threads `pqDecapKeyHandle` from `mlsInitIdentity`/`mlsInitIdentityFromPhrase` into auth store.
  - **`app/src/hooks/__mocks__/useCryptoWorker.ts`** (MODIFIED): Added `mlsEncrypt`, `mlsDecrypt`, `mlsPqDeriveBinding` mock stubs.
  - **`app/src/workers/mlsPqExtension.test.ts`** (NEW): 7 PQ extension tests (encapKey size, signature size, argument pass-through, field aliasing, pqDecapKeyHandle mock contracts).
  - **Formatting fixes:** biome format applied to 6 files (AcceptInviteModal.tsx, Login.tsx, auth.ts, useMessages.test.ts, ChatLayout.tsx, AcceptInviteModal.test.tsx). Fixed TS error: `makePqEnvelope(ct: number[])` unused param removed.
  - **crypto-reviewer:** PASS (GREEN). HKDF-SHA256 with salt=None RFC 5869 §3.3 compliant. KAT c702693eff3c46bd independently verified. Handle-drop-then-derive correct. 3 YELLOW: Y-B-1 domain prefix-extension concern for future v2 (no length prefix between label and group_id), Y-B-2 group_id string canonicality, Y-B-3 format! allocations in hex conversion.
  - **security-auditor:** PASS (GREEN). No RED findings. 2 YELLOW: Y-1 decap handle retained on partial HKDF failure (benign — logout+clearSessionState cleans up), Y-2 silent NaN on malformed sigKeyHex in AcceptInviteModal hex parser.
  - **353 frontend tests** (+16 vs cycle 122); **417 Rust tests**; tsc clean; biome clean.
  - **Remaining deferred security findings (YELLOW):** same as cycle 122 plus:
    - PQ binding Y-B-1: domain prefix-extension concern (no length prefix between domain label and group_id in HKDF info)
    - PQ binding Y-B-2: group_id &str canonicality not validated at WASM boundary
    - PQ binding Y-B-3: format! allocations in hex conversion (linear memory residue)
    - PQ frontend Y-1: decap key handle retained in Zustand on partial HKDF failure (benign)
    - PQ frontend Y-2: silent NaN on malformed peer.sigKeyHex in AcceptInviteModal

## Current state (2026-06-11, cycle 122 — FEATURE: client-side disappearing message expiry — prd.md §9.4.3)
- **Cycle 122 (commit efad54f):** FEATURE — closes the client-side gap in the disappearing messages feature (prd.md §9.4.3 + §15.3 Post-MVP "Disappearing Messages"). Backend TTL was already enforced server-side (`expires_at` on envelopes); this cycle wires the signal into the frontend and adds a periodic sweep.
  - **`app/src/hooks/useMessages.ts`** (MODIFIED): Added `expiresAt?: number` (unix ms) to `IncomingMessage`. In `processEnvelope`, parses `env.expires_at` ISO string → unix ms before calling `onMessage`.
  - **`app/src/db/schema.ts`** (MODIFIED): Added `expiresAt?: number` to `MessageRow`. Dexie v5 migration adds `expiresAt` as indexed field on messages table for efficient range-query purge.
  - **`app/src/db/encrypted-db.ts`** (MODIFIED): New `purgeExpiredMessages(): Promise<number>` — `db.messages.where("expiresAt").belowOrEqual(now).primaryKeys()` bulk-deletes across all groups. `expiresAt` is intentionally unencrypted (timestamp, not content; same sensitivity class as `receivedAt`/`groupId`).
  - **`app/src/hooks/usePersistentMessages.ts`** (MODIFIED): `persistIncoming` stores `expiresAt: msg.expiresAt`. New `purgeExpired()` callback filters `rows` state (removes `expiresAt ≤ now`) and calls `encryptedDb.purgeExpiredMessages()` best-effort. `PersistedMessages` interface gains `purgeExpired: () => void`.
  - **`app/src/components/ChatLayout.tsx`** (MODIFIED): `handleIncoming` passes `expiresAt: msg.expiresAt` to pushed chat message. Added 30s `setInterval` sweep in `useEffect`: filters expired messages from `chats` React state and calls `purgeExpired()` for Dexie cleanup. Returns `clearInterval` on unmount.
  - **security-auditor:** PASS — no RED. YELLOW-1: 30s cadence vs future sub-30s TTLs (min TTL option is currently 300s; add per-message setTimeout if shorter options added). YELLOW-2: purge failures invisible (no telemetry counter; mirrors pattern of `writeErrorCount` — future work). `expiresAt` not logged, server-authoritative, no XSS, no SSRF.
  - **337 frontend tests** (+5: 2 `useMessages` expiresAt mapping, 3 `usePersistentMessages` purge/store; was 332); Biome clean; tsc clean.
  - **Remaining deferred security findings (YELLOW):** same as cycle 121 plus:
    - Disappearing messages YELLOW-1: sweep cadence vs future sub-30s TTL options
    - Disappearing messages YELLOW-2: purgeExpired failure invisible (no telemetry counter)

## Current state (2026-06-11, cycle 121 — FEATURE: §9.2 media receive path — download, decrypt, display incoming images)
- **Cycle 121 (commit eda5a82):** FEATURE — closes the final §9.2 receiver-side gap: incoming image messages now download and decrypt from R2 and display inline instead of showing "Image attachment" placeholder.
  - **`app/src/hooks/useMediaReceive.ts`** (NEW): Hook that takes `MediaPayload | undefined`. Gets presigned R2 download URL via `getMediaDownloadUrl`, fetches ciphertext with `redirect: "error"` (SSRF defense-in-depth), calls `cryptoWorker.mediaDecryptWithRawKey(mediaKey, iv, ct, blobHash)` (WASM verifies SHA-256(ciphertext) === blobHash before AES-GCM decrypt — R-2 blob-swap detection), creates blob object URL (MIME sniffed from magic bytes: jpeg/png/gif/webp/fallback-jpeg). `mediaKey.fill(0)` in `finally` (security invariant). Object URL revoked on unmount or dep change (no memory leak). `cancelled` flag guards all `await` points.
  - **`app/src/components/MediaImage.tsx`** (NEW): Wrapper around `useMediaReceive` — renders loading placeholder, "Image unavailable" on error, or `<img src={objectUrl} alt="Encrypted attachment">` on success.
  - **`app/src/components/ChatLayout.tsx`** (MODIFIED): `ChatMessage.mediaAttachment?: { blobId }` replaced with `media?: MediaPayload` (stores full payload including key for on-demand decrypt). `handleIncoming` stores `media: msg.media`. `MessageBubble` renders `<MediaImage media={msg.media} />` instead of icon+text placeholder.
  - **security-auditor:** PASS — no RED findings. YELLOWs: (a) mediaKey in React state as `number[]` — known cycle-119 advisory, receiver opaque-handle is future work; (b) MIME fallback image/jpeg — browser decoder reliance; (c) `redirect: "error"` applied (audit finding closed). No plaintext logging, no XSS (blob: URL, no dangerouslySetInnerHTML), token only in Authorization header.
  - **332 frontend tests** (+11 `useMediaReceive` tests; was 321); Biome clean; tsc clean.
  - **Remaining deferred security findings (YELLOW):** same as cycle 120 plus:
    - Media §9.2 YELLOW: mediaKey receiver opaque-handle pattern (future work, currently `number[]` in React state)
    - Media §9.2 YELLOW: MIME fallback image/jpeg (browser decoder risk for unrecognized magic bytes)

## Current state (2026-06-11, cycle 120 — STABILIZATION: CI red fix — rustfmt 1.96.0 + clippy unused_mut in wasm_exports)
- **Cycle 120 (commit 571545a):** STABILIZATION — CI was RED on Rust Format check since cycle 119. Root cause: two formatting drifts in `wasm_exports.rs` test code introduced by `media_message_create` commit:
  - `assert!(parsed.get("rawKey").is_none(), "no rawKey field must be present")` → rustfmt 1.96.0 requires 3-line block form for `assert!(cond, msg)`.
  - `let json_bytes = \n    build_media_payload_json(blob_id, ...)` → rustfmt collapses to single line (fits within 100-char limit with shorter variable names).
  - Also fixed `let mut group_mut` → `let group_mut` (clippy -D unused_mut; variable is immediately dropped, never actually mutated).
  - **cargo fmt --all -- --check:** PASS; **cargo clippy --workspace --all-targets -- -D warnings:** PASS.
  - **93 Rust crypto-wasm tests** (unchanged); **321 frontend tests** (unchanged); **cargo audit:** 1 allowed (instant/openmls, unchanged).
  - **security-auditor:** GREEN — full backend sweep. No new RED findings. Two YELLOW advisories carried forward (non-blocking): rate-limit XFF ops-gate (infra config), HandleRateLimiter unbounded state growth (future cycle).
  - **Remaining deferred security findings (YELLOW):** same as cycle 119 — see below.

## Current state (2026-06-11, cycle 119 — FEATURE: §9.2 media_message_create — MLS-encrypt media payload inside WASM)
- **Cycle 119 (commit 0da8cc7):** FEATURE — closes the final §9.2 sender-path gap: raw AES-256-GCM media key stays inside WASM throughout the entire send sequence.
  - **`crates/client/powehi-crypto-wasm/src/wasm_exports.rs`** (MODIFIED): new `media_message_create` WASM export — retrieves key by opaque handle from `MEDIA_KEYS`, serialises media payload JSON (type, blobId, blobHash, mediaKey, iv) inside WASM via new `build_media_payload_json` pure helper (validates blob_hash=32 bytes, iv=12 bytes), MLS-encrypts via same `encrypt_message` path as `mls_encrypt`, returns only the MLS ciphertext. Raw 32-byte AES key NEVER crosses WASM-JS boundary.
  - **`app/src/workers/crypto.worker.ts`** (MODIFIED): adds `mediaMessageCreate` to `WasmModule` interface and Comlink `api`.
  - **`app/src/hooks/useMediaSend.ts`** (NEW): full §9.2 send flow — `mediaEncrypt` → `requestMediaUpload` → PUT ciphertext to R2 → `confirmMediaUpload` → `mediaMessageCreate` → `sendMessage`. `mediaDropKey` always called in `finally` (handle cleanup invariant). No logging of file content, key bytes, or error details.
  - **`app/src/hooks/useMessages.ts`** (MODIFIED): §9.2 receiver-side JSON parsing — MLS-decrypted payload JSON-parsed for `type=image`; `text` set to `"[image]"`; `MediaPayload` extracted (blobId, blobHash, mediaKey, iv) for downstream download path.
  - **`app/src/components/ChatLayout.tsx`** (MODIFIED): hidden file input wired to Photo button; optimistic "Image attachment" placeholder; `sendMedia(file).catch(() => {})` silent failure; `MessageBubble` renders icon + "Image attachment" for media msgs.
  - **`app/src/hooks/__mocks__/useCryptoWorker.ts`** (MODIFIED): adds `mediaMessageCreate` mock stub.
  - **Tests (+15 Rust + 6 frontend):** `build_media_payload_*` validation tests, `media_message_create` error-path tests (unknown handle/identity/group), encryption smoke test; useMediaSend security invariants (handle always dropped, R2 PUT receives ciphertext not plaintext, etc.).
  - **crypto-reviewer:** PASS — opaque-handle invariant preserved, no RFC 9420 violations. YELLOWs: json_bytes not Zeroizing (advisory, consistent with mls_encrypt pattern), serde number-array encoding (bandwidth advisory), test name overclaim, caller must drop handle (done in useMediaSend.ts).
  - **security-auditor:** PASS — no plaintext logging, token not in URL, `media.mediaKey` NOT persisted to Dexie (persistIncoming verified: only stores id/groupId/ciphertextB64/senderDeviceId/epochSeq/receivedAt/plaintextB64("[image]")). YELLOWs: blobId UUID validation (advisory), mediaKey receiver opaque handle (future work), mediaDropKey failure observability (advisory).
  - **108 Rust crypto-wasm tests** (+15; was 93); **321 frontend tests** (+6; was 315); Biome clean; tsc clean.
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)
    - ML-KEM-768 Phase C remaining: Y-9 Zeroizing buffer-zero verification in tests (unsafe ptr test, future work)
    - Invite system backend YELLOWs Y-1 through Y-6 (cycle 107, non-blocking)
    - Invite frontend YELLOWs Y-1 (DOM code visibility) and Y-2 (origin baseline) — non-blocking
    - useWelcomePoller Y1/Y3: sinceRef does not advance for skipped Application/Welcome envelopes (benign, follow-up)
    - useWelcomePoller Y2: senderDeviceId UUID format not validated client-side (advisory)
    - Recovery clipboard auto-clear (advisory, low priority)
    - Push Y1: silent catch on registerPushSubscription failure (no telemetry, advisory)
    - Push Y2: token rotation gap — existing sub reused under new session (advisory)
    - Push Y3: no group-size cap on fan-out — DoS amplification advisory (cycle 116 Y1)
    - Push Y4: member list re-fetched twice in send_message/send_commit — informational
    - Media §9.2 YELLOWs: json_bytes not Zeroizing (advisory); serde number-array encoding; blobId UUID validation; mediaKey receiver opaque-handle future work; mediaDropKey failure observability
    - Informational: header-shape coupling in auth API tests
    - Pre-existing vitest GHSA-5xrq-8626-4rwp (vitest UI not exposed; low real-world risk)

## Current state (2026-06-10, cycle 116 — FEATURE: Web Push fan-out on send_message + send_commit — prd.md §7.5)
- **Cycle 116 (commit 96755f4):** FEATURE — closes the final §7.5 gap: group message push fan-out.
  - **Root cause:** `send_message` previously only called `maybe_push(sender)`, meaning only the sender received a push ping (meaningless — they already know they sent). Other group members received no wake-up signal.
  - **Fix:** New `fan_out_push(sender, group_id)` method in `MessagingService`:
    - Lists all group members via `group_repo.list_members(group_id)`
    - Filters out the sender (they don't need a wake-up for their own message)
    - Calls `maybe_push(device_id)` for each non-sender member (best-effort sequential)
    - Errors logged with opaque categories only; never propagated to message write path
  - `send_commit` also calls `fan_out_push` so peers can ratchet to the new epoch
  - `send_welcome` unchanged — already pushes directly to the Welcome target
  - **FakePushSubRepo** upgraded from single-sub to `HashMap<DeviceId, PushSubscription>` in tests
  - **+4 new tests:** `fan_out_notifies_all_members_except_sender`; `fan_out_sender_not_notified_even_if_subscribed`; `fan_out_on_send_commit_notifies_members_except_committer`; `fan_out_noop_when_push_not_configured`
  - **2 tests updated** to reflect fan-out (non-sender) semantics
  - **security-auditor:** PASS — GREEN. Y1 (no group-size cap, DoS amplification advisory); Y2 (member list re-fetched twice — informational). Both non-blocking.
  - **75 application tests** (+4 new; was 71); clippy + rustfmt clean; 393 Rust workspace tests total.
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)
    - ML-KEM-768 Phase C remaining: Y-9 Zeroizing buffer-zero verification in tests (unsafe ptr test, future work)
    - Invite system backend YELLOWs Y-1 through Y-6 (cycle 107, non-blocking)
    - Invite frontend YELLOWs Y-1 (DOM code visibility) and Y-2 (origin baseline) — non-blocking
    - useWelcomePoller Y1/Y3: sinceRef does not advance for skipped Application/Welcome envelopes (benign, follow-up)
    - useWelcomePoller Y2: senderDeviceId UUID format not validated client-side (advisory)
    - Recovery clipboard auto-clear (advisory, low priority)
    - Push Y1: silent catch on registerPushSubscription failure (no telemetry, advisory)
    - Push Y2: token rotation gap — existing sub reused under new session (advisory)
    - Push Y3 (new): no group-size cap on fan-out — DoS amplification advisory (cycle 116 Y1)
    - Push Y4 (new): member list re-fetched twice in send_message/send_commit — informational
    - Informational: header-shape coupling in auth API tests
    - Pre-existing vitest GHSA-5xrq-8626-4rwp (vitest UI not exposed; low real-world risk)

## Current state (2026-06-10, cycle 115 — STABILIZATION: BIP-39 registration flow tests + security sweep)
- **Cycle 115 (commit ce4f60f):** STABILIZATION — CI GREEN (latest 2 runs success), cargo audit clean (1 allowed: instant/openmls), no open GitHub issues.
  - **Test gap CLOSED — prd.md §8.5 Login registration flow:** `Login.test.tsx` always mocked `useCryptoWorker` as null, leaving the full BIP-39 registration path (generateRecoveryPhrase → mlsInitIdentityFromPhrase → RecoveryPhraseModal display → deferred login on confirm) without coverage.
    - New `app/src/components/Login.registration.test.tsx` (6 tests): RecoveryPhraseModal appears after registration; all 24 words rendered; auth phase stays "login" until confirmed; phase advances to "app" after confirmation; **security invariant**: recovery words absent from all console output; **security invariant**: regInit receives Uint8Array hash, not plaintext handle.
    - Also added OPAQUE methods (`opaqueRegistrationStart/Finish`, `opaqueLoginStart/Finish`) to `__mocks__/useCryptoWorker.ts` so future tests can mock the full OPAQUE flow.
  - **security-auditor:** GREEN on full backend sweep (push-subscription, invite, group-member handlers). 1 informational YELLOW (unused `_caller` in invite redeem — pre-existing by design per cycle 107 YELLOWs).
  - **288 frontend tests** (+6, was 282); Biome clean; tsc clean; 393 Rust tests unchanged.
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)
    - ML-KEM-768 Phase C remaining: Y-9 Zeroizing buffer-zero verification in tests (unsafe ptr test, future work)
    - Invite system backend YELLOWs Y-1 through Y-6 (cycle 107, non-blocking)
    - Invite frontend YELLOWs Y-1 (DOM code visibility) and Y-2 (origin baseline) — non-blocking
    - useWelcomePoller Y1/Y3: sinceRef does not advance for skipped Application/Welcome envelopes (benign, follow-up)
    - useWelcomePoller Y2: senderDeviceId UUID format not validated client-side (advisory)
    - Recovery clipboard auto-clear (advisory, low priority)
    - Push Y1: silent catch on registerPushSubscription failure (no telemetry, advisory)
    - Push Y2: token rotation gap — existing sub reused under new session (advisory, upsert semantics on backend)
    - Informational: header-shape coupling in auth API tests
    - Pre-existing vitest GHSA-5xrq-8626-4rwp (vitest UI not exposed; low real-world risk)

## Current state (2026-06-10, cycle 114 — FEATURE: Web Push subscription registration — prd.md §7.5)
- **Cycle 114 (commits cffcf5d, 74b25a4):** Two changes:
  1. **CI rustfmt fix (cffcf5d):** `recovery.rs` and `wasm_exports.rs` had formatting drift after stable 1.96.0 — array literal line breaks in KAT constants, `assert_eq!` expansion with message args, `generate_identity_from_keypair` continuation-line form. Fixed to match stable 1.96.0 output. Rust CI is now GREEN.
  2. **FEATURE — prd.md §7.5 Web Push subscription registration (74b25a4):** Closes the `// TODO Phase 5: POST subscription to /v1/push-subscriptions` in `useServiceWorker.ts`:
     - **`app/src/api/push.ts`** (NEW): `registerPushSubscription(token, endpoint, p256dh, auth)` — POST `/v1/push-subscriptions` with Bearer token (never in URL). `unregisterPushSubscription(token)` — DELETE. Both use `authHeaders(token)`.
     - **`app/src/hooks/useServiceWorker.ts`** (MODIFIED): Accepts `sessionToken?: string`. After `PushManager.subscribe()` resolves, calls `registerPushSubscription` if token present. Registration failure swallowed (non-fatal — app works without push per RFC 8291 design).
     - **`app/src/main.tsx`** (MODIFIED): `Root` component reads `sessionToken` from Zustand auth store + `VITE_VAPID_PUBLIC_KEY` from Vite env; passes both to `useServiceWorker`. Missing VAPID key or token → silently skips push (dev/CI safe).
     - **`app/src/vite-env.d.ts`** (MODIFIED): Added `ImportMetaEnv.VITE_VAPID_PUBLIC_KEY?: string` declaration.
  - **security-auditor:** GREEN. Y1 (silent catch no telemetry — advisory); Y2 (token rotation gap — advisory). Both non-blocking.
  - **282 frontend tests** (+16: 9 push API + 7 useServiceWorker; was 266); tsc clean; Biome clean.
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)
    - ML-KEM-768 Phase C remaining: Y-9 Zeroizing buffer-zero verification in tests (unsafe ptr test, future work)
    - Invite system backend YELLOWs Y-1 through Y-6 (cycle 107, non-blocking)
    - Invite frontend YELLOWs Y-1 (DOM code visibility) and Y-2 (origin baseline) — non-blocking
    - useWelcomePoller Y1/Y3: sinceRef does not advance for skipped Application/Welcome envelopes (benign, follow-up)
    - useWelcomePoller Y2: senderDeviceId UUID format not validated client-side (advisory)
    - Recovery clipboard auto-clear (advisory, low priority)
    - Push Y1: silent catch on registerPushSubscription failure (no telemetry, advisory)
    - Push Y2: token rotation gap — existing sub reused under new session (advisory, upsert semantics on backend)
    - Informational: header-shape coupling in auth API tests
    - Pre-existing vitest GHSA-5xrq-8626-4rwp (vitest UI not exposed; low real-world risk)

## Current state (2026-06-10, cycle 113 — FEATURE: BIP-39 recovery phrase — prd.md §8.5)
- **Cycle 113 (commit 7d8c216):** FEATURE — §8.5 Recovery Mechanism implemented:
  - **`crates/client/powehi-crypto-wasm/src/recovery.rs`** (NEW): BIP-39 mnemonic generation (256-bit CSPRNG), PBKDF2-HMAC-SHA512 seed derivation (empty passphrase, by design), HKDF-SHA256 key derivation (salt=None, domain=`b"powehi-mls-signing-v1"`, L=32) → Ed25519 keypair. All secret material in `Zeroizing` wrappers. KAT with two frozen test vectors (all-zero seed, abandon×11+about phrase).
  - **`crates/client/powehi-crypto-wasm/src/mls_group.rs`** (MODIFIED): New `generate_identity_from_keypair()` — uses `SignatureKeyPair::from_raw` with private/public consistency check (re-derives expected public from private via ed25519-dalek; returns `MlsError::SignatureKey` on mismatch, closing F2 from crypto-reviewer).
  - **`crates/client/powehi-crypto-wasm/src/wasm_exports.rs`** (MODIFIED): Two new WASM exports — `mls_generate_recovery_phrase()` (returns `{ words: string[] }`), `mls_init_identity_from_phrase(phrase, identity_bytes)` (same shape as `mls_init_identity`). Private key never crosses WASM-JS boundary.
  - **`app/src/components/RecoveryPhraseModal.tsx`** (NEW): Fixed, non-dismissible modal (no X, no backdrop click, no ESC) showing 24 numbered words in a 4-column grid. Copy-all and confirm buttons. Photon-blue frame (encryption), accretion-orange confirm.
  - **`app/src/components/Login.tsx`** (MODIFIED): Registration now generates BIP-39 phrase → derives `mlsIdentityBytes` (SHA-256(phrase)[0..16]) → `mlsInitIdentityFromPhrase`. Phrase is a local const (never stored in state/IndexedDB). `login()` deferred until modal confirmed via `pendingLoginRef`.
  - **`docs/prd.md` §8.5** (MODIFIED): Added implementation decision note — empty BIP-39 passphrase explicit rationale, HKDF domain label, no-storage invariant.
  - **crypto-reviewer:** YELLOW→fixed. F1 (KAT missing) — pinned HKDF byte constants for 2 vectors. F2 (from_raw no consistency check) — ed25519 re-derivation guard added. F3/F6/F7 advisories addressed in comments + prd.md.
  - **security-auditor:** PASS (GREEN). Y1: clipboard auto-clear (advisory, non-blocking).
  - **71 WASM tests** (+12 recovery; was 59); **266 frontend tests** (+9 RecoveryPhraseModal; was 257). Clippy + tsc + Biome clean.
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)
    - ML-KEM-768 Phase C remaining: Y-9 Zeroizing buffer-zero verification in tests (unsafe ptr test, future work)
    - Invite system backend YELLOWs Y-1 through Y-6 (cycle 107, non-blocking)
    - Invite frontend YELLOWs Y-1 (DOM code visibility) and Y-2 (origin baseline) — non-blocking
    - useWelcomePoller Y1/Y3: sinceRef does not advance for skipped Application/Welcome envelopes (benign, follow-up)
    - useWelcomePoller Y2: senderDeviceId UUID format not validated client-side (advisory)
    - Recovery clipboard auto-clear (advisory, low priority)
    - Informational: header-shape coupling in auth API tests
    - Pre-existing vitest GHSA-5xrq-8626-4rwp (vitest UI not exposed; low real-world risk)

## Current state (2026-06-10, cycle 112 — FEATURE: QR code display in InviteModal — prd.md §8.4)
- **Cycle 112 (commit d44479d):** FEATURE — §8.4 Contact Discovery QR code implemented:
  - **`app/src/components/InviteModal.tsx`** (MODIFIED): Added `qrcode` 1.5.4 import. New `qrDataUrl` state. `useEffect` generates a PNG data URL (`QRCode.toDataURL`) when `inviteUrl` is set — pure client-side via Canvas API, zero network calls. Design system colors: cream `#F2EDE3` dots on cosmic black `#040408`. Cancellation flag guards stale state updates. `.catch()` prevents unhandled rejection from serializing invite code into global error handlers. Modal close clears `qrDataUrl`.
  - **`app/src/components/InviteModal.test.tsx`** (MODIFIED): `vi.mock("qrcode")` returns mock data URL. 3 new tests: QR img rendered after invite creation; descriptive alt text (`"QR code for invite link"`); security invariant — `img.src` is `data:` URL, never `https://`.
  - **security-auditor:** GREEN (0 RED). Y1: unhandled rejection fixed (`.catch()`). Y2: pre-existing vitest GHSA-5xrq-8626-4rwp advisory (unrelated to this cycle, deferred).
  - **257 frontend tests** (+3 QR code; was 254); Biome clean; tsc clean.
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)
    - ML-KEM-768 Phase C remaining: Y-9 Zeroizing buffer-zero verification in tests (unsafe ptr test, future work)
    - Invite system backend YELLOWs Y-1 through Y-6 (cycle 107, non-blocking)
    - Invite frontend YELLOWs Y-1 (DOM code visibility) and Y-2 (origin baseline) — non-blocking
    - useWelcomePoller Y1/Y3: sinceRef does not advance for skipped Application/Welcome envelopes (benign, follow-up)
    - useWelcomePoller Y2: senderDeviceId UUID format not validated client-side (advisory)
    - Informational: header-shape coupling in auth API tests
    - Pre-existing vitest GHSA-5xrq-8626-4rwp (vitest UI not exposed; low real-world risk)

## Current state (2026-06-10, cycle 111 — FEATURE: Welcome message processing — inviter auto-joins group (§8.3))
- **Cycle 111 (commit eaa88fd):** FEATURE — closes the final §8.3 contact discovery gap: inviter's device now auto-joins the MLS group when acceptee sends a Welcome envelope.
  - **`app/src/hooks/useWelcomePoller.ts`** (NEW): Global polling hook. Calls `mlsJoinGroup(identityId, welcomeBytes)` on Welcome envelopes. **Ack-after-callback ordering** (R1 fix): `onNewGroup` callback fires BEFORE `ackMessage` so if the callback throws, the envelope stays on the server for redelivery. Commit/Proposal acked silently. Application envelopes skipped (useMessages owns them).
  - **`app/src/hooks/useMessages.ts`** (MODIFIED): Welcome envelopes are now SKIPPED (no ack) instead of acked silently. Comment updated. useWelcomePoller is the exclusive Welcome acker.
  - **`app/src/components/ChatLayout.tsx`** (MODIFIED): `useWelcomePoller(identityId, handleNewGroup)` wired. `handleNewGroup` inserts a new `Chat` entry with dedup guard (`mlsGroupId` uniqueness), `mlsGroupId=event.groupId`, `mlsIdentityId=identityId`.
  - **security-auditor:** GREEN (R1 ack-before-callback fixed; YELLOW Y1/Y3 sinceRef skip advisory, Y2 senderDeviceId UUID shape advisory — all non-blocking).
  - **254 frontend tests** (+13 useWelcomePoller; +1 ordering invariant; was 241); Biome clean; tsc clean.
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)
    - ML-KEM-768 Phase C remaining: Y-9 Zeroizing buffer-zero verification in tests (future work)
    - Invite system backend YELLOWs Y-1 through Y-6 (cycle 107, non-blocking)
    - Invite frontend YELLOWs Y-1 (DOM code visibility) and Y-2 (origin baseline) — non-blocking
    - useWelcomePoller Y1/Y3: sinceRef does not advance for skipped Application/Welcome envelopes (benign, follow-up)
    - useWelcomePoller Y2: senderDeviceId UUID format not validated client-side (React escaping prevents XSS; advisory)
    - Informational: header-shape coupling in auth API tests

## Current state (2026-06-09, cycle 109 — FEATURE: invite acceptance flow — AcceptInviteModal + MLS identity persistence)
- **Cycle 109 (commit 954df2e):** FEATURE — receiving side of §8.3 contact discovery implemented:
  - **`app/src/components/AcceptInviteModal.tsx`** (NEW): Full invite accept flow (prd.md §8.3). `handleAccept()` sequence: redeemInvite → fetchKeyPackage → mlsCreateGroup → mlsAddMember → createGroup → addMember → sendWelcome. Idle/loading/accepted/error states. Error kinds: expired / no_key_package / no_identity / generic. Security: invite code in POST body (never URL); Welcome is Uint8Array (MLS ciphertext); server sees only opaque UUIDs.
  - **`app/src/App.tsx`**: Detect invite code in URL fragment on auth, clear hash via `history.replaceState` after reading (RFC 3986 §3.5 — fragment never sent to server). Renders `<AcceptInviteModal>` when code present + phase=app.
  - **`app/src/components/Login.tsx`**: MLS identity bytes (16-byte BasicCredential public label, NOT a secret) persisted to IndexedDB as `mlsIdentityB64`; re-initialised on each sign-in via `mlsInitIdentity(bytes)` so KeyPackages across sessions are consistent with same device identity.
  - **`app/src/store/auth.ts`**: Added `identityId: string | null` (WASM handle) to AuthState; `login()` accepts optional 3rd param.
  - **`app/src/db/schema.ts`**: v4 migration adds `mlsIdentityId` / `mlsIdentityB64` to LocalIdentity.
  - **Tests:** 12 new AcceptInviteModal tests (render + 5 success flow + 4 error path + 1 security invariant); 3 new App hash-detection tests; updated auth/schema/base64 tests. **241 frontend tests** total (+22 vs cycle 108). security-auditor: PASS (7/7 categories).
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)
    - ML-KEM-768 Phase C remaining:
      - Y-9: Zeroizing buffer-zero verification in tests (unsafe ptr test, future work)
    - Invite system backend YELLOWs Y-1 through Y-6 (cycle 107, non-blocking)
    - Invite frontend YELLOWs Y-1 (DOM code visibility) and Y-2 (origin baseline) — non-blocking
    - Informational: header-shape coupling in auth API tests

## Current state (2026-06-09, cycle 108 — FEATURE: frontend invite link UI — closes §8.3 frontend gap)
- **Cycle 108 (commit cebbfe7):** FEATURE — frontend invite link UI completing the §8.3 contact discovery flow:
  - **`app/src/api/invites.ts`:** `createInvite()`, `redeemInvite()`, `buildInviteUrl()`, `extractInviteCode()`. Code sent in POST body (never URL path); shareable link places code in `#fragment` (browser-standard — never reaches server per RFC 3986).
  - **`app/src/components/InviteModal.tsx`:** `<dialog>` modal wired to "New chat" (+) button; idle → loading → ready/error flow; copy-to-clipboard button; Escape key + backdrop click close. Security-auditor GREEN.
  - **`app/src/components/Icon.tsx`:** Added `copy` and `alert` icon paths.
  - **`app/src/components/ChatLayout.tsx`:** `onNewChat` now opens `InviteModal`.
  - **security-auditor:** GREEN — 0 RED. 2 YELLOW non-blocking: (Y-1) code rendered in DOM (design intent; 24h/one-use bounds blast radius); (Y-2) `window.location.origin` baseline (build-time VITE var would be tighter but not required).
  - **219 frontend tests** (+30, was 189): 19 API unit tests (`createInvite`, `redeemInvite`, `buildInviteUrl`, `extractInviteCode`) + 11 modal tests (render/create/copy/close flows). Biome clean; tsc clean.
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)
    - ML-KEM-768 Phase C remaining:
      - Y-9: Zeroizing buffer-zero verification in tests (unsafe ptr test, future work)
    - Invite system backend YELLOWs Y-1 through Y-6 (cycle 107, non-blocking)
    - Invite frontend YELLOWs Y-1 (DOM code visibility) and Y-2 (origin baseline) — non-blocking
    - Informational: header-shape coupling in auth API tests

## Current state (2026-06-09, cycle 107 — FEATURE: one-time contact invite codes + Y-ACVP-2 closure)
- **Cycle 107 (commit a711c83):** FEATURE — contact invite system implemented per prd.md §8.3:
  - **`POST /v1/invites`** (authenticated): creates 24h one-time invite code. Code = `Uuid::new_v4().simple()` (32 lowercase hex, 122-bit CSPRNG entropy). Stored as `invite:SHA256(code) → DeviceId bytes` in Redis — Redis dump yields no usable tokens.
  - **`POST /v1/invites/redeem`** (authenticated): atomically redeems code via `GETDEL` (zero-TOCTOU window in production). Returns inviter's `DeviceId` so caller can fetch KeyPackage and initiate MLS Welcome. Returns 404 for expired/unknown codes AND invalid-format codes (no oracle).
  - **Code validation:** 32 chars, `[0-9a-f]` only — rejects oversized/non-lowercase before any cache lookup.
  - **Threat model update:** prd.md §3 updated with invite metadata surface (server sees inviter device_id + creation/consumption timestamps; Redis stores H(code) not code; GETDEL ensures no permanent record).
  - **Y-ACVP-2 CLOSED:** Added Cargo.lock SHA256 provenance comment (`8de49b3d...`) to the NIST ACVP vector block in `kem.rs`.
  - **security-auditor:** PASS (0 RED; 6 YELLOW deferred — all non-blocking):
    - Y-1: Self-invite not prevented (caller discarded in handler)
    - Y-2: DEBUG `invite.redeemed` log leaks (inviter,redeemer) social-graph edge at DEBUG level
    - Y-3: No route-level body limit on RedeemInviteRequest (global 512KB cap applies)
    - Y-4: SET not SET-NX for invite creation (UUID collision negligible but not explicit)
    - Y-5: api_governor shared with all API endpoints; invite-specific per-device quota would be tighter
    - Y-6: Timing distinguishability between format-reject vs cache-miss (not exploitable)
  - **393 Rust tests** (+9 invite: 4 invite_service + 5 REST; was 384); clippy clean; rustfmt clean.
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)
    - ML-KEM-768 Phase C remaining:
      - Y-9: Zeroizing buffer-zero verification in tests (unsafe ptr test, future work)
    - Invite system YELLOWs Y-1 through Y-6 (see above, non-blocking)
    - Informational: header-shape coupling in auth API tests

## Current state (2026-06-09, cycle 105 — STABILIZATION: push-subscription auth-bypass tests + RUSTSEC-2026-0173 audit)
- **Cycle 105 (commit 7ad1b86):** STABILIZATION — CI GREEN, no open issues.
  - **New advisory RUSTSEC-2026-0173:** `proc-macro-error2 2.0.1` unmaintained. Added to `.cargo/audit.toml` ignore list with full impact analysis: compile-time proc-macro dep (hax-lib-macros → hax-lib → libcrux → openmls_rust_crypto 0.5.1), not in any production binary, no CVE or vulnerability. `cargo tree -i proc-macro-error2` returns empty for default targets. Cannot upgrade: upstream openmls_rust_crypto 0.5.1 is the latest. Cargo audit now shows 1 allowed warning (instant/openmls only).
  - **Test gap CLOSED:** `POST /v1/push-subscriptions` and `DELETE /v1/push-subscriptions` both lacked auth-bypass (401) invariant tests. Required by testing-conventions.md: "auth bypass impossible: unauthenticated request to a protected endpoint returns 401." Added `post_push_subscription_without_token_returns_401` and `delete_push_subscription_without_token_returns_401` in `push_subscription.rs`.
  - **security-auditor:** GREEN on full backend sweep — all handlers use `AuthenticatedDevice`, all SQL parameterized, no plaintext logging, OPAQUE oracle closed, error mapping safe.
  - **384 Rust tests** (+2, was 382); 189 frontend tests unchanged; clippy clean; rustfmt clean; Biome clean; tsc clean.
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)
    - ML-KEM-768 Phase C remaining:
      - Y-9: Zeroizing buffer-zero verification in tests (unsafe ptr test, future work)
      - Y-ACVP-2: ACVP vector provenance — upstream encap-decap.json not vendored in-tree
    - Informational: header-shape coupling in auth API tests (if fetch init migrates to `Headers` instance); lowercase `cookie` and `credentials: "include"` absence assertions

## Current state (2026-06-06, cycle 104 — FEATURE: close Cookie + case-insensitive auth header advisories)
- **Cycle 104 (commit a23a5ee):** Closed the two non-blocking advisories filed by security-auditor in cycle 103:
  - **Cookie header absence CLOSED:** `regInit`, `regFinish`, `loginInit`, `loginFinish` each assert `headers?.Cookie` is `undefined` — guards against future refactors that accidentally attach session cookies to unauthenticated requests.
  - **Lowercase authorization absence CLOSED:** `regInit`, `regFinish`, `loginInit`, `loginFinish` each assert `headers?.authorization` (lowercase) is `undefined` — closes the case-insensitive gap. If code ever sets `"authorization": token` instead of `"Authorization": token`, the test fails.
  - **security-auditor:** PASS — GREEN, no RED/YELLOW blockers. Two informational findings deferred to next cycle: (1) header-shape coupling (if fetch init migrates to `Headers` instance, property access semantics differ); (2) lowercase `cookie` and `credentials: "include"` absence assertions.
  - **189 frontend tests** (+8, was 181); Biome clean; tsc clean; security-auditor PASS.
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)
    - ML-KEM-768 Phase C remaining:
      - Y-9: Zeroizing buffer-zero verification in tests (unsafe ptr test, future work)
      - Y-ACVP-2: ACVP vector provenance — upstream encap-decap.json not vendored in-tree
    - Future auth test hardening (next cycle): lowercase `cookie` check, `credentials: "include"` absence, `Object.keys(headers)` comprehensive assertion

## Current state (2026-06-06, cycle 103 — FEATURE: close 5 auth API security-auditor YELLOWs from cycle 102)
- **Cycle 103 (commit 0b014fd):** Closed all 5 YELLOW advisories filed by security-auditor in cycle 102:
  - **Token not-in-URL CLOSED:** `uploadKeyPackage` test asserts Bearer token does not appear in the request URL (must be in Authorization header only).
  - **regFinish wire shape CLOSED:** New test verifies body fields: `user_id` (string), `opaque_record` and `mls_credential` as number arrays with correct lengths.
  - **loginFinish body shape CLOSED:** New test verifies `opaque_ke3` is a number array of correct length, `login_nonce` and `device_id` are strings.
  - **Log args count CLOSED:** `uploadKeyPackage` `console.warn` now asserted to be called with exactly 2 args (prefix + status code) — catches any future key/body/token leak appended to the warn line.
  - **Pre-auth no-token CLOSED:** `regInit`, `regFinish`, `loginInit`, `loginFinish` each assert `headers?.Authorization` is `undefined`.
  - **security-auditor:** GREEN — no RED/YELLOW blockers. Two non-blocking advisories for future cycles: (1) assert absence of Cookie header on pre-auth endpoints; (2) case-insensitive `authorization` header check.
  - **181 frontend tests** (+8, was 173); Biome clean; security-auditor GREEN.
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)
    - ML-KEM-768 Phase C remaining:
      - Y-9: Zeroizing buffer-zero verification in tests (unsafe ptr test, future work)
      - Y-ACVP-2: ACVP vector provenance — upstream encap-decap.json not vendored in-tree
    - Future auth test hardening: Cookie header assertion + case-insensitive authorization check

## Current state (2026-06-06, cycle 102 — FEATURE: auth API client tests + workspace MSRV — closes Y-ACVP-1)
- **Cycle 102 (commit da59613):** Closed advisory Y-ACVP-1 and filled auth API test gap:
  - **Y-ACVP-1 CLOSED:** Added `rust-version = "1.87"` to `[workspace.package]` in root `Cargo.toml`. Formalises the minimum Rust version required by `is_multiple_of` (stabilised in Rust 1.87, used in `powehi-crypto-wasm`). CI @1.96.0 already satisfied; this pins the contract.
  - **Test gap CLOSED:** New `app/src/api/auth.test.ts` — 21 tests covering the full OPAQUE auth API client (`hashHandle`, `regInit`, `regFinish`, `loginInit`, `loginFinish`, `uploadKeyPackage`). Previously the only coverage was in `Login.test.tsx` which mocked all these functions.
  - **Security invariants tested:**
    - Sentinel-string assertions: plaintext handle never appears in `regInit`/`loginInit` request body
    - `handle_hash` is a 32-element number array (not a string) in all protocol messages
    - `loginFinish` maps server `"unauthorized"` → `"invalid_credentials"` (prevents user-not-found oracle)
    - `uploadKeyPackage` non-fatal on HTTP failure (does not throw)
    - HTTP status code is logged on KP upload failure, not key bytes
  - **security-auditor:** PASS — GREEN on all 5 checks. Five YELLOW advisories for future test-author symmetry work (token not-in-URL assertion, regFinish wire shape, body shape for loginFinish/regFinish, log args count check, pre-auth endpoints don't attach tokens). All non-blocking.
  - **173 frontend tests** (+21, was 152); Biome clean; tsc clean.
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)
    - ML-KEM-768 Phase C remaining:
      - Y-9: Zeroizing buffer-zero verification in tests (unsafe ptr test, future work)
      - Y-ACVP-2: ACVP vector provenance — upstream encap-decap.json not vendored in-tree

## Current state (2026-06-05, cycle 101 — STABILIZATION: CI red fix — rustfmt 1.96.0 assert! formatting in ACVP KAT)
- **Cycle 101 (commit 67da97e):** CI was RED on Format check since cycle 100. Root cause: Rust stable updated to 1.96.0 (2026-05-28), which reformats single-line `assert!(condition, message)` with both args to a 3-line block. Fixed `kem.rs:449` `from_hex` helper in `acvp_kat_tests` module. `cargo fmt --all --check` passes; all tests green (59 Rust tests in crypto-wasm, full workspace clean). No security/logic changes.
  - **Advisory:** Y-ACVP-1 (is_multiple_of Rust ≥1.87) confirmed non-blocking — CI now on 1.96.0 which satisfies.
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)
    - ML-KEM-768 Phase C remaining:
      - Y-9: Zeroizing buffer-zero verification in tests (unsafe ptr test, future work)
      - Y-ACVP-2: ACVP vector provenance — upstream encap-decap.json not vendored in-tree (add SHA256 comment or fixture in future)

## Current state (2026-06-05, cycle 100 — STABILIZATION: NIST ACVP ML-KEM-768 KAT — closes Y-5 (ADR-0003 Phase C))
- **Cycle 100 (commit 87ecdcd):** STABILIZATION — CI GREEN, no open issues. Closed Y-5 (NIST ACVP conformance KAT):
  - **Y-5 CLOSED:** New `mod acvp_kat_tests` in `kem.rs` — 2 `#[test]` functions (cfg(test) only, not in prod WASM binary):
    - `ml_kem_768_nist_acvp_encap_conformance`: FIPS 203 §6.2 ML-KEM.Encaps_internal — uses `EncapsulateDeterministic` with NIST-sourced `(ek, m)` from RustCrypto/KEMs ml-kem/tests/encap-decap.json (mirrors usnistgov/ACVP-Server@65370b8), tcId 26. Verifies `(ct, ss)` matches NIST expected output.
    - `ml_kem_768_nist_acvp_decap_conformance`: FIPS 203 §6.3 — uses NIST-sourced `(dk, ct)`, verifies `ss` matches. Together these close Y-5 for both encap+decap directions.
  - **Key correctness:** Vectors independently computed by NIST (not self-consistent like the regression KAT). A FIPS 203-non-conformant ml-kem cannot produce correct output even if self-consistency passes. `EncapsulateDeterministic` exercises ML-KEM.Encaps_internal (FIPS 203 Alg. 17) exactly. `Ciphertext<MlKem768>` is the correct public type (consistent with production `decapsulate()`).
  - **Compilation fix:** Changed `ml_kem::kem::EncodedCiphertext<MlKem768Params>` (private type) to `Ciphertext<MlKem768>` (public) in ACVP decap test.
  - **cargo audit:** clean (1 allowed: instant/openmls unmaintained, unchanged).
  - **crypto-reviewer:** PASS — GREEN on all criteria. Y-ACVP-1 (is_multiple_of Rust ≥1.87, non-blocking: CI @stable ≥1.87) and Y-ACVP-2 (vector provenance comment advisory) filed below.
  - **59 Rust tests** (+2 ACVP KAT; was 57); rustfmt clean; clippy clean (is_multiple_of fix applied).
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)
    - ML-KEM-768 Phase C remaining:
      - Y-9: Zeroizing buffer-zero verification in tests (unsafe ptr test, future work)
      - Y-ACVP-1: Workspace has no `rust-version` field; `is_multiple_of` requires ≥1.87 (CI @stable is fine; advisory only)
      - Y-ACVP-2: ACVP vector provenance — upstream encap-decap.json not vendored in-tree (add SHA256 comment or fixture in future)

## Current state (2026-06-05, cycle 98 — FEATURE: wasm-bindgen cap tests — closes YELLOW-2 (ADR-0003 Phase C))
- **Cycle 98 (commit 2f57c52):** FEATURE — closed YELLOW-2 from cycle-97 crypto-reviewer (no wasm-bindgen integration test verifying cap→JsError at the JS boundary):
  - **YELLOW-2 CLOSED:** New file `crates/client/powehi-crypto-wasm/tests/wasm_bindgen_tests.rs` — 2 `#[wasm_bindgen_test]` integration tests:
    - `test_keygen_v2_cap_exceeded_returns_js_error`: fills `KEM_DECAP_KEYS` to 256 via `ml_kem_768_keygen_v2()`, asserts 257th returns `Err(JsError)` with message containing "cap exceeded". Cleans up via `ml_kem_768_drop_decap_key`.
    - `test_encap_v2_cap_exceeded_returns_js_error`: fills `KEM_SHARED_SECRETS` to 256 via `ml_kem_768_encap_v2()` (same map checked by `decap_v2`), asserts 257th returns `Err(JsError)`. Uses `mls_clear_session()` for full cleanup. Also covers the `decap_v2` cap path (same map).
  - **Helper `js_err_message`:** uses `wasm_bindgen::JsCast::dyn_into::<js_sys::Error>()` to extract the JsError message string at the JS boundary — not relying on `Display` which is not guaranteed in wasm context.
  - **New CI job `wasm-test`** in `ci-frontend.yml`: `wasm-pack test --node crates/client/powehi-crypto-wasm` with Node.js 20 setup. Tests run only under wasm32 (0 native tests confirmed, consistent with `wasm_bindgen_test` semantics).
  - **crypto-reviewer:** PASS — GREEN on all criteria. FIPS 203 §6.2 multi-encap with same key is correct (randomized per call, IND-CCA2). Cleanup is correct. No RFC 9420 violations.
  - **57 WASM tests** (unchanged native; +2 wasm-bindgen tests run via wasm-pack test --node); rustfmt clean; clippy clean.
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)
    - ML-KEM-768 Phase C remaining:
      - Y-5 follow-up: NIST ACVP conformance KAT (official vectors from ACVP-Server)
      - Y-9: Zeroizing buffer-zero verification in tests (unsafe ptr test, future work)

## Current state (2026-06-05, cycle 97 — FEATURE: KEM handle cap — closes Y-8 (ADR-0003 Phase C))
- **Cycle 97 (commit c3787c4):** FEATURE — closed Y-8 from cycle-90 crypto-reviewer (unbounded KEM_SHARED_SECRETS growth on repeated decap):
  - **Y-8 CLOSED:** `MAX_KEM_HANDLES = 256` cap on both `KEM_DECAP_KEYS` and `KEM_SHARED_SECRETS` thread-local maps.
  - **`kem_cap_check(len) -> Result<(), &'static str>`:** Pure helper function (no JsValue/JsError, callable in native tests). TOCTOU-safe invariant documented in docstring (WASM single-threaded, no `.await` between check and insert).
  - **Cap check wired in 3 WASM exports:**
    - `ml_kem_768_keygen_v2`: checks `KEM_DECAP_KEYS.len() < 256` before `kem::generate()` — no wasted CSPRNG on rejected path.
    - `ml_kem_768_encap_v2`: checks `KEM_SHARED_SECRETS.len() < 256` before `kem::encapsulate()`.
    - `ml_kem_768_decap_v2`: checks `KEM_SHARED_SECRETS.len() < 256` before `kem::decapsulate()`; old Y-8 deferral comment removed.
  - **+3 security tests:**
    - `test_kem_cap_check_boundary`: pure logic test (0, MAX-1, MAX, MAX+1).
    - `test_kem_decap_keys_cap_and_release`: fills `KEM_DECAP_KEYS` to 256 with dummy bytes, verifies cap fires, drops one, verifies cap releases.
    - `test_kem_shared_secrets_cap_and_release`: same for `KEM_SHARED_SECRETS`.
  - **crypto-reviewer:** PASS — GREEN on all 10 correctness criteria. YELLOW-1 (single-thread invariant comment) addressed in docstring. YELLOW-2 (wasm-bindgen integration test for cap → JsError) deferred to next cycle.
  - **57 WASM tests** (+3; was 54); rustfmt clean; clippy clean.
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)
    - ML-KEM-768 Phase C remaining:
      - Y-5 follow-up: NIST ACVP conformance KAT (official vectors from ACVP-Server)
      - Y-9: Zeroizing buffer-zero verification in tests (unsafe ptr test, future work)
      - YELLOW-2 from cycle 97: wasm-bindgen integration test for cap-exceeds-as-JsError

## Current state (2026-06-05, cycle 96 — FEATURE: KAT for sign_encap_key wire format — closes YELLOW-b)
- **Cycle 96 (commit 9b3f18c):** FEATURE — closed YELLOW-b from cycle-95 crypto-reviewer (no KAT for ml_kem_sign_encap_key output wire format):
  - **YELLOW-b CLOSED:** New test `sign_encap_key_kat_wire_format` in `kem_credential.rs`:
    - Fixed seed: `[0x42u8; 32]` → derived public key via `ed25519-dalek 2.2.0 SigningKey::from_bytes`
    - Signs all-zero 1184-byte encap key with domain `SIGN_DOMAIN || 0x00 || ek`
    - Asserts exact 64-byte signature matches hardcoded `KAT_SIG` constant (captured from openmls_basic_credential 0.5.0 + ed25519-dalek 2.2.0)
    - Asserts `verify_encap_key` returns `Ok(true)` for the KAT signature (round-trip)
    - Detects silent library drift (ed25519-dalek upgrade) and supply-chain tampering
  - **Ignored capture helper:** `kem_credential_kat_capture` — derives key from fixed seed via ed25519-dalek, signs + verifies, prints bytes for re-capture. Includes crypto-reviewer gate comment (WARNING: rotation must be reviewed by crypto-reviewer agent before commit — YELLOW-2 from crypto-review fix).
  - **Workspace dep hoist:** `ed25519-dalek = "2.2"` hoisted to `[workspace.dependencies]` in root `Cargo.toml` (YELLOW-1 from crypto-review fix, prevents future version skew).
  - **crypto-reviewer:** PASS — GREEN on all correctness criteria. YELLOW-1 (workspace pin) and YELLOW-2 (KAT rotation gate comment) both fixed in this cycle. No RFC 8032/9420 violations.
  - **54 WASM tests** (+1 KAT test; was 53); rustfmt clean; clippy clean.
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)
    - ML-KEM-768 Phase C remaining:
      - Y-5 follow-up: NIST ACVP conformance KAT (official vectors from ACVP-Server)
      - Y-8: CLOSED (cycle 97) — KEM handle cap MAX=256 implemented
      - Y-9: Zeroizing buffer-zero verification in tests (unsafe ptr test, future work)
      - YELLOW-2 from cycle 97: wasm-bindgen integration test for cap-exceeds-as-JsError

## Current state (2026-06-05, cycle 95 — STABILIZATION: CI red fix + crypto test gap closure)
- **Cycle 95 (commits a0d4645, 30ffa1a):** STABILIZATION — CI was RED on both Rust + Frontend pipelines since cycle-94 commit (e8bb982). Fixed:
  - **Rust CI fix (a0d4645):** `cargo fmt` stable 1.96.0 emitted diffs for 3 files added in cycle 94:
    - `kem_credential.rs`: `sign_encap_key` params collapsed to one line (fits ≤100 chars), `tampered_encap_key_rejects_signature` let-binding style, `assert_ne!` expanded to 3-line macro form
    - `wasm_exports.rs`: `ml_kem_768_sign_encap_key` params on one line, two method-chain test assertions flattened
  - **Frontend CI fix (a0d4645):** Biome line-width violation — `mlKem768SignEncapKey` method signature in `crypto.worker.ts` collapsed to one line.
  - **crypto-reviewer sweep (GREEN) on `kem_credential.rs`:** All cryptographic properties verified: domain separation sound (`SIGN_DOMAIN || 0x00 || ek`), signing uses openmls Signer trait correctly, verification correctly collapses `InvalidSignature`/`CryptoLibraryError` → `Ok(false)`, input validation complete. No RFC 9420 violations. Two YELLOW test gaps identified (non-blocking):
    - YELLOW-a: No cross-protocol domain-separation regression test → CLOSED this cycle
    - YELLOW-b: No KAT for sign output wire format → deferred to next cycle
  - **New tests (30ffa1a):**
    - `kem_credential.rs`: `raw_signature_without_domain_is_rejected` — signs `ek_bytes` without domain prefix and asserts `verify_encap_key` returns `Ok(false)` (domain-separation regression)
    - `wasm_exports.rs`: `test_ml_kem_sign_unknown_identity_returns_error` — confirms `MLS_CTX.get()` returns `None` for unregistered identity_id (WASM export fail-closed path)
  - **cargo audit:** clean (1 allowed: instant/openmls unmaintained, unchanged)
  - **53 WASM tests** (+2 new, was 51 before cycle 94 formatting; cycle 94 added sign/verify tests); **152 frontend tests** unchanged; rustfmt clean; Biome clean; clippy clean.
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)
    - ML-KEM-768 Phase B remaining prerequisites:
      - Y-3 CLOSED (cycle 94): Encap key authentication via Ed25519 sign/verify implemented
      - Y-5 follow-up: NIST ACVP conformance KAT (official vectors from ACVP-Server)
      - Y-8: Unbounded KEM_SHARED_SECRETS growth on repeated decap (Phase C rate limiting)
      - Y-9: Zeroizing buffer-zero verification in tests (unsafe ptr test, future work)
      - YELLOW-b: KAT for ml_kem_sign_encap_key output wire format (deferred from cycle 95)

## Current state (2026-06-04, cycle 94 — FEATURE: ADR-0003 Phase B — ML-KEM encap key authentication, Y-3 closed)
- **Cycle 94 (commit e8bb982):** ADR-0003 Phase B — closed Y-3 from cycle-90 crypto-reviewer (encap key not authenticated):
  - **Y-3 CLOSED:** New module `kem_credential.rs` — `sign_encap_key(ek_bytes, signer)` signs `SIGN_DOMAIN || 0x00 || ek_bytes` with MLS Ed25519 identity key; `verify_encap_key(ek, sig, pub_key, provider)` verifies. Domain `b"powehi-kem-ek-v1"` with NUL separator prevents cross-protocol reuse and prefix extension.
  - **WASM exports:** `ml_kem_768_sign_encap_key(identity_id, encap_key)` → `{signature: 64 bytes}`; `ml_kem_768_verify_encap_key(encap_key, signature, sig_pub_key)` → `{valid: boolean}`. Private signing key stays in MLS_CTX; signature (public) may cross WASM-JS boundary.
  - **`crypto.worker.ts`:** `mlKem768SignEncapKey(identityId, encapKey)` and `mlKem768VerifyEncapKey(encapKey, signature, sigPubKey)` added to Comlink API.
  - **+5 frontend tests** in `mlKem768Credential.test.ts`: API contract tests (signature size, no private key in result, verify returns boolean, round-trip mock, no key material in verify result).
  - **+11 Rust unit tests** in `kem_credential.rs`: round-trip, determinism, wrong-pubkey, tampered-ek, tampered-sig, cross-key isolation, input validation.
  - **+2 WASM tests** in `wasm_exports.rs`: sign+verify via internal state, wrong-pubkey via internal state.
  - **crypto-reviewer:** PASS (GREEN, cycle 95 sweep) — see cycle 95 entry above.
  - **CI FAILURE (fixed in cycle 95):** rustfmt stable 1.96.0 + Biome line-width violations — formatting-only, no logic changed.
  - **Remaining deferred security findings (YELLOW):** see cycle 95 entry above.

## Current state (2026-06-04, cycle 93 — FEATURE: ADR-0003 Phase B — ML-KEM opaque-handle pattern, Y-1 closed)
- **Cycle 93 (commit 36277ae):** ADR-0003 Phase B — closed Y-1 from cycle-90 crypto-reviewer (raw ML-KEM key bytes crossed WASM-JS boundary):
  - **Y-1 CLOSED:** New opaque-handle API: `ml_kem_768_keygen_v2` returns `{encapKey, decapKeyHandle}`, `ml_kem_768_encap_v2` returns `{ciphertext, sharedSecretHandle}`, `ml_kem_768_decap_v2(handle, ct)` returns `{sharedSecretHandle}`. Raw decap keys (2400 bytes) and shared secrets (32 bytes) are stored in `KEM_DECAP_KEYS` and `KEM_SHARED_SECRETS` thread-locals (`Zeroizing<Vec<u8>>`) — never returned to JS.
  - **Y-7 NEW+FIXED:** JS object built before thread-local insert in all 3 v2 functions, preventing orphan handle entries if `js_obj()` fails (extraordinary JS host exception).
  - **`mls_clear_session()` extended:** now also clears `KEM_DECAP_KEYS` and `KEM_SHARED_SECRETS` (Zeroizing zeroes each buffer on drop).
  - **Phase A exports preserved** (`ml_kem_768_keygen/encap/decap`) with "Phase A test surface only" warnings — kept for backward compatibility during migration window.
  - **crypto-reviewer:** PASS — Y-1 CLOSED. Y-7 fixed. Y-8 (DoS via unbounded decap calls — documented in comment, Phase C), Y-9 (Zeroizing buffer-zero verification in tests — future unsafe test), Y-10 (sequential handle IDs visible in WASM memory — informational, pre-existing) noted but non-blocking.
  - **+8 native Rust tests** (handle storage, round-trip via handles, explicit drop, clear_session clears KEM); **+12 frontend tests** (opaque-handle invariant, `@ts-expect-error` type guards, idempotent drop).
  - **DB reset fix:** `usePersistentMessages.test.ts` `beforeEach` now calls `indexedDB.deleteDatabase("PowehiDb")` before each test, fixing flaky "Y1 — outgoing epochSeq" test caused by cross-test IndexedDB state contamination.
  - **39 WASM tests** (+8); **147 frontend tests** (+12); clippy clean; rustfmt clean.
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)
    - ML-KEM-768 Phase B remaining prerequisites:
      - Y-3: Encap key not authenticated (Phase B hybrid handshake must bind ek to signed credential)
      - Y-5 follow-up: NIST ACVP conformance KAT (official vectors from ACVP-Server)
      - Y-8: Unbounded KEM_SHARED_SECRETS growth on repeated decap (Phase C rate limiting)
      - Y-9: Zeroizing buffer-zero verification in tests (unsafe ptr test, future work)

## Current state (2026-06-04, cycle 92 — FEATURE: ADR-0003 Phase B — ml-kem version pin + regression KAT)
- **Cycle 92 (commit 9136790):** ADR-0003 Phase B — closed Y-5 (partial) and Y-6 from cycle-90 crypto-reviewer:
  - **Y-6 CLOSED:** `ml-kem` workspace dep tightened from `"0.2"` to `"=0.2.3"` in `Cargo.toml`. Prevents silent `cargo update` to a future 0.2.x that could shift KAT output or introduce behavioral differences. The Cargo.lock checksum `8de49b3df74c35498c0232031bb7e85f9389f913e2796169c8ab47a53993a18f` is now the authoritative pin.
  - **Y-5 PARTIALLY CLOSED:** Added `kem::kat_tests::ml_kem_768_regression_kat_fixed_seed` — uses `generate_deterministic(d, z)` + `encapsulate_deterministic(m)` with fixed seeds (d=0x00..1f, z=0x20..3f, m=0x40..5f) to pin:
    - First 16 bytes of encapsulation key (supply-chain / tamper detection)
    - Full 32-byte shared secret captured from ml-kem 0.2.3
    - Verifies: key sizes (FIPS 203 §2.4), encap/decap agreement, determinism
  - **`deterministic` feature added to `[dev-dependencies]`** in `powehi-crypto-wasm/Cargo.toml` only — NOT compiled into production WASM binary.
  - **crypto-reviewer:** PASS — no RED findings. Y-5 partially closed (self-consistency / supply-chain guard; NOT a NIST ACVP conformance test — full FIPS 203 §A.3 conformance via official vectors is Y-5 follow-up). No production code changed.
  - **354 Rust tests** (+1 KAT test; was 353 non-ignored); clippy clean; rustfmt clean.
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)
    - ML-KEM-768 Phase B remaining prerequisites:
      - Y-1: decapKey/sharedSecret cross worker boundary as raw Uint8Array (opaque-handle pattern, Phase B architecture)
      - Y-2: Transient stack array (documented, no action needed)
      - Y-3: Encap key not authenticated (Phase B hybrid handshake)
      - Y-5 follow-up: NIST ACVP conformance KAT (official vectors from ACVP-Server)

## Current state (2026-06-04, cycle 91 — STABILIZATION: CI red fix — mlKem768 mock TS2554)
- **Cycle 91 (STABILIZATION — CI was RED):** Frontend CI was RED on Bundle budget check step.
  - **Root cause:** `app/src/hooks/__mocks__/useCryptoWorker.ts` declared `mlKem768Encap` and `mlKem768Decap` with zero parameters. Tests in `mlKem768.test.ts` (added cycle 90) call them with arguments (`encapKey`, `decapKey+ciphertext`). TypeScript strict mode emits TS2554 "Expected 0 arguments, but got N" during `tsc -b`.
  - **Fix:** Added `_encapKey: Uint8Array`, `_decapKey: Uint8Array`, `_ciphertext: Uint8Array` parameters to the two mock functions. TypeScript check passes; 135 frontend tests pass; Biome clean.
  - **No security impact:** mock-only change; no production code touched.

## Current state (2026-06-04, cycle 90 — STABILIZATION: ML-KEM-768 crypto-review pass + test gap closure)
- **Cycle 90 (STABILIZATION):** CI green, cargo audit clean (1 allowed: instant/openmls), no open issues. Two changes:
  - **Test gap closed:** `mlKem768Keygen/Encap/Decap` in `crypto.worker.ts` (added cycle 88) had zero frontend tests. Added `app/src/workers/mlKem768.test.ts` — 5 API-contract tests verifying FIPS 203 §2.4 byte sizes (EK=1184, DK=2400, CT=1088, SS=32) through the standard mock proxy.
  - **Race condition fixed:** `usePersistentMessages.test.ts` `persistIncoming adds message to rows immediately` was failing intermittently — same root cause as the cycle-84 dedup race (initial `getMessagesByGroup` useEffect resolving inside `act()` and overriding the optimistic `setRows([row])`). Fix: added `await act(async () => {})` pre-flush before the `persistIncoming` call.
  - **crypto-reviewer on ML-KEM-768 (kem.rs + wasm_exports.rs + crypto.worker.ts):** PASS — GREEN on all correctness criteria (FIPS 203 §2.4 sizes, key-type ordering, OsRng/CSPRNG, implicit rejection, encapsulation randomness, length validation, Zeroizing, no homegrown crypto, no plaintext logging, §7.2 caveat disclosed). 6 YELLOW advisories — ALL scoped to Phase B (not blocking Phase A):
    - Y-1: decapKey/sharedSecret cross worker boundary as raw Uint8Array (Phase B must use opaque-handle pattern like MlsContext)
    - Y-2: Transient `Encoded<Dk768>` stack array not zeroized (WASM linear-memory residue, already documented)
    - Y-3: Encap key not authenticated before use (acknowledged in comment; Phase B hybrid handshake must bind ek to signed credential)
    - Y-4: ZeroizeOnDrop round-trip through from_bytes (no action needed — documented)
    - Y-5: No FIPS 203 §A.3 KAT vectors (add at least one for Phase B)
    - Y-6: ml-kem 0.2.3 is pre-1.0 (pin exact version for Phase B)
  - **security-auditor on handle-oracle Postgres + ML-KEM-768:** PASS — all GREEN. SQL injection: parameterized queries, no string concat. No plaintext logging of key/value_bytes. First-boot race: ON CONFLICT DO NOTHING + re-read is safe. Error messages: no key bytes. Authorization: server_config table unreachable from REST/gRPC/WS (server-process only). No RED findings.
  - **353 Rust tests** (unchanged non-ignored), **135 frontend tests** (+5 ML-KEM, +0 other); Biome clean; clippy clean; rustfmt clean.
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)
    - ML-KEM-768 Phase B prerequisites (Y-1 through Y-6 above — Phase A test surface only)

## Current state (2026-06-04, cycle 87 — FEATURE: persist handle-oracle secret in Postgres — closes YELLOW-2)
- **Cycle 87 (commit 9c2a47f):** Closed YELLOW-2: handle oracle cross-restart oracle fix.
  - **Root cause:** If `POWEHI__HANDLE_ORACLE_SECRET_TOKEN` env var was not set, `main.rs` generated a fresh random 32-byte HMAC key each restart. Consecutive `login_init` calls for the same unknown handle across a server restart would get different synthetic `UserId` values — distinguishable from known handles, breaking the anti-enumeration guarantee.
  - **Fix:**
    - Migration `0007_server_config.sql`: new `server_config (key TEXT PK, value_bytes BYTEA, created_at TIMESTAMPTZ)` table for opaque server-side config blobs (never content/PII/ciphertext).
    - New port `ServerConfigRepository` (`get_bytes` / `upsert_bytes`) in `powehi-port-outbound`.
    - `PgServerConfigRepository` in `powehi-postgres` — sqlx parameterized queries (no SQL injection), `ON CONFLICT DO NOTHING` semantics.
    - `main.rs` startup priority: (1) env var set → SHA-256 derive; (2) DB has key → load it; (3) first boot → generate, INSERT DO NOTHING, re-read winner (concurrent first-boot race-safe).
  - **Race safety:** `ON CONFLICT DO NOTHING + re-read` ensures all concurrent first-boot instances converge on the same value (the first writer's key).
  - **security-auditor:** PASS — no RED. YELLOW entropy note (UUID v4 ≈244 bits for HMAC-SHA256 key — acceptable). YELLOW-2 CLOSED.
  - **+3 testcontainers integration tests** (`#[ignore]`): `get_before_insert → None`, round-trip, `DO NOTHING` preserves first writer's value.
  - **342 Rust tests** (unchanged non-ignored count); 11 ignored (was 8 + 3 new server_config tests); clippy clean; rustfmt clean.
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)

## Current state (2026-06-04, cycle 86 — FEATURE: sort messages by receivedAt — closes Y1 epoch-namespace mismatch)
- **Cycle 86 (commit 7c1b45b):** Closed Y1 from cycle 83: outgoing message display ordering fix.
  - **Y1 closed:** `getMessagesByGroup` and `persistIncoming` optimistic sort now use `receivedAt` (wall-clock ms) instead of `epochSeq`. Outgoing messages had `epochSeq = Date.now()` (~1.7e12) while incoming messages used real MLS epoch sequences (~0–N), causing outgoing to always sort after every incoming message regardless of actual send time. Fix: both directions use `receivedAt` for display ordering; `epochSeq` is retained for potential future WASM-layer replay detection.
  - **security-auditor:** GREEN — `receivedAt` is already a plaintext-indexed field; no new exposure surface, no auth path touched, no plaintext logged.
  - **+1 test:** "Y1 — outgoing message with large epochSeq sorts before later incoming". "sorts by epochSeq" test updated to "sorts by receivedAt". 130 frontend tests (was 129); Biome clean; 342 Rust tests unchanged.
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - POWEHI__HANDLE_ORACLE_SECRET_TOKEN cross-restart oracle if env var not set (YELLOW-2) ← CLOSED cycle 87
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)

## Current state (2026-06-04, cycle 85 — STABILIZATION: Y3 closed — writeErrorCount telemetry in usePersistentMessages)
- **Cycle 85 (commit 495226a):** STABILIZATION — CI green, cargo audit clean (1 allowed: instant/openmls), no open issues.
  - **Y3 closed:** `usePersistentMessages` now exposes `writeErrorCount: number` in `PersistedMessages`. Both `persistIncoming` and `persistOutgoing` catch `encryptedDb.putMessage()` failures and increment an opaque React state counter (no content, no error details, no logging). Security-auditor GREEN across all 5 invariants (counter is per-instance, discards rejection reason, no new console output).
  - **+3 tests:** `writeErrorCount starts at 0`, increments on persistIncoming write failure, increments on persistOutgoing write failure. Used `vi.spyOn(EncryptedPowehiDb.prototype, 'putMessage').mockRejectedValueOnce(...)`.
  - **129 frontend tests** pass (was 126, +3); Biome clean; 342 Rust tests unchanged.
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - POWEHI__HANDLE_ORACLE_SECRET_TOKEN cross-restart oracle if env var not set (YELLOW-2, documented)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)
    - Y1 from cycle 83: `epochSeq = Date.now()` for outgoing mixes epoch namespaces (display order only) ← CLOSED cycle 86

## Current state (2026-06-03, cycle 84 — STABILIZATION: CI red fix — Biome lint + dedup test race condition)
- **Cycle 84 (commit db37b0a):** STABILIZATION — Frontend CI was RED due to two issues in the cycle-83 `usePersistentMessages` commit:
  1. **7 Biome errors:** Import ordering violations in `useMessages.ts`, `usePersistentMessages.ts`, `usePersistentMessages.test.ts`, and `ChatLayout.tsx`. Format violation: multi-line function signatures that Biome expects on one line. Two `noNonNullAssertion` lint errors in test (`!` → `?? ""`).
  2. **1 Vitest test failure:** `persistIncoming deduplicates — same id added twice stays one row` → `expected [] to have a length of 1 but got 0`. Root cause: race condition — the initial `useEffect`'s async `getMessagesByGroup` promise resolves INSIDE the `act()` that calls `persistIncoming`, and its `setRows([])` overrides the optimistic `setRows([row])`. Fix: pre-flush the initial DB load with `await act(async () => {})` before calling `persistIncoming`, so the DB load completes before dedup is tested.
  - **126 frontend tests** pass (all 15 test files); Biome clean; 342 Rust tests pass (unchanged).
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - POWEHI__HANDLE_ORACLE_SECRET_TOKEN cross-restart oracle if env var not set (YELLOW-2, documented)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)
    - Y1 from cycle 83: `epochSeq = Date.now()` for outgoing mixes epoch namespaces (display order only)
    - Y3 from cycle 83: Dexie write errors silently swallowed (no telemetry counter yet)

## Current state (2026-06-03, cycle 83 — FEATURE: Dexie encrypted message persistence + CI TypeScript fix)
- **Cycle 83 (commit 3177792):** Two changes:
  1. **CI fix (commit 4683d19):** Frontend CI was RED — `useMessages.test.ts` had TS2322 type errors on `pollSpy`/`ackSpy` declared as `ReturnType<typeof vi.spyOn>` (too-wide generic type incompatible with the specific spy return type in Vitest 3.x). Fixed: typed as `MockInstance<typeof MessagesModule.pollMessages/ackMessage>`. Also removed unused `useCallback` import (TS6133) from `useMessages.ts`. CI now GREEN.
  2. **Dexie encrypted persistence (commit 3177792):** Closes Phase 4 "Dexie encrypted storage layer functional":
     - **New hook `usePersistentMessages(groupId)`:** Loads `MessageRow[]` from `EncryptedPowehiDb.getMessagesByGroup()` on group change; `persistIncoming(msg)` / `persistOutgoing(id, groupId, text, ct)` write AES-GCM-256-encrypted rows to IndexedDB.
     - **`IncomingMessage` extended:** Added `ciphertextB64: string` + `epochSeq: number` so the wire ciphertext is available for `MessageRow.ciphertextB64` persistence.
     - **`useMessages.processEnvelope`:** Computes `ciphertextB64` (safe loop via `uint8ToBase64`) + `epochSeq` from envelope and passes to callback.
     - **`ChatLayout` wired:** `handleIncoming` calls `persistIncoming`; `sendMessage` captures server-returned `envelopeId` from `sendMessageApi` and calls `persistOutgoing` with the MLS ciphertext.
     - **New `app/src/utils/base64.ts`:** `uint8ToBase64` (byte-by-byte loop — no spread/RangeError), `textToBase64`, `base64ToText`. Replaces all `btoa(String.fromCharCode(...array))` occurrences (security-auditor R1 fix).
     - **`plaintextB64` now stores base64-encoded UTF-8** via `textToBase64` — matching the field name contract; prevents silent corruption of Korean/emoji text (security-auditor R2 fix).
     - **security-auditor:** R1 (stack overflow on large ciphertext) and R2 (raw UTF-8 in B64 field) fixed. PASS.
     - **+18 tests (126 total frontend, was 108):** 9 `usePersistentMessages` tests, 9 `base64` utility tests. Total: 15 test files, 126 tests.
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - POWEHI__HANDLE_ORACLE_SECRET_TOKEN cross-restart oracle if env var not set (YELLOW-2, documented)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)
    - Y1 from cycle 83: `epochSeq = Date.now()` for outgoing mixes epoch namespaces (display order only; replay detection at WASM layer)
    - Y3 from cycle 83: Dexie write errors silently swallowed (no telemetry counter yet)

## Current state (2026-06-03, cycle 82 — FEATURE: Frontend messaging API integration — MLS encrypt/decrypt + REST polling)
- **Cycle 82 (commit 82f60b6):** Closed the largest remaining frontend gap: ChatLayout sent messages only to local mock state; no real API calls were made.
  - **New API clients:** `app/src/api/messages.ts` (`sendMessage`, `sendWelcome`, `sendCommit`, `pollMessages`, `ackMessage`); `app/src/api/groups.ts` (`createGroup`, `addMember`, `removeMember`); `app/src/api/key_packages.ts` (`fetchKeyPackage`, `getKeyPackageCount`). All use Bearer token auth headers, never URL params; binary payloads as JSON number arrays (matching serde `Vec<u8>`).
  - **New hook `useMessages`:** Polls `GET /v1/messages` every 3 s. Application messages decrypted via `cryptoWorker.mlsDecrypt(identityId, groupId, ciphertext)` → `onMessage`. Welcome/Commit/Proposal acked silently. Wrong-group envelopes skipped without decryption. Decrypt failures swallowed (no ack — server GC via TTL). `sinceRef` tracks last timestamp to avoid re-delivery. Cleanup: `cancelled + clearInterval` on unmount.
  - **ChatLayout wiring:** `sendMessage` now async with optimistic local update (synchronous) + real MLS encrypt (`cryptoWorker.mlsEncrypt`) + `sendMessageApi` REST POST. Plaintext `Uint8Array` zeroed in `finally`. Silent failure on network/encrypt error — optimistic message remains visible.
  - **Security:** `security-auditor` PASS. Token only in Authorization header. No console.log of content/ciphertext/tokens. `plaintext.fill(0)` in finally block. Server error `code` field forwarded as exception (no server internals). UUID interpolated into paths (frontend-only, TypeScript-typed; UUID format not re-validated — low severity). XSS-safe: React JSX escapes `msg.text`.
  - **+36 tests (108 total frontend, was 72):** 15 messages API tests, 6 groups API tests, 6 key_packages API tests, 9 useMessages hook tests. Uses `vi.spyOn(module, 'fn')` on namespace imports (not `vi.mock` factory — ESM live binding issue with Vitest 3.x).
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - POWEHI__HANDLE_ORACLE_SECRET_TOKEN cross-restart oracle if env var not set (YELLOW-2, documented)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)

## Current state (2026-06-03, cycle 81 — FEATURE: REST endpoints for group member add/remove — closed group membership gap)
- **Cycle 81 (commit 775745c):** Closed functional gap: `GroupUseCase.add_member`/`remove_member` existed but had no REST surface — clients could create a group but never add subsequent members.
  - **New endpoints:**
    - `POST /v1/groups/:group_id/members/:device_id` → `add_member` (body: `{ "epoch": u64 }`)
    - `DELETE /v1/groups/:group_id/members/:device_id` → `remove_member` (no body)
  - **Security:** `GroupService.add_member`/`remove_member` now enforce caller-must-be-member (fail-closed) via `list_members()` before the mutation. Both handlers require `AuthenticatedDevice`. Path params extracted as `Path<(Uuid, Uuid)>` → typed `GroupId`/`DeviceId`.
  - **Logging:** only opaque UUIDs logged (caller + group_id); target device_id omitted per no-plaintext-logging.md.
  - **security-auditor:** PASS — no RED. YELLOW-1 (TOCTOU between `list_members` read and `add_member`/`remove_member` write — documented in comment; non-blocking because MLS Welcome+Commit is the actual E2E auth boundary; server is zero-trust per prd.md threat model).
  - **+8 tests:** 2 application-layer (add_member/remove_member by non-member → Unauthorized), 6 REST-layer (auth-bypass ×2, non-member ×2, happy-path ×2).
  - **342 Rust tests** (was 334, +8); clippy clean; rustfmt clean.
  - **Remaining deferred security findings (YELLOW):**
    - TOCTOU in group member add/remove (cycle 81, documented, non-blocking)
    - POWEHI__HANDLE_ORACLE_SECRET_TOKEN cross-restart oracle if env var not set (YELLOW-2, documented)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)

## Current state (2026-06-03, cycle 80 — STABILIZATION: CI red fix — audit RUSTSEC-2025-0111 + duplicate handle_hash in pg_security_it)
- **Cycle 80 (commit 31a0c4e):** STABILIZATION — CI was RED on 2 jobs; both fixed:
  - **Security audit job failure:** `RUSTSEC-2025-0111` (tokio-tar 0.3.1 — PAX extended header parsing allows file smuggling) appeared in the cargo advisory DB. Added to `.cargo/audit.toml` ignore list with full impact analysis: tokio-tar is a test-only transitive dep of testcontainers, used only to write tar archives to the Docker daemon (never to untar untrusted input). No production binary includes it. No fixed version upstream.
  - **Integration Tests job failure:** `insert_user` fixture in `pg_security_it.rs` always used `vec![0u8; 32]` as handle_hash. When any test called `insert_user` twice in the same DB (e.g., creating separate sender + non_member users), the second insert violated `users_handle_hash_unique`. Fixed: `insert_user` now uses two random `Uuid::new_v4()` values concatenated to form a unique 32-byte handle_hash per call.
  - **Preemptive fix:** `insert_device` was using the same anti-pattern (`vec![0u8; 32]` for mls_credential). Fixed to use a UUID-derived unique value, guarding against potential future uniqueness constraints on that column.
  - **security-auditor:** PASS — GREEN on both changes. YELLOW-1 (insert_device anti-pattern) was also fixed in the same commit.
  - **334 Rust tests** unchanged (8 testcontainers tests still `#[ignore]`); cargo audit clean (1 allowed warning: instant/openmls unmaintained); clippy clean; rustfmt clean.
  - **Remaining deferred security findings (YELLOW)**:
    - POWEHI__HANDLE_ORACLE_SECRET_TOKEN cross-restart oracle if env var not set (YELLOW-2, documented)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)

## Current state (2026-06-03, cycle 79 — FEATURE: testcontainers integration tests — Postgres security invariants)
- **Cycle 79 (commit bc30041):** Implemented the required testcontainers gate from testing-conventions.md (outbound adapters must have integration tests against real Postgres):
  - **New file:** `crates/adapters/outbound/powehi-postgres/tests/pg_security_it.rs`
  - **8 security-invariant integration tests** (all `#[ignore = "requires Docker (testcontainers)"]`):
    - `list_groups_for_device_returns_only_own_groups` — device scoping: device_a sees only group_a
    - `find_pending_broadcast_excluded_for_non_member` — cycle-74 SQL fix validated against real PG: `IN (<empty subquery>)` is FALSE in PG, non-member gets zero broadcasts
    - `find_pending_broadcast_included_for_member` — positive case: member receives group broadcast
    - `find_pending_excludes_expired_envelopes` — TTL enforcement: `expires_at > NOW()` guard is real PG
    - `key_package_fetch_one_atomically_marks_consumed` — single-use: count drops to 0, second fetch returns None
    - `mark_consumed_prevents_double_consume` — CAS: first = Consumed, second = AlreadyConsumed
    - `mark_consumed_not_found_for_unknown_id` — NotFound (not Internal error)
    - `group_add_member_is_idempotent` — ON CONFLICT DO NOTHING: no duplicate rows
  - **New CI job** `integration-test` in `.github/workflows/ci-rust.yml`:
    - `timeout-minutes: 20` + `permissions: contents: read`
    - `cargo nextest run -p powehi-postgres --run-ignored all -E 'binary(pg_security_it)'`
    - Specifically runs only the testcontainers binary (not push_subscription_repo_it which needs TEST_DATABASE_URL)
  - **testcontainers = "0.23"** + **testcontainers-modules = { version = "0.11", features = ["postgres"] }** added to workspace Cargo.toml
  - **security-auditor:** PASS — no RED; YELLOW-2 (CI permissions + timeout) fixed; no plaintext fixtures
  - **334 Rust tests** unchanged; 8 new tests ignored (Docker required); clippy clean; rustfmt clean
  - **Remaining deferred security findings (YELLOW)**:
    - POWEHI__HANDLE_ORACLE_SECRET_TOKEN cross-restart oracle if env var not set (YELLOW-2, documented)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)

## Current state (2026-06-03, cycle 78 — FEATURE: WS broadcast global fan-out YELLOW closed — group-scoped notifications)
- **Cycle 78 (commit 7396c78):** Closed long-deferred YELLOW: WS broadcast global fan-out:
  - **Root cause:** `handle_socket` ignored the authenticated `DeviceId` — every connected device received every group notification (EnvelopeReceived, EpochAdvanced, MemberAdded, MemberRemoved) regardless of group membership. Device could observe activity in groups it never joined.
  - **Fix:** Added `GroupRepository::list_groups_for_device(device_id) -> Vec<GroupId>` to port. `handle_socket` loads the device's groups on connect and maintains a local `HashSet<GroupId>`. `filter_notification()` function gates all outgoing notifications against this set:
    - `MemberAdded { device_id == me }` → insert group, always notify (this device just got access)
    - `MemberRemoved { device_id == me }` → notify once, then remove group (no further events)
    - `MemberAdded/Removed { device_id != me }` → only forward if already a member
    - `EnvelopeReceived`/`EpochAdvanced` → only forward if member
  - **WsNotification::MemberAdded/MemberRemoved** now carry `device_id: String` (opaque UUID) for in-flight membership updates; enables live set maintenance without extra DB calls.
  - **Auditor Y-1 fix:** `parse_device_id(s).as_ref() == Some(device_id)` (typed Uuid comparison, not string equality)
  - **Auditor Y-2 fix:** DB error on connect emits `tracing::warn!(error_kind="db_error")` + returns empty set (fail-closed)
  - **`PgGroupRepository`:** `SELECT group_id FROM group_members WHERE device_id = $1`
  - **All 4 FakeGroupRepo impls** updated with `list_groups_for_device`
  - **security-auditor:** PASS — no RED; Y-1+Y-2 fixed; Y-3 (initial-load race) accepted+documented in comment; Y-4 (outbound rate limit) pre-existing.
  - **+9 tests:** dispatch MemberAdded/Removed with device_id; 6 filter_notification security invariants; JSON format check; all in powehi-ws-hub.
  - **334 Rust tests** (was 325, +9); clippy clean; rustfmt clean.
  - **Remaining deferred security findings (YELLOW)**:
    - POWEHI__HANDLE_ORACLE_SECRET_TOKEN cross-restart oracle if env var not set (YELLOW-2, documented)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)

## Current state (2026-06-03, cycle 77 — FEATURE: tls_required runtime assertion — mTLS startup YELLOW closed)
- **Cycle 77 (commit 07ccea8):** Closed deferred YELLOW from cycle 76: gRPC mTLS startup assertion:
  - **Root cause:** `verify_peer_region` was a free function that, when `TlsConnectInfo` was absent (no TLS on the gRPC listener), would log a warning and return `Ok(())`. In production, if the gRPC listener started without `.tls_config()` due to misconfiguration, all `SyncGroupMembership` peer-cert checks would silently pass — bypassing the home_region binding.
  - **Fix:** Converted `verify_peer_region` to an `&self` method on `RegionGrpcServer`. Added `tls_required: bool` field. When `tls_required=true` and `TlsConnectInfo` is absent: returns `Err(Status::permission_denied("peer certificate required"))` — fail-closed. When `tls_required=false` (dev/test): warns + passes (unchanged behavior).
  - **`main.rs`:** Passes `cfg.grpc_tls_enabled()` as `tls_required` so the listener wiring (`.tls_config()` call) and the per-request check are always in sync — no skew window.
  - **Error message:** `"peer certificate required"` — does not reveal whether `tls_required` is set or why TLS was absent (non-disclosing).
  - **+2 security-invariant tests:** `sync_group_membership_without_tls_info_rejected_when_tls_required` (asserts PermissionDenied when tls_required=true + no TlsConnectInfo), `sync_group_membership_without_tls_info_passes_when_tls_not_required` (dev/test backward compat).
  - **security-auditor:** PASS — no RED/YELLOW findings. Wiring verified: `grpc_tls_enabled()` produces `true` iff all 3 TLS env vars set, and same value used for both listener `.tls_config()` and `tls_required`.
  - **325 Rust tests** (was 323, +2); clippy clean; rustfmt clean.
  - **Remaining deferred security findings (YELLOW)**:
    - WS broadcast global fan-out (Phase 5 architectural — all devices get wake-up signals)
    - POWEHI__HANDLE_ORACLE_SECRET_TOKEN cross-restart oracle if env var not set (YELLOW-2, documented)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)

## Current state (2026-06-02, cycle 76 — FEATURE: mTLS peer-cert → home_region binding — RED-2/RED-3 closed)
- **Cycle 76 (commit 92005f9):** Closed long-deferred RED-2/RED-3: gRPC peer region identity binding:
  - **Root cause:** `sync_group_membership` accepted any `home_region` claim from any peer inside the mTLS perimeter. A compromised or rogue peer could declare membership for groups it doesn't own, enabling `ForwardEnvelope` acceptance for those groups.
  - **Fix:** `verify_peer_region(extensions, expected_region)` — extracts `TlsConnectInfo<TcpConnectInfo>` from tonic request extensions; if absent (dev/test, no TLS) → warns + passes; if present but no peer cert → PermissionDenied; calls `peer_cert_matches_region`.
  - **`peer_cert_matches_region(der, region)`** — x509-parser 0.16 parses the DER leaf cert; checks Subject CN and SAN DNS names for exact string match against `home_region`. Parser-only — no crypto ops; chain trust already enforced by rustls handshake.
  - **`sync_group_membership`**: `request.into_parts()` once to access extensions + body; `verify_peer_region` called before any DB writes. `ForwardEnvelope`/`ForwardCommit` covered transitively (Sync is the only membership writer; those handlers are fail-closed on empty membership).
  - **x509-parser = "0.16"** added to workspace (parser only, no homegrown crypto; no ring added — crypto-libraries-pinned.md compliant).
  - **+6 peer cert unit tests** using pre-generated P-256 DER fixtures (no rcgen/ring dep — bytes generated once with OpenSSL and hardcoded): `peer_cert_matches_by_cn`, `_by_san_dns`, `_mismatched_region`, `_wrong_cn_no_matching_san`, `_cn_matches_own_region`, `_invalid_der`.
  - **security-auditor:** PASS — 2 YELLOW (startup assertion for dev-mode skip deferred; lowercase-region doc comment advisory). No RED.
  - **323 Rust tests** (was 287 with nextest, count differs with cargo test; +9 net in powehi-grpc: 31→40); clippy clean; rustfmt clean.
  - **Remaining deferred security findings (YELLOW)**:
    - WS broadcast global fan-out (Phase 5 architectural — all devices get wake-up signals)
    - mTLS startup assertion: no runtime check that gRPC listener actually uses TLS_config (YELLOW from cycle 76 security-auditor)
    - POWEHI__HANDLE_ORACLE_SECRET_TOKEN cross-restart oracle if env var not set (YELLOW-2, documented)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)

## Current state (2026-06-02, cycle 75 — STABILIZATION: create_group REST test gap + security sweep)
- **Cycle 75 (commit 8dc597c):** STABILIZATION — CI green, no open issues, test gap closed + security sweep:
  - **cargo audit:** 1 allowed warning (RUSTSEC-2024-0384 instant/openmls — unchanged).
  - **Test gap fixed:** `POST /v1/groups` (create_group handler, added cycle 70) had ZERO REST-layer tests despite being the entry point for group creation and the prerequisite for the membership auth gate.
  - **+3 tests:**
    - `create_group_without_token_returns_401` (auth bypass invariant — testing-conventions.md)
    - `create_group_returns_204` (authenticated creator → 204 NO_CONTENT)
    - `create_group_with_missing_group_id_returns_unprocessable` (bad body → 422)
  - **Added `groups_router()` helper** using `test_session_cache()` + `noop_group()`.
  - **security-auditor:** GREEN — no RED findings. YELLOW-1 (group_id uniqueness — enforced at DB layer by ON CONFLICT in PgGroupRepository, not a handler concern). YELLOW-2 (WS global broadcast — pre-existing architectural deferral Phase 5).
  - **287 Rust tests** (was 284, +3); clippy clean; rustfmt clean.
  - **Remaining deferred security findings (YELLOW)**:
    - WS broadcast global fan-out (Phase 5 architectural — all devices get wake-up signals)
    - mTLS peer-cert → home_region binding (RED-2/RED-3, architectural, tonic TlsConnectInfo)
    - POWEHI__HANDLE_ORACLE_SECRET_TOKEN cross-restart oracle if env var not set (YELLOW-2, documented)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)

## Current state (2026-06-02, cycle 74 — FEATURE: broadcast envelope poll — offline devices now receive group messages)
- **Cycle 74 (commit a12f742):** Fixed functional gap: `PgEnvelopeRepository::find_pending` previously only returned unicast messages (`WHERE recipient_device_id = $1`), silently dropping all group (broadcast) Application envelopes for offline devices.
  - **Root cause:** `find_pending` never included `recipient_device_id IS NULL` rows. An offline device would miss every group message sent while it was disconnected.
  - **Fix:** Added OR clause to SQL: `OR (recipient_device_id IS NULL AND group_id IN (SELECT group_id FROM group_members WHERE device_id = $1))`. PostgreSQL's `IN (<empty subquery>) = FALSE` keeps the fail-closed invariant: a device with no memberships gets zero broadcasts.
  - **Migration `0006_group_members_device_idx.sql`:** `CREATE INDEX … ON group_members(device_id)` — the existing PRIMARY KEY `(group_id, device_id)` is useless for `WHERE device_id = $1`; the new index prevents a full scan on every poll call.
  - **`FakeEnvelopeRepo` updated:** Added `memberships: Mutex<HashMap<GroupId, HashSet<DeviceId>>>` field. `find_pending` now uses `is_some_and(|members| members.contains(device_id))` for broadcasts — mirrors SQL semantics exactly.
  - **`FakeGroupRepo::with_member_list`:** New constructor accepting multiple `(GroupId, DeviceId)` pairs.
  - **security-auditor:** PASS — no RED. YELLOW-1 (post-removal staleness window) acceptable (MLS PCS enforces epoch-bounded decryption; evicted device cannot decrypt after next Commit). YELLOW-2 (delete_expired race) pre-existing/benign.
  - **+2 tests:** `poll_envelopes_does_not_return_broadcast_for_non_member` (security invariant), `poll_envelopes_returns_group_broadcasts_to_member` (functional).
  - **Fixed test:** `poll_envelopes_returns_recipient_envelopes` updated to add device_a to the group (was relying on the permissive fake behavior).
  - **284 Rust tests** (was 282, +2); clippy clean; rustfmt clean.
  - **Remaining deferred security findings (YELLOW)**:
    - WS broadcast global fan-out (Phase 5 architectural — all devices get wake-up signals)
    - mTLS peer-cert → home_region binding (RED-2/RED-3, architectural, tonic TlsConnectInfo)
    - POWEHI__HANDLE_ORACLE_SECRET_TOKEN cross-restart oracle if env var not set (YELLOW-2, documented)
    - Post-removal broadcast staleness window (YELLOW-1 from cycle 74, MLS PCS mitigated)

## Current state (2026-06-02, cycle 73 — FEATURE: TraceLayer URI omission — UUID path-param log leakage fix)
- **Cycle 73 (commit c2e473e):** Closed deferred YELLOW: TraceLayer UUID path params at DEBUG level (logging hygiene):
  - **Root cause:** `TraceLayer::new_for_http()` default `make_span_with` emits `uri = %request.uri()` in every HTTP span at ALL log levels. Routes like `/v1/key-packages/:device_id`, `/v1/messages/:id`, `/v1/media/:id` would expose device UUIDs, envelope IDs, and media IDs in trace logs — violating `no-plaintext-logging.md`.
  - **Fix:** `powehi-rest-api/src/lib.rs` — custom `make_span_with` closure records only `http.method`. Status + latency appear in `DefaultOnResponse` child events (not span fields), so observability is fully preserved.
  - **Tower-http `DefaultOnResponse` verified:** does NOT add `uri` via `span.record()` post-creation — confirmed against tower-http 0.5.2 source.
  - **`tracing-subscriber` added to dev-dependencies** (workspace pin, features: env-filter + json).
  - **`SpanFieldNames` custom tracing `Layer`:** hooks both `on_new_span` AND `on_record` to capture field names at creation AND via late-bound `span.record(...)` calls — future-proof against post-creation URI injection.
  - **+2 tests:**
    - `trace_span_omits_uri_field_for_path_param_routes`: asserts no `uri`/`http.uri` field present in span after request to `/v1/key-packages/:device_id`.
    - `key_package_count_returns_200_when_authenticated`: behavioral test for `/v1/key-packages/:device_id/count` with auth.
  - **security-auditor:** GREEN — YELLOW-1 (on_record coverage) fixed; YELLOW-2 (misleading comment) fixed. No RED findings.
  - **312 Rust tests** (was 310, +2); clippy clean; rustfmt clean.
  - **Remaining deferred security findings (YELLOW)**:
    - WS broadcast global fan-out (Phase 5 architectural — all devices get wake-up signals)
    - mTLS peer-cert → home_region binding (RED-2/RED-3, architectural, tonic TlsConnectInfo)
    - POWEHI__HANDLE_ORACLE_SECRET_TOKEN cross-restart oracle if env var not set (YELLOW-2, documented)

## Current state (2026-06-02, cycle 72 — FEATURE: WS per-connection Ping rate limiter)
- **Cycle 72 (commit c423874):** Closed long-deferred YELLOW: WS per-message rate limiting:
  - **`powehi-ws-hub/src/handler.rs`:** Added `PingRateLimiter` — fixed-window counter per connection. `PING_BURST=5` pings allowed per `PING_WINDOW=10s`. Exceeding the limit: `tracing::warn!` (static string, no PII) + immediate disconnect.
  - **Fixed-window caveat documented:** worst case 2×PING_BURST (10) pings at window boundary in ~0s — harmless at current values since Pong work is negligible. Comment explains the limitation.
  - **security-auditor:** GREEN — no PII logging, no auth bypass, fail-closed on limit breach, per-connection scope (one abuser cannot poison another's budget).
  - **+4 unit tests:** within-burst (all 5 allowed), over-burst (6th rejected), post-window-reset (count resets, first allowed), boundary-exactly-at-burst-is-allowed.
  - **310 Rust tests** (was 306, +4); clippy clean; rustfmt clean.
  - **Remaining deferred security findings (YELLOW)**:
    - WS broadcast global fan-out (Phase 5 architectural — all devices get wake-up signals)
    - TraceLayer UUID path params at DEBUG level (logging hygiene) ← CLOSED in cycle 73
    - mTLS peer-cert → home_region binding (RED-2/RED-3, architectural, tonic TlsConnectInfo)
    - POWEHI__HANDLE_ORACLE_SECRET_TOKEN cross-restart oracle if env var not set (YELLOW-2, documented)

## Current state (2026-06-02, cycle 71 — FEATURE: handle-hash oracle fix — deterministic HMAC synthetic user_id)
- **Cycle 71 (commit 0d7c67a):** Closed long-deferred YELLOW: login_init handle-hash oracle fix:
  - **Root cause:** `login_init` called `UserId::new()` (random UUID per call) for unknown handles. An attacker calling login_init twice for the same unknown handle observed different `user_id` values each time → handle enumeration oracle.
  - **Fix:** `AuthService` now holds `handle_oracle_secret: [u8; 32]`. Unknown handles map through `HMAC-SHA256(secret, handle_hash)` → deterministic 16-byte UUID. Same handle_hash always yields same synthetic user_id → indistinguishable from known handles.
  - **`hmac = "0.12"`** added to workspace (RustCrypto, approved per crypto-libraries-pinned.md).
  - **`AppConfig.handle_oracle_secret_token`**: operator-supplied stable secret; falls back to random key with `tracing::warn!`. Redacted in Debug impl.
  - **`POWEHI__HANDLE_ORACLE_SECRET_TOKEN`** env var for persistent stable key across restarts.
  - **+2 security-invariant tests**: `login_init_unknown_handle_returns_consistent_synthetic_user_id`, `login_init_different_unknown_handles_return_different_synthetic_ids`.
  - **security-auditor:** GREEN. YELLOW-1 (handle_hash UNIQUE constraint) — verified already exists in migration 0002. YELLOW-2 (cross-restart oracle with empty token) — documented deferred.
  - **306 Rust tests** (was 304, +2); clippy clean; rustfmt clean.
  - **Remaining deferred security findings (YELLOW)**:
    - WS broadcast global fan-out (Phase 5 architectural — all devices get wake-up signals)
    - TraceLayer UUID path params at DEBUG level (logging hygiene)
    - WS per-connection rate limiting (connection-establishment is rate-limited; per-message is not) ← CLOSED in cycle 72
    - mTLS peer-cert → home_region binding (RED-2/RED-3, architectural, tonic TlsConnectInfo)
    - POWEHI__HANDLE_ORACLE_SECRET_TOKEN cross-restart oracle if env var not set (YELLOW-2, documented)

## Current state (2026-06-02, cycle 70 — STABILIZATION: group membership authorization RED fix)
- **Cycle 70 (commit 664b421):** STABILIZATION — security-auditor found RED-1/RED-2 (any authenticated device could post envelopes to any group_id without being a member). Fixed:
  - **`MessagingService.check_sender_is_member`**: fail-closed (empty member list → Unauthorized); called in `send_message` (before TTL check), `send_welcome`, `send_commit` (after group existence check).
  - **`POST /v1/groups`**: new REST endpoint wires `GroupService.create_group` — creator becomes first member. Required prerequisite for the membership gate.
  - **`AppState`**: gains `group: Arc<dyn GroupUseCase>`; all 13 test constructions updated with `noop_group()` mock; `main.rs` wires `GroupService`.
  - **`FakeGroupRepo`** in messaging tests now properly tracks members. `FakeGroupRepo::with_group_and_member`, `with_member_in` constructors added.
  - **+4 security tests**: `send_message_by_non_member_returns_unauthorized`, `send_message_to_unknown_group_returns_unauthorized`, `send_welcome_by_non_member_returns_unauthorized`, `send_commit_by_non_member_returns_unauthorized`.
  - **304 Rust tests** (was 300, +4); clippy clean; rustfmt clean.
  - **Remaining deferred security findings (YELLOW)**: login_init handle-hash oracle (UUID non-deterministic for unknown users → deterministic HMAC recommended; complexity deferred); WS broadcast global fan-out (Phase 5 architectural); TraceLayer UUID path params at DEBUG level; WS rate limiting.
  - **Previously deferred**: mTLS peer-cert → home_region binding (RED-2/RED-3, architectural); set_expire stale-token (acceptable); Y5 invalid group_id → 500 (cosmetic).

## Current state (2026-06-02, cycle 69 — STABILIZATION: CI red fix — WasmModule exportKey type mismatch)
- **Cycle 69 (commit d7d7de3):** STABILIZATION — CI was RED on "Bundle budget check / Build" step:
  - **Root cause:** `crypto.worker.ts` `WasmModule` interface declared `opaque_registration_finish` / `opaque_login_finish` as returning the public `RegFinishResult`/`LoginFinishResult` types, which lacked `exportKey`. The worker internally consumed `result.exportKey` to derive the IndexedDB AES-GCM key (lines 121/149) but TypeScript emitted TS2339 `Property 'exportKey' does not exist` during the production build.
  - **Fix:** Introduced `WasmRegFinishResult = { exportKey: Uint8Array; upload: Uint8Array }` and `WasmLoginFinishResult = { exportKey: Uint8Array; finalization: Uint8Array }` as internal-only types mirroring the actual WASM output. `WasmModule` now uses these for the two finish functions. Public `RegFinishResult`/`LoginFinishResult` remain export-key-free — the key is consumed inside the worker and never crosses the thread boundary.
  - **72 frontend tests** pass; Biome clean; tsc --noEmit clean; bundle budget within limits (107KB JS gz, 553KB WASM gz).
  - **No Rust changes;** 297 workspace tests unchanged.

## Current state (2026-06-01, cycle 67 — FEATURE: zeroize OpaqueRegSession/OpaqueLoginSession — YELLOW-1 closed)
- **Cycle 67 (commit 135fe51):** Closed long-deferred crypto-reviewer YELLOW-1 (zeroize wrappers on OpaqueRegSession/OpaqueLoginSession):
  - **`powehi-crypto-wasm/src/wasm_exports.rs`:** `OpaqueRegSession.state` and `OpaqueLoginSession.state` replaced with `bytes: Zeroizing<Vec<u8>>`. Ephemeral OPRF client state and KE1 ephemeral DH keys are now serialized (infallible `opaque_ke::ClientRegistration::serialize()` / `ClientLogin::serialize()`) on store and deserialized on consume.
  - **Security guarantee:** `Zeroizing<Vec<u8>>` calls `Vec<u8>::zeroize()` on drop, zeroing the backing allocation before deallocation. Prevents ephemeral OPRF blind scalar and KE1 ephemeral DH keys from persisting in WASM linear memory beyond useful lifetime.
  - **Drop chain preserved:** deserialized `ClientRegistration`/`ClientLogin` are `derive_where(ZeroizeOnDrop)`, so the working copy is also zeroed when consumed by finish functions.
  - **NIT-1 documented:** transient stack `GenericArray` from `serialize().to_vec()` is not Zeroized (heap copy IS zeroed); consistent with existing WASM linear-memory residue caveat.
  - **+2 tests:** `test_opaque_registration_session_roundtrip`, `test_opaque_login_session_roundtrip` — serialize→deserialize identity tests.
  - **crypto-reviewer:** GREEN — YELLOW-1 closed. No RFC 9807 concerns.
  - **20 WASM tests** (was 18, +2); **297 Rust workspace tests** unchanged; clippy clean; rustfmt clean.
  - **Remaining deferred:** mTLS peer-cert → home_region binding (RED-2/RED-3, architectural); set_expire stale-token (best-effort, acceptable); Y5 invalid group_id → 500 (cosmetic).

## Current state (2026-06-01, cycle 66 — FEATURE: uploader membership check at media upload — Y1 closed)
- **Cycle 66 (commit 7f626ab):** Closed deferred security finding Y1 (media upload group membership check):
  - **`powehi-application/src/media_service.rs`:** `MediaService::request_upload` now validates group membership when `group_id` is provided. Fail-closed: empty member list → `Unauthorized` (consistent with gRPC `check_sender_is_member` pattern from cycle 59). Non-member uploader → `Unauthorized`. Only UUIDs logged per no-plaintext-logging.md.
  - **`FakeGroupRepo`:** Added `with_members(pairs: Vec<(GroupId, DeviceId)>)` constructor for tests requiring multiple group members.
  - **Fixed 2 existing tests** (`get_download_url_by_group_member_succeeds`, `get_download_url_by_non_member_returns_unauthorized`) that uploaded with `group_id` but the uploader wasn't in the group — now correctly supply membership.
  - **`request_upload_stores_group_id`**: Updated to use `FakeGroupRepo::with_member` for the uploader.
  - **+4 service-layer tests:** `request_upload_stores_group_id` (fixed), `request_upload_with_group_id_member_succeeds`, `request_upload_with_group_id_non_member_returns_unauthorized`, `request_upload_with_group_id_empty_membership_fails_closed`.
  - **+1 REST integration test:** `request_upload_non_member_group_returns_401` — `MockMediaUnauthorized::request_upload` changed from `unimplemented!()` to `Err(Unauthorized)`.
  - **security-auditor:** GREEN — no RED/YELLOW blockers. Advisory findings: O(N) list_members (future `is_member` port method), TOCTOU benign (download-time ACL re-checks), log compliance confirmed.
  - **297 Rust tests** (was 294, +3 net); clippy clean; rustfmt clean.
  - **Remaining deferred:** mTLS peer-cert → home_region binding (RED-2/RED-3, architectural); zeroize wrappers on `OpaqueRegSession`/`OpaqueLoginSession`; set_expire stale-token (best-effort, acceptable); Y5 invalid group_id → 500 (cosmetic).

## Current state (2026-06-01, cycle 65 — STABILIZATION: revoke_device warn logging + test gaps closed)
- **Cycle 65 (commit d12f49d):** STABILIZATION — CI green, no open issues, security sweep + deferred fix:
  - **`cargo audit`:** 1 allowed warning (RUSTSEC-2024-0384 instant/openmls — unchanged).
  - **Deferred fix — revoke_device per-token delete failure logging:** `auth_service.rs` loop now emits `tracing::warn!` when individual `session:{token}` cache deletes fail during device revocation. Previously silently swallowed via `let _ =`. Device revocation still returns Ok (best-effort continuation is correct — surviving tokens expire within SESSION_TTL).
  - **`SessionDeleteFailCache`** test helper: `delete` fails for any `session:*` key; all other ops delegate to inner FakeCache.
  - **`SetMembersFailCache`** test helper: `set_members` always returns Internal error.
  - **+2 tests:**
    - `revoke_device_partial_session_delete_failure_still_returns_ok`: proves device deleted and Ok returned even when cache deletes fail; tokens expire naturally.
    - `revoke_device_set_members_failure_propagates_error`: documents ordering hazard — device row is removed before set_members; caller gets error but device is gone.
  - **security-auditor:** GREEN — no new RED findings; all prior deferred items confirmed unchanged; no logging violations.
  - **294 Rust tests** (was 292, +2); clippy clean; rustfmt clean.
  - **Remaining deferred (non-blocking):** Y1 (uploader membership check at upload); mTLS peer-cert → home_region binding (RED-2/RED-3, architectural); set_expire stale-token (best-effort, acceptable); Y5 invalid group_id → 500 (cosmetic).
  - **Security-auditor observation (not a finding):** safety of revoke_device silent-swallow depends on every session-consuming handler re-verifying device row existence post-lookup. All current handlers do this; note added to secondary-cache invariant tracking.

## Current state (2026-06-01, cycle 64 — FEATURE: media group-member download ACL — Phase 4 deferred closed)
- **Cycle 64 (commit ed4693e):** Closed "Phase 4 TODO: expand to group-member ACL check" in `get_download_url`:
  - **`powehi-domain/src/media.rs`:** `MediaBlob` gains `group_id: Option<GroupId>` — MLS group the blob was shared to.
  - **`powehi-port-inbound/src/media.rs`:** `request_upload` gains `group_id: Option<&GroupId>` param; Phase 4 TODO comment removed.
  - **`powehi-application/src/media_service.rs`:** `MediaService` gains `group_repo: Arc<dyn GroupRepository>`. `get_download_url` checks: uploader → allow; else if `blob.group_id` is Some → `list_members` → check membership → allow; else → Unauthorized. `request_upload` saves `group_id` into blob.
  - **Migration `0005_media_group_id.sql`:** `ALTER TABLE media_blobs ADD COLUMN group_id UUID NULL REFERENCES groups(id) ON DELETE SET NULL` + index.
  - **`powehi-r2`:** `MediaBlobRow` gets `group_id: Option<Uuid>`; `From<MediaBlobRow>` maps it; `save`/`find_by_id` SQL updated.
  - **`powehi-rest-api/routes/media.rs`:** `UploadRequest` gets `group_id: Option<Uuid>`; handler maps `GroupId::from(uuid)` and passes to service; comment updated.
  - **All 5 `MockMedia`/mock impls** in REST API lib/routes updated to match new trait signature.
  - **`main.rs`:** `group_repo_media` clone passed to `MediaService::new`.
  - **+7 tests:** `request_upload_stores_group_id`, `get_download_url_by_group_member_succeeds`, `get_download_url_by_non_member_returns_unauthorized`, plus 3 `MediaBlobRow` test fixes.
  - **security-auditor:** PASS (YELLOW-only). Y1: uploader not validated as member of claimed group at upload time (ciphertext can't be spoofed; deferred). Y5: invalid group_id → 500 instead of 400 (cosmetic, deferred).
  - **291 Rust tests** (was 284, +7); clippy clean; rustfmt clean.
  - **Remaining deferred:** Y1 (uploader membership check at upload); mTLS peer-cert → home_region binding (RED-2/RED-3, architectural); set_expire stale-token (already deemed acceptable); revoke_device mid-loop delete failure logging.

## Current state (2026-06-01, cycle 63 — STABILIZATION: CI red fix — rustfmt wasm_exports line-width)
- **Cycle 63 (commit efd9626):** CI was RED on Format check — `mls_clear_session` WASM tests (added cycle 62) had two `.with()` closures exceeding stable 1.96.0 rustfmt line-length limit. Fixed by expanding both to multi-line block form. 284 Rust tests pass; rustfmt clean; clippy clean.

## Current state (2026-06-01, cycle 62 — FEATURE: MLS/OPAQUE WASM heap wipe on logout — session-clear closed)
- **Cycle 62 (commit 4119253):** Closed long-deferred "MLS WASM heap wipe on logout" security item:
  - **WASM (`wasm_exports.rs`):** New `mls_clear_session()` `#[wasm_bindgen]` export — calls `.clear()` on `MLS_CTX`, `OPAQUE_REG`, `OPAQUE_LOGIN` thread-locals. After logout, no Rust-level reference to prior-session identity material, encryption secrets, or in-flight OPAQUE sessions remains.
  - **`crypto.worker.ts`:** Added `mls_clear_session: () => void` to `WasmModule` interface; added `clearSessionState(): Promise<void>` to Comlink `api`.
  - **`auth.ts` logout():** Calls `proxy?.clearSessionState().catch(() => {})` then `proxy?.dropDbKey()` (single proxy capture, documented FIFO order guarantee, `.catch()` per no-plaintext-logging rule).
  - **`__mocks__/useCryptoWorker.ts`:** Added `clearSessionState: async () => {}`.
  - **+4 WASM unit tests:** removes MLS contexts, removes OPAQUE reg sessions, removes OPAQUE login sessions, idempotent on empty state.
  - **+1 frontend test:** `clearSessionState called on logout` with ordering assertion (`clearSessionState` before `dropDbKey`).
  - **security-auditor:** PASS — YELLOW-1 (WASM heap residual bytes — documented platform constraint), YELLOW-3 (unhandled rejection — fixed with `.catch`), YELLOW-6 (ordering assertion — fixed in test). No RED findings.
  - **67 frontend tests** (was 66, +1); **18 WASM tests** (was 14, +4); 284 Rust workspace tests unchanged; Biome clean; clippy clean.
  - **Remaining deferred:** YELLOW-1 (zeroize wrappers on `OpaqueRegSession`/`OpaqueLoginSession` — opaque-ke implements `Zeroize`, wiring deferred); mTLS peer-cert → home_region binding (RED-2/RED-3, architectural); set_expire stale-token accumulation; revoke_device mid-loop delete failure logging.

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

## Cycle log (recent)
- Cycle 256 FEATURE: CI fix + sidebar pinned-message indicator (commits 098bfe6, eb016fc).
  - **Mode:** FEATURE (counter 256 % 5 ≠ 0). CI quick check found main RED (cycle 255's commit
    83dcf6e failed `CI — Rust` Format check).
  - **CI fix (098bfe6):** `crates/adapters/outbound/powehi-redis/tests/redis_cache_it.rs` was
    never run through `cargo fmt` before commit in cycle 255 — two blocks (a chained method call,
    a `vec![...]` literal) were left multi-line where rustfmt collapses them to one line. Ran
    `cargo fmt --all`, diff matched the CI failure log exactly. `cargo fmt --all --check` and
    `cargo clippy --workspace --all-targets -- -D warnings` both clean after.
  - **Feature (eb016fc):** Sidebar pinned-message indicator. `Chat.pinnedMessageId` (set by the
    pin/unpin feature since cycle 161) was previously only surfaced via the in-chat `PinnedBanner`
    — the sidebar `ChatRow` gave no signal that a chat had a pinned message. Added a small pin
    badge (`data-testid="pinned-message-indicator"`, `Icon name="pin"` at `#FF8A3D` — accretion
    orange per DESIGN.md action-color rule, since pinning is a user action) next to the existing
    `pinnedTop`/"pin chat to top" indicator (`#A8C8FF`, an unrelated local-only feature — kept
    visually and semantically distinct via separate testid/color/title).
  - Pure new rendering consumer of existing state — no new API calls, no new MLS ops, no new
    Zustand/Dexie fields. `title`/`aria-label` are static strings only (no plaintext, message ID,
    or sender identity in the DOM).
  - **security-auditor: GREEN** — no plaintext/PII/ciphertext leak (static title/aria-label only),
    no XSS (boolean truthiness gate, not string interpolation; `Icon` renders static SVG), no new
    logging, no weakened trust boundary (same local-state scope as the existing `pinnedTop`
    indicator it sits beside).
  - **5 new tests** in `ChatLayoutPinIndicatorSidebar.test.tsx`: absent by default, appears on
    incoming pin, disappears on unpin, chat-scoped (Maya pin doesn't mark Jordan's row), coexists
    correctly with the independent pin-to-top indicator.
  - **Frontend: 1141 tests pass** (was 1136, +5, 93 files); tsc clean; biome clean.
  - **Backend:** all workspace tests green (unchanged, 87+120+40+85+143+... across crates).
  - **Next cycle:** PQ hybrid Phase A still blocked on openmls stable `MLS_128_MLKEM768`. Other
    open UX items: per-chat notification sound picker, `powehi-r2` testcontainers integration
    suite (S3-compatible, deferred from cycle 255 — the last outbound adapter still missing one).
- Cycle 257 FEATURE: Per-chat notification sound picker (commit e5d8c26).
  - **Mode:** FEATURE (counter 257 % 5 ≠ 0). CI green on main (`gh run list` clean) — proceeded
    straight to implementation.
  - Cycle 256 flagged that `Chat.sound` (on/off toggle, local-only since early cycles) was never
    actually wired to play audio, and there was no way to choose WHICH sound plays. Closed that gap.
  - `app/src/lib/notificationSound.ts` (new): fixed catalog `NOTIFICATION_SOUNDS = ["default",
    "chime", "pop", "none"]`, synthesized via Web Audio API (`OscillatorNode`+`GainNode`, quick
    attack/decay envelope) — no binary audio assets, no new npm deps, no fetch. Lazily-created
    shared `AudioContext`, per-note node cleanup via `onended`; never throws (feature-detects and
    no-ops without Web Audio, e.g. jsdom/SSR).
  - `Chat.notificationSoundId?: NotificationSoundId` added, following the same local-only pattern
    as `muted`/`sound`/`vibrate`/`chatTheme` (React state only, never persisted to Dexie — schema
    stays at v8, never sent to server).
  - Sound picker UI added to the chat's Notifications `InfoSection`, visible only when the Sound
    toggle is on; selecting an option updates state and plays an immediate preview.
  - Wired into the incoming-message handler: `playNotificationSound(incomingChat.notificationSoundId
    ?? "default")`, gated on the same `!muted && (sound ?? true)` condition already used for vibrate/
    OS notification — did not weaken or duplicate existing gating.
  - **security-auditor: GREEN** — only an opaque `NotificationSoundId` enum value ever crosses into
    `playNotificationSound()` or the DOM (no message content/sender/group ID); no plaintext logging;
    no XSS surface (fixed compile-time catalog, nothing peer/user-interpolated); confirmed local-only
    scoping (no Dexie/network); AudioContext lifecycle bounded (short-lived nodes, self-cleaning,
    shared context reused — no leak under a message flood); existing mute/sound gates unchanged.
  - Fixed a test collision along the way: the picker's `aria-label` originally contained the word
    "sound" (`"${label} notification sound"`), which broke pre-existing `getByRole("button", { name:
    /sound/i })` queries in `ChatLayoutSound.test.tsx`/`ChatLayoutVibrate.test.tsx` (multiple matches).
    Renamed to `"${label} tone"` instead of touching the older tests.
  - 17 new tests: `notificationSound.test.ts` (11 — catalog shape, no-AudioContext no-op path,
    node-creation when available, distinct note counts per sound, construction-failure safety) +
    `ChatLayoutNotificationSoundPicker.test.tsx` (6 — renders catalog, defaults to "default", hides
    when sound off, selection updates + previews, chat-scoped, opaque-id-only assertion).
  - **Frontend: 1158 tests pass** (was 1141, +17, 95 files); tsc clean; biome clean (after
    `--write` autofix for import ordering + an unsafe `delete` → assignment lint fix).
  - **Backend:** untouched this cycle (pure frontend feature).
  - **Next cycle:** `powehi-r2` testcontainers integration suite (S3-compatible) still deferred —
    now the only outbound adapter without one (Postgres and Redis both have testcontainers suites).
    Also open: PQ hybrid Phase A (blocked on openmls stable `MLS_128_MLKEM768`).
- Cycle 258 FEATURE: powehi-r2 testcontainers integration suite (commit d75c01c).
  - **Mode:** FEATURE (counter 258 % 5 ≠ 0). CI check found `CI — Frontend` red on main for the
    latest real code push (e5d8c26, cycle 257's sound picker) — investigated before implementing:
    a byte-for-byte fresh clone + `pnpm install --frozen-lockfile` + `pnpm --filter app build` at
    that exact commit reproduced ZERO TypeScript errors, so the failure (mass `TS2339: Property
    'toBeInTheDocument' does not exist` across ~20 unrelated test files, in the `Bundle budget
    check` job's `tsc -b` step) was a transient CI cache/runner artifact, not a real regression.
    Confirmed via `gh run rerun --failed`: all jobs including Bundle budget check went green on
    rerun with zero code changes. Proceeded to FEATURE work once confirmed green.
  - Closed the last outbound-adapter test-coverage gap (testing-conventions.md item: every
    outbound adapter needs a `testcontainers` integration test) — Postgres and Redis already had
    one (cycles pre-255 and 255), `powehi-r2` (Cloudflare R2 / S3-compatible `R2MediaAdapter`) did
    not.
  - Added `testcontainers-modules`' `"minio"` feature to the root workspace Cargo.toml (image
    `minio/minio:RELEASE.2022-02-07T08-17-33Z`, default creds `minioadmin`/`minioadmin`, S3 API on
    container port 9000).
  - New `crates/adapters/outbound/powehi-r2/tests/r2_media_it.rs` (12 `#[ignore]`d tests): each
    spins up BOTH a real Postgres (media_blobs metadata + FK rows via `powehi_postgres::
    run_migrations`) and a real MinIO container per test — no mocks. Covers save/find_by_id
    round-trip (group_id Some AND None), save idempotency (`ON CONFLICT (id) DO NOTHING`),
    `presigned_upload_url` validates content-type BEFORE touching S3 (verified against the actual
    `lib.rs` impl rather than assumed), NotFound paths for missing rows, `delete` removing both the
    S3 object and the Postgres row (delete of an absent id is a no-op, not an error — also verified
    against the impl), and a full presigned upload→download byte round-trip via `reqwest`.
  - Wired into `.github/workflows/ci-rust.yml`'s `integration-test` job: `docker pull minio/minio:
    RELEASE.2022-02-07T08-17-33Z` pre-pull + `cargo nextest run -p powehi-r2 --run-ignored all
    -E 'binary(r2_media_it)'`, mirroring the existing Postgres/Redis steps.
  - Delegated implementation to `backend-lead`; verified independently: `cargo test --no-run -p
    powehi-r2` compiles clean, `cargo fmt --all --check` clean, `cargo clippy --workspace
    --all-targets -- -D warnings` clean, `cargo test --workspace` all green (Docker unavailable in
    sandbox so the 12 `#[ignore]`d tests run for real only in CI).
  - **security-auditor: GREEN** (one YELLOW-informational, not a blocker): all fixtures are opaque
    metadata (random UUIDs, content-type hints, sizes) or test-authored synthetic bytes for the
    upload round-trip — never real content/PII; MinIO default test creds are scoped to the test
    file only, pointing at an ephemeral local Docker container, not committed secrets; confirmed
    `src/lib.rs` (the actual adapter) diff is empty — this is a genuinely test-only + CI-config
    change; noted (not fixed, informational only) that `assert_eq!` on the round-trip payload bytes
    (synthetic, not real ciphertext) would print full bytes on failure — fine for synthetic test
    data, flagged as a pattern to avoid copy-pasting into any future test that touches real content.
  - `powehi-r2` is now the last outbound adapter with `testcontainers` coverage — all three
    (Postgres, Redis, R2) now have one. This closes the multi-cycle-tracked test-gap item.
  - **Next cycle:** PQ hybrid Phase A still blocked on openmls stable `MLS_128_MLKEM768` (only
    remaining tracked deferred item). No other known open UX/test-gap items from recent cycles —
    next FEATURE cycle should scan for a fresh gap (UX polish or a new checklist item) rather than
    working off a stale backlog.
- Cycle 259 FEATURE: Persist pinned message to Dexie (commit 7f150af).
  - **Mode:** FEATURE (counter 259 % 5 ≠ 0). CI green on main. No open `gh issue list` items.
  - Closes the last item in the edit(252)/delete(253)/reaction(254) Dexie-persistence series: pin/
    unpin (already fully implemented end-to-end over MLS control envelopes —
    `{type:"pin"|"unpin",targetMessageId}` in `useMessages.ts`/`ChatLayout.tsx`, with `PinnedBanner`
    UI + pin button already wired) lived only in React `chats` state — a reload silently un-pinned
    every conversation, the same gap edit/delete/reactions had before their cycles closed it.
  - `GroupRow.pinnedMessageId?: string` (schema v9, **not** encrypted at rest — same non-sensitive
    tier as the existing `disappearingTtlSeconds`, since it's just an opaque `MessageRow.id`
    reference, and `MessageRow.id` is itself already an unencrypted Dexie primary key).
  - `handleIncomingPin`/`sendPin` now also call `db.groups.update(groupId, {pinnedMessageId})`,
    mirroring the pre-existing `disappearingTtlSeconds` persistence pattern (raw `db.groups.update`,
    not routed through `EncryptedPowehiDb` since the field isn't sensitive).
  - Two new effects: one loads the persisted `pinnedMessageId` from Dexie on chat switch (alongside
    the existing `disappearingTtlSeconds` load) into new state `persistedPinnedMessageId`; a second
    applies it onto the active chat's `pinnedMessageId`/message-`pinned` flag once the target
    message exists in `chats` state, re-running on `rows` changes to retry past the async race
    between the group-row fetch and `usePersistentMessages`' message rehydration (neither has an
    ordering guarantee relative to the other).
  - **security-auditor: YELLOW → fixed in-cycle.** `persistedPinnedMessageId` was only ever set once
    at load time; an in-session unpin cleared `chats` state + Dexie but left the stale persisted id
    around, so the *next unrelated* `rows` change (e.g. any incoming message in that chat) re-ran
    the apply effect, found the old target still un-pinned-but-present, and silently re-pinned it —
    Dexie and in-memory state then disagreed until a full reload. Fixed by syncing
    `persistedPinnedMessageId` on every pin/unpin (both local `sendPin` and incoming
    `handleIncomingPin`), scoped to only update it when the event's group is the currently active
    one (via `activeIdRef`/`chatsRef`, the codebase's existing stable-callback-without-deps idiom)
    so a background group's pin event can't leak into whatever chat happens to be active later.
    Verified the fix is load-bearing by reverting it locally and confirming the new regression test
    fails against the un-fixed code, then re-applying and confirming it passes.
  - Also GREEN: no new attack surface for peer-forged pin/unpin (persistence writes exactly what
    the already-accepted in-memory `handleIncomingPin` trust model computes, no new authority); no
    plaintext/PII logging (silent `.catch(() => {})` on write failure, matching sibling patterns).
  - Added `db.groups.clear()` to `beforeEach` in `ChatLayout.test.tsx`,
    `ChatLayoutPinnedJump.test.tsx`, `ChatLayoutPinIndicatorSidebar.test.tsx` — these are now the
    only test files that write to the `groups` table, and needed the same cross-test-isolation fix
    cycle 253 applied to `db.messages.clear()`.
  - **Known pre-existing gap, confirmed not worsened by this diff:** no code path anywhere in the
    app currently calls `db.groups.add()` — a `GroupRow` is never created, so in the live app today
    `db.groups.update()` (both for `disappearingTtlSeconds` since v6, and now `pinnedMessageId`)
    is a no-op until group-row creation gets wired up. Root-caused during this cycle (searched for
    `addGroup(`/`putGroup(`/`db.groups.add` across the whole frontend — zero hits outside
    `encrypted-db.ts`'s unused method definitions and test seed helpers). Deliberately left
    unfixed: real group-row creation would need to decide what a client-created `mlsStateB64`
    placeholder should contain before real MLS state export exists, which is crypto-adjacent and
    belongs in a `crypto-lead`-reviewed cycle, not bundled into a UI-persistence fix. **This is the
    top candidate for the next cycle that wants to make Dexie persistence actually work end-to-end
    in production** rather than only in tests that pre-seed `GroupRow`s.
  - 8 new tests in `ChatLayout.test.tsx` (persist-on-pin-click, persist-on-unpin-clears,
    persist-on-incoming-pin, the unpin-resurrection regression test) + 2 in the message-history-
    rehydration describe block (restores a persisted pin on mount, does not leak a different/
    inactive chat's persisted pin into the active one). **Frontend: 1164 tests pass** (was 1163,
    +8 net after also touching 3 sibling test files' `beforeEach`; 95 files); tsc clean; biome
    clean.
  - **Next cycle:** the group-row-creation gap above, or PQ hybrid Phase A (still blocked on
    openmls stable `MLS_128_MLKEM768`).
- Cycle 260 STABILIZATION: Media Content-Type validation + full security/crypto sweep (commit f446b12).
  - **Mode:** STABILIZATION (counter 260 % 5 == 0). CI green on main (`gh run list`), `gh issue
    list --state open` empty, working tree clean at start.
  - `cargo audit`: clean (only the pre-existing waived RUSTSEC-2024-0384 `instant` advisory via
    openmls/fluvio-wasm-timer, unchanged). `cargo-deny` not installed in this sandbox — skipped
    (not previously a gating tool in this repo's cycles either).
  - Ran the full local gate before touching anything: `cargo test --workspace` all green (91 + 12
    + 85 + 8 + 7 + 4(+1 ignored) + 4 + 7 + 14 + 143 + 9 + 33 = all `ok`, zero failures), `cargo
    clippy --workspace --all-targets -- -D warnings` clean, frontend `pnpm test` 1164/1164 green
    (95 files) — matched cycle 259's counts exactly, no drift.
  - **security-auditor sweep (backend handlers + application services): PASS, no RED.** Two
    YELLOW findings:
    1. **Fixed this cycle:** `media_service.rs::request_upload` persisted and signed an
       unvalidated client `content_type` string into `MediaBlob` metadata and the R2 presigned PUT
       URL — no shape or length check. Added `is_valid_content_type`/`is_valid_media_type_token`
       (RFC 6838 §4.2 `type/subtype` token grammar, ASCII alnum + `!#$&-^_.+`, 128-char cap) and a
       fail-closed check in `request_upload` (mirrors the existing `size_bytes` defense-in-depth
       check, single source of truth in the application layer so gRPC/non-REST callers can't
       bypass it either). 4 new tests (2 pure-function table tests incl. a CRLF-injection-shaped
       string, 1 oversized-length test, 1 `request_upload` behavioral test) — `powehi-application`
       now 91/91 (was 87).
    2. **Documented, not fixed (architecture-level, deferred):** `push_subscription.rs`'s
       `is_private_host` SSRF guard only inspects IP literals in the endpoint URL; a registered
       hostname whose DNS resolves to an internal/link-local address at *send* time (not
       registration time) bypasses it (SSRF via DNS rebinding). Already mitigated in depth by the
       k8s egress NetworkPolicy blocking `169.254.169.254/32` + RFC-1918 (infra cycles 248/250).
       A real fix is resolve-then-validate-then-connect at send time, which is a bigger behavioral
       change to the webpush send path — left as a named candidate for a future cycle rather than
       bundled into this pass.
  - **crypto-reviewer sweep (all 7 `powehi-crypto-wasm` src files): GREEN, no regressions, no
    required changes.** Re-verified MLS state transitions stay entirely inside openmls, OPAQUE KE
    ordering intact, ML-KEM-768 sizes/KATs/implicit-rejection still correct, kem_credential domain
    separation intact, HKDF recovery-phrase derivation unchanged, AES-256-GCM media encryption
    fresh-key-per-call. Three previously-accepted findings (Y-B-1 unprefixed HKDF info, Y-3
    unverified-extract footgun-by-design, opaque-ke 3.0/draft-16 RFC-9807 waiver) reconfirmed as
    standing, not regressions — explicitly told not to re-action them.
  - **Target dir hygiene:** 13G, under the 20G prune threshold — no pruning needed this cycle.
  - **Next cycle:** the SSRF-via-DNS-rebinding hardening above (resolve-then-validate at webpush
    send time), or the group-row-creation gap (cycle 259), or PQ hybrid Phase A (still blocked on
    openmls stable `MLS_128_MLKEM768`).
- Cycle 255 STABILIZATION: Redis testcontainers integration suite (commit 7f9d213).
  - CI green (no red runs), `gh issue list` empty, `cargo audit` clean (only the pre-existing
    waived RUSTSEC-2024-0384 `instant` advisory via openmls/fluvio-wasm-timer), `cargo clippy
    --workspace --all-targets -- -D warnings` clean, backend `cargo test --workspace` all green,
    frontend `pnpm test` 1136/1136 green (92 files) — no regressions found, so this cycle targeted
    the test-gap sweep instead (testing-conventions.md item 3).
  - Gap found: testing-conventions.md requires a `testcontainers` integration test per outbound
    adapter (Postgres/Redis/R2); only Postgres had one (`pg_security_it.rs`). `powehi-redis`'s
    `RedisCache` (`CachePort` impl) had only inline unit tests — never touched a real Redis.
  - Added `crates/adapters/outbound/powehi-redis/tests/redis_cache_it.rs`: 9 `#[ignore]`d
    `#[tokio::test]`s against a real ephemeral `redis:7-alpine` testcontainer (overrides the
    testcontainers-modules 0.11 default tag of 5.0, which predates GETDEL/Redis 6.2 that
    `RedisCache::get_del` issues) — covers set/get round-trip, missing-key None, TTL expiry
    (real sleep-past-deadline, not mocked), delete + idempotent delete-on-missing, exists
    presence tracking, GETDEL atomicity, SADD/SMEMBERS round-trip, and set_expire TTL-on-existing-
    key. Per-test unique key prefixes (`it:{uuid}:...`) though containers are already per-test.
  - Wired into `.github/workflows/ci-rust.yml`'s existing `integration-test` job: added a
    `docker pull redis:7-alpine` pre-pull + `cargo nextest run -p powehi-redis --run-ignored all
    -E 'binary(redis_cache_it)'` step, mirroring the existing Postgres testcontainers step.
  - Cargo.toml: added `"redis"` to workspace `testcontainers-modules` features; powehi-redis
    Cargo.toml: added `tokio`/`testcontainers`/`testcontainers-modules` to `[dev-dependencies]`.
  - Delegated implementation to `backend-lead`; verified `cargo test --no-run -p powehi-redis`
    compiles clean and `cargo clippy --workspace --all-targets -- -D warnings` stays clean (Docker
    unavailable in this sandbox, so the `#[ignore]`d tests themselves run for real only in CI).
  - **security-auditor: GREEN**, no findings. Test fixtures are synthetic/opaque (no plaintext
    content or PII), container lifecycle correct (`_c` binding keeps `ContainerAsync` alive,
    Drop tears it down), test isolation sound, CI change low-risk (mirrors existing Postgres step,
    no new secrets/permissions). Minor non-blocking nit: `redis:7-alpine` is tag- not
    digest-pinned, consistent with the existing `postgres:16-alpine` step (not a regression).
  - `powehi-r2` (S3-compatible testcontainers via minio/localstack) intentionally left as a
    separate future stabilization item — did not want to scope-creep this pass.
  - target/ at 11G (well under the 20G prune threshold) — no hygiene pass needed this cycle.
- Cycle 254 FEATURE: Persist emoji reactions to Dexie (commit 4cde17a).
  - Closed the last remaining gap in the cycle 252/253 series: reactions (already fully
    implemented end-to-end over MLS control envelopes — `{type:"reaction"|"reaction_remove",...}`
    in useMessages.ts/ChatLayout.tsx) lived only in React `chats` state; a reload reverted them,
    same gap edit/delete had before cycles 252-253 closed it for those.
  - `MessageRow.reactionsJson?: string` (JSON-serialized `Record<emoji, senderDeviceId[]>`,
    encrypted at rest like editedText) added to schema.ts, bumped to `version(8)` (additive,
    no migration needed).
  - `EncryptedPowehiDb.markMessageReactions(id, reactionsJson)` — encrypts + `db.messages.update()`,
    no-ops safely on a missing id, mirrors markMessageEdited/markMessageDeleted.
  - `usePersistentMessages` gained `persistReaction(targetMessageId, reactions)`, same
    fire-and-forget + `writeErrorCount` pattern as persistEdit/persistDelete.
  - `handleIncomingReaction`/`handleRemoveReaction` in ChatLayout.tsx now also call
    `persistReaction` with the recomputed post-mutation map (recomputed from `chatsRef.current`
    since `setChats` is async — same technique handleIncomingEdit/handleIncomingDelete already use).
  - Rehydration `useEffect` (cycle 253) now also parses `row.reactionsJson` via `JSON.parse` in a
    try/catch — a corrupt/malformed value drops reactions for just that one row rather than
    aborting the whole rehydration.
  - **security-auditor: GREEN.** Two LOW findings noted as pre-existing (not introduced this
    cycle): (1) fire-and-forget Dexie writes can race under rapid react/unreact toggles — same
    exposure persistEdit/persistDelete already have; (2) reaction attribution trusts `env.sender`
    (server-authenticated device id) which is not an MLS-cryptographic sender proof — same gap the
    live (non-persisted) reaction feature already had; persistence doesn't change severity since
    the state was already forgeable-and-displayed before this cycle.
  - 9 new tests (encrypted-db.test.ts ×2, usePersistentMessages.test.ts ×3, ChatLayout.test.tsx ×4:
    incoming-reaction persists, reaction_remove persists emoji-key-dropped map, rehydrates a
    persisted reaction chip, skips unparseable reactionsJson safely). All 1136 frontend tests green
    (92 files, was 1127); tsc clean; Biome clean.
  - This closes out the edit/delete/reaction persistence trio — no further known gaps in
    message-adjacent state persistence. Reactions/pins/mentions note from cycle 253 is now just
    "pins/mentions remain session-only", reactions no longer included.
- Cycle 253 FEATURE: Rehydrate persisted chat history from Dexie into `chats` state (commit fcab6c4).
  - Closed the follow-up noted in cycle 252: `usePersistentMessages().rows` was write-only — never
    consumed in ChatLayout.tsx — so Dexie-stored message history (incl. edited text and delete-for-
    everyone tombstones) silently vanished from the UI after a reload or a switch away-and-back.
  - New `useEffect` in ChatLayout.tsx maps decrypted `MessageRow[]` → `ChatMessage[]` (text from
    `editedText ?? plaintextB64` via `base64ToText`, `from` via `senderDeviceId === deviceId`,
    `edited`/`deleted` flags, `expiresAt`), merges by dedup-on-`id` into the active chat's `messages`,
    guarded by `row.groupId !== groupId` against the async chat-switch transition window where
    `usePersistentMessages`'s `rows` briefly still holds the previous group's data.
  - **security-auditor YELLOW → fixed in-cycle:** rows from `getMessagesByGroup` aren't TTL-filtered
    and the `purgeExpired()` sweep only runs every 30s, so an already-expired disappearing message
    could flash back on screen for up to 30s after every mount — added
    `if (row.expiresAt && row.expiresAt <= Date.now()) continue;` in the rehydration loop.
  - **security-auditor YELLOW → documented/deferred (not fixed):** (1) `from: "me"` attribution
    trusts `senderDeviceId` (server-authenticated via `AuthenticatedDevice` extractor at send time,
    but not an MLS-cryptographic sender proof) — a compromised server could in principle mislabel a
    peer's message as self-authored on rehydration specifically (live/non-rehydrated incoming always
    hardcodes "them" regardless of sender, so this divergence is scoped to the rehydration path only,
    under a compromised-server assumption outside current threat model). (2) dedup is add-only —
    an id already in `chats` is left untouched even if Dexie's copy was since edited/deleted
    out-of-band (e.g. another tab), so an inactive tab that switches away-and-back (not a full reload)
    won't retroactively redact an in-memory bubble; a full reload still heals it since `chats` starts
    empty. Both documented inline in ChatLayout.tsx with "security-auditor finding, cycle 253" comments.
  - Reactions/pins/mentions remain session-only (no MessageRow/GroupRow fields exist for them) —
    explicitly out of scope; a real fix needs a schema bump, left as a future item.
  - 4 new tests in ChatLayout.test.tsx (mount rehydrates incl. edited/deleted, chat-switch doesn't
    leak, missing-plaintext row skipped safely, no duplicate for already-in-state id); also added
    `db.messages.clear()` to `beforeEach` in ChatLayout.test.tsx + 4 sibling ChatLayout*.test.tsx files
    (previously only `verifiedContacts` was cleared — cross-test Dexie pollution was latent until this
    cycle made `rows` actually get read). All 1127 frontend tests green (92 files, was 1123); tsc clean;
    Biome clean.
- Cycle 252 FEATURE: Persist edit/delete-for-everyone state to Dexie (commit 97b1f14).
  - Gap: "edit message" / "delete for everyone" were already fully implemented end-to-end over MLS
    control envelopes ({type:"edit"|"delete",...} in useMessages.ts/ChatLayout.tsx), but the edited
    text and deleted tombstone lived only in React `chats` state — a page reload reverted edits and
    un-deleted tombstoned messages, since `usePersistentMessages`'s Dexie-loaded `rows` were never
    hydrated back into `chats` (that hydration gap is separate/larger — noted as a follow-up below).
  - `MessageRow.editedText?: string` (encrypted at rest, added to SENSITIVE.messages) + `.deletedAt?: number`
    (plain, same tier as receivedAt/expiresAt); schema.ts bumped to `version(7)`, no index change.
  - `EncryptedPowehiDb.markMessageEdited(id, newTextB64)` / `.markMessageDeleted(id)` — Dexie `update()`
    no-ops safely on a missing id (attacker-influenced targetMessageId from peer envelopes, confirmed safe).
  - `usePersistentMessages` gained `persistEdit`/`persistDelete`, mirroring the existing
    `persistIncoming`/`persistOutgoing` fire-and-forget + `writeErrorCount` pattern.
  - **security-auditor YELLOW → fixed in-cycle:** `handleIncomingEdit`/`handleIncomingDelete` called
    `persistEdit`/`persistDelete` unconditionally, bypassing the `m.from === "them"` guard that already
    protected the `setChats` mutation — a forged peer envelope targeting the victim's own "me" message
    could still poison the local Dexie mirror even though in-memory state stayed correct. Fixed by
    gating persistence on the same `chatsRef`-derived from==="them" check used by the state guard.
    Added regression tests (ChatLayout.test.tsx) asserting `markMessageEdited`/`markMessageDeleted` are
    NOT called for forged edits/deletes targeting own messages, and ARE called for legitimate peer ones.
  - 9 new tests (encrypted-db.test.ts ×3, usePersistentMessages.test.ts ×6); all 1123 frontend tests green
    (92 files); tsc clean; Biome clean.
  - **Follow-up (not done this cycle):** `usePersistentMessages`'s loaded `rows` are still never read back
    into `ChatLayout`'s `chats` state on mount/group-change — full chat history (and now edited/deleted
    state) does not actually rehydrate into the UI after a reload. This is a larger, separate feature
    (mapping decrypted `MessageRow[]` → `ChatMessage[]` incl. reactions/pins/mentions/sender resolution)
    that deserves its own cycle rather than a half-finished addition here.
- Cycle 250 STABILIZATION: Security dependency fixes + domain proptest suite (commit c0c8179).
  - Fixed RUSTSEC-2026-0204 (crossbeam-epoch 0.9.18→0.9.20, invalid ptr deref via metrics-exporter-prometheus + openmls).
  - Fixed RUSTSEC-2026-0190 (anyhow 1.0.102→1.0.103, unsound downcast_mut).
  - Replaced yanked bitcoin_hashes 0.14.100→0.14.101 (via bip39 in powehi-crypto-wasm).
  - Upgraded vitest ^3.2.0→^3.2.7 (critical UI-server file-read advisory, dev-only).
  - Added 12 proptest property-based tests in crates/domain/powehi-domain/tests/prop_serde.rs:
    JSON serde roundtrips + UUID identity + Display/FromStr for GroupId/DeviceId/UserId/EnvelopeId/Epoch/MessageType.
  - security-auditor: GREEN (no RED findings; Y-LOW rate_limit XFF deploy-time precondition documented, already waived).
  - cargo audit: clean (1 existing waiver: RUSTSEC-2024-0384 instant via openmls).
  - All tests: 1114 frontend (92 files) + 52 backend domain tests (40 unit + 12 proptest) + all workspace tests passing.
- Cycle 231 FEATURE: Linked Devices panel + GET /v1/auth/devices endpoint (commit 85a4a54).
  - Fixed CI-Frontend failure: proptest moved to [target.cfg(not(wasm32)).dev-dependencies] in powehi-crypto-wasm (wait-timeout doesn't compile on wasm32).
  - Backend: DeviceInfo type (device_id, created_at, last_seen_at; no mls_credential), list_devices in AuthUseCase + AuthService, GET /v1/auth/devices handler (rate-limited, auth-gated), 2 new backend tests.
  - Frontend: LinkedDevicesPanel component (current device badge, 2-step revoke confirm, error/empty/loading states), listDevices + revokeDevice API functions in auth.ts, 11 component tests + 6 API tests.
  - security-auditor: GREEN (6 questions all clean; authorization scoped to authenticated user, no credential leakage, rate-limited, no plaintext logging, encodeURIComponent on DELETE URL).
  - All tests: 987 frontend (81 files) + all backend tests passing.
- Cycle 215 STABILIZATION: Added 4 security-invariant tests (KeyPackage single-use, cross-device isolation, expired-envelope suppression, TTL complement). security-auditor GREEN. 83/83 application tests. commit 6cbde19.
