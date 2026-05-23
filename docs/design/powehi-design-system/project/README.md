# Powehi Design System · v2

> *Powehi* — Hawaiian, "embellished dark source of unending creation."
> Two black holes, one brand.

**Powehi** is an end-to-end encrypted messaging app. Only the people in the conversation can read what's sent. Everything in between is dark.

The brand sits at the merge of two black holes:

- **Pōwehi (M87)** — the only black hole ever photographed. The EHT image gives us the warm orange accretion disk, the *real* light. The product's name comes from here.
- **Gargantua (Interstellar)** — the iconic cinematic silhouette. Gravitational lensing bends the disk's light up and over the sphere, creating the recognizable vertical halo. The cool blue-white photon ring.

These two ideas give us a **dual-light system**: warm orange (action, the user, the message) and cool photon-blue (encryption, protection, the system). The black sphere in the middle is where information becomes private.

**Tagline:** *Past the horizon, only you.*

---

## Sources

No codebase, Figma, or assets were provided — everything was built from scratch against the description "End-to-end encrypted messaging app, named from the M82 black hole."

**Resolved during design:**
- "M82" was an honest mix-up — M82 is a starburst galaxy, not a famous photographed black hole. The brand name *Powehi* refers to **M87** (Pōwehi). The visual language now intentionally combines Pōwehi (M87) with the *Interstellar* black hole **Gargantua**.
- Fonts loaded from Google Fonts CDN (Geist, Geist Mono, Instrument Serif). Drop licensed files into `fonts/` to self-host.

---

## Index

| File | What's in it |
|---|---|
| [`README.md`](README.md) | This file |
| [`SKILL.md`](SKILL.md) | Skill manifest (compatible with Claude Code / Agent Skills) |
| [`colors_and_type.css`](colors_and_type.css) | All CSS variables — color tokens, type scale, spacing, radii, shadows, semantic classes |
| [`assets/`](assets/) | Logo SVGs — mark (Gargantua silhouette), monoline, lockup |
| [`preview/`](preview/) | 21 cards populating the Design System tab |
| [`ui_kits/web/`](ui_kits/web/) | Web app — interactive clickthrough chat |
| [`ui_kits/mobile/`](ui_kits/mobile/) | Mobile app — iOS frame with three screens |

---

## Content Fundamentals

Voice is **calm, second-person, occasionally poetic.** It speaks like someone who knows you and respects your privacy.

**Casing.** Sentence case everywhere. `Send securely`, not `Send Securely`. Eyebrows and section labels are the *only* place caps appear — UPPERCASE with 0.16em tracking.

**Person.**
- **You / your** addresses the user. (`Only you can read this.`)
- **We** is the product, used sparingly and only for system actions. (`We'll text a 6-digit code.`)
- Never "the user," "they," or anything corporate.

**Tone register.** Confident, brief, never apologetic. One sentence per idea. State, don't reassure: "Only the endpoints can read this" — not "Don't worry, we promise!"

**Cosmic vocabulary** is a finishing salt, not a main course. Use sparingly: *horizon, orbit, ring, fall, dark, light, lens.* Avoid *void*-as-emptiness, *singularity*-as-metaphor, *infinity*.

**Canonical examples** (lifted from the kits):
- Tagline: *Past the horizon, only you.*
- First-load explainer: *End-to-end encrypted from the first byte.*
- Empty composer: *Message Maya — encrypted*
- Encryption banner: *Only you and Maya can read these messages. Not even Powehi.*
- Sent-status pill: *encrypted · sent*
- Auth: *We sent you a code. / Enter the 6-digit code we sent to +1 555 0124.*
- Error toast: *Couldn't send. Out of range. We'll retry when you're back.*
- Key-changed warning: *Keys changed. Maya started using a new device. Re-verify.*
- Verification CTA: *Compare in person* (not "Verify Identity")
- Sign-up: *Continue with phone*

**Emoji** is used by *users*, not by the *product*. Chat content can carry 🌒 ✺ etc.; UI chrome cannot.

**Numbers.** Tabular numerals for timestamps, counts, fingerprints. 24-hour time (`14:32`). Fingerprints colon-separated: `A3:5F:91:CC:7E:08`.

---

## Visual Foundations

**Mode.** Dark-first. The cosmic black is `#040408` — slightly cool, never pure `#000`.

**Dual-light system.** The core brand decision.
- **Accretion** (`#FF8A3D` warm orange) — primary actions, the user's own messages, unread counts, the send button glow, focused input rings. *Action and presence.*
- **Photon ring** (`#A8C8FF` cool blue-white) — encryption signals only. Every lock icon, verified pill, encryption card. *Protection.*

These two colors never trade jobs. Orange means *you*; photon-blue means *encrypted*. Don't use orange for the lock or blue for the send button.

**Background system.** Five blacks: `--bg-void` (page) → `--bg-surface` (panels) → `--bg-elevated` (hover/raised) → `--bg-overlay` (menus) → `--bg-input` (wells, a touch darker than the page to read inset). Every black has a faint cool tint.

**Background motifs.**
1. **Void** — flat `#040408`. Default.
2. **Horizon glow** — soft `radial-gradient` of accretion orange at low opacity, anchored bottom or center. Used behind hero moments and the conversation surface.
3. **Lensing** — radial halo + central sphere shadow, the Gargantua effect. Reserved for welcome / featured surfaces.
4. **Star dust** — quiet dot-pattern texture. Use only when a surface feels too flat.

**Type.**
- **Geist** 400/500/600 covers 90% of the UI. Modern grotesk, neutral, technical.
- **Geist Mono** for content that needs monospace alignment: fingerprints, key IDs, timestamps. Never decorative.
- **Instrument Serif italic** appears at most once per screen — taglines and welcome poetry. Never for UI labels.
- Eyebrows: 11px / 500 / UPPERCASE / 0.14–0.16em tracking / `--fg-3`.

Text uses cream `--fg-1` (`#F2EDE3`), never pure white.

**Spacing.** 4-px base scale (4, 8, 12, 16, 20, 24, 32, 40, 48, 64, 96). Reading-width content capped at 480–720px.

**Corner radii.** 8 chips · 10 buttons · 12 inputs · 14 cards · 16 composer · 18 message bubbles · 24 welcome card · pill badges. The black sphere and the photon ring are the only true circles in the brand.

**Message bubbles.** Asymmetric tails — 18px corners except the *near* corner of the *last* bubble in a run, which drops to 6px. "Mine" bubbles use an accretion gradient with a soft 18px glow. "Theirs" use `--bg-elevated` with a faint 1px border. Continued messages keep the avatar slot but render only the first avatar.

**Shadows & elevation.** Dark elevation is invisible-but-felt: `--shadow-md` is `0 4px 12px rgba(0,0,0,0.6)`. Paired with `--glow-accretion` or `--glow-photon` on focused / primary elements — *light leaks out of action*.

**Borders.** Three weights of cream at low alpha: faint (5%), soft (9%), strong (16%). Plus `--border-photon` (blue at 22%) for encryption-tinted cards. 1px throughout.

**Hover / press.**
- Hover: surface lifts one step (transparent → `--bg-surface` → `--bg-elevated`).
- Press: 120ms scale to 0.94, no color change.
- Focus on inputs: orange ring `0 0 0 3px rgba(255,138,61,0.15)` + 1px `rgba(255,138,61,0.5)`.

**Animation.**
- `cubic-bezier(0.22, 1, 0.36, 1)` ("orbit") for most things — gentle settle, no overshoot.
- `cubic-bezier(0.65, 0, 0.35, 1)` ("horizon") for hero transitions — slow-fast-slow.
- Durations: 120 / 200 / 380 / 800ms.
- **No bounces.** Black holes don't bounce. Fades > slides. Crossfades > wipes.

**Transparency & blur.** Used on the welcome card (60% surface + 20px blur), mobile composer / tab bar, conversation header. Never on the active reading area.

**Layout.**
- Web: sidebar (320px fixed) · main (fluid) · info panel (340px when open).
- Mobile: single column on a 390-wide design grid.
- Bubbles cap at 72% width on web, 78% on mobile.
- Composer is full-bleed within its column, never centered.

---

## Iconography

**System.** Inline SVG icon set in Lucide style (1.6px stroke, rounded caps & joins, 24×24 viewBox). Renders via `<Icon name="lock" size={20}/>` from `ui_kits/web/Icon.jsx`. The set is small (~19 glyphs) and bundled inline — no runtime fetches.

**Set.** lock, send, search, plus, settings, phone, video, more, attach, smile, mic, check, doublecheck, user, chat, arrowLeft, arrowRight, x, image.

**Sizes.** 11 (inline badges), 14–16 (button), 20 (default), 22 (toolbar), 28 (large feature).

**Color.** Icons inherit `currentColor`. **The lock icon is always photon blue** (`#A8C8FF`) regardless of surface — hard-coded brand rule. The brand reads "encryption is always cool light."

**Emoji.** Not used as icons. *User content* contains emoji; *chrome* never does.

**Unicode glyphs.** Quiet symbols inside copy — `·` (middle dot) as a separator, `←` `→` for nav text. User-generated text may carry `✺` `🌒` etc. Don't use bullets (`•`) — middle dot is more elegant at small sizes.

**Logo as icon.** The mark in [`assets/logo-mark.svg`](assets/logo-mark.svg) doubles as the app icon. It's the only place a sphere with an accretion disk appears in the brand.

---

## Open work / known gaps

1. **Real licensed fonts.** Currently CDN'd Google Fonts.
2. **No Android frame.** Mobile kit uses iOS only.
3. **No Settings / Profile / Calls screens.** Tabs in mobile kit are decorative.
4. **No marketing site.** Brand could extend into a landing surface.
5. **No real photography.** Backgrounds are pure gradients — if EHT or telescope photography fits a marketing context, drop assets in and I'll wire them in.
