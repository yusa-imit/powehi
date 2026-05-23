# Powehi Design — UI source of truth

The brand + UI design system for Powehi. **Read this before building or restyling any UI.**
A "Claude Design" handoff bundle (claude.ai/design), mirrored in-repo.

## Where it lives
`docs/design/powehi-design-system/` — start here, in order:
- `README.md` — coding-agent handoff notes (read first)
- `chats/chat1.md` — the design conversation = **what the user actually wants** (read for intent)
- `project/README.md` — the design system: brand, visual foundations, content voice
- `project/colors_and_type.css` — **all tokens** (color, type, spacing, radii, shadows) as drop-in CSS variables
- `project/ui_kits/web/` & `project/ui_kits/mobile/` — JSX component kits (cosmetic prototypes)
- `project/preview/*.html` — 21 spec cards (buttons, inputs, message-bubbles, chat-list, encryption-card, toasts, …)
- `project/assets/` — logo SVGs (Gargantua silhouette)

A **`/powehi-design` skill** is installed at `.claude/skills/powehi-design/` — invoke it when generating Powehi UI.

## How to use it (per the bundle's own handoff README)
- These are HTML/CSS/JS + JSX **prototypes, not production code**. **Recreate them pixel-perfectly in React 19 + Tailwind v4** (prd.md §7.1), mapping the CSS variables to OKLCH Tailwind tokens. Match the visual output; don't copy prototype internals.
- Reuse visuals/interactions, but **rebuild all logic for our stack** — the kits have no real crypto/backend; our crypto goes through the WASM worker (rule: react-hooks-only).
- **Don't render these in a browser or screenshot** unless asked — read the HTML/CSS directly.
- If design intent is ambiguous, confirm with the user before implementing.

## Brand non-negotiables (hard rules)
- **Dark-first.** Cosmic black `#040408` (never pure `#000`). Cream text `#F2EDE3` (never pure white).
- **Dual-light system** (never trade jobs): **accretion orange `#FF8A3D`** = action / presence / the user; **photon blue `#A8C8FF`** = encryption only.
- **The lock icon is always photon blue.**
- No emoji in UI chrome (only user content). No motion bounces (gentle eases). Sentence case except UPPERCASE eyebrows. Instrument Serif italic only for taglines/poetry, ≤1 per screen.
- Logo = the Gargantua silhouette (black sphere + warm disk + lensed top halo + photon ring). Never substitute.

## Provenance / re-sync
Source: Claude Design bundle — `https://api.anthropic.com/v1/design/h/2fVmOYLj2BFtfh0bMPTWGw` (public; gzip tarball).
Mirrored in-repo (not fetched on demand) so the autonomous cron and offline builds don't depend on the network or the URL's lifetime. To refresh from source:
```bash
curl -fsSL "https://api.anthropic.com/v1/design/h/2fVmOYLj2BFtfh0bMPTWGw" -o /tmp/powehi-design.tar.gz
rm -rf docs/design/powehi-design-system && tar xzf /tmp/powehi-design.tar.gz -C docs/design
```
