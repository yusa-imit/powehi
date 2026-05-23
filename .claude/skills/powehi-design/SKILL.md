---
name: powehi-design
description: Generate well-branded Powehi UI and assets (production or prototype) using the in-repo design system — colors, type, fonts, logos, and web/mobile UI-kit components. Use whenever building or restyling any Powehi interface.
user-invocable: true
---

# Powehi Design

Powehi's brand merges two black holes — Pōwehi (M87) and Gargantua (Interstellar) — into a **dual-light system**: warm accretion orange (action) + cool photon blue (encryption). Tagline: *Past the horizon, only you.*

The full design system is mirrored in-repo at `docs/design/powehi-design-system/`. The repo-root `DESIGN.md` is the map.

## How to use
1. Read `docs/design/powehi-design-system/project/README.md` first (voice, visual foundations, iconography).
2. Pull tokens from `docs/design/powehi-design-system/project/colors_and_type.css` (CSS variables → map to Tailwind v4 OKLCH per prd.md §7.1).
3. Reuse components from `docs/design/powehi-design-system/project/ui_kits/web/` (Icon, Atoms, Sidebar, Conversation, InfoPanel, Welcome) and `.../mobile/`. They are cosmetic prototypes — recreate pixel-perfect in React 19, rebuild logic for our stack.
4. Check the matching `.../project/preview/*.html` spec card for the exact component.
5. For intent, skim `docs/design/powehi-design-system/chats/chat1.md`.

## Brand non-negotiables (don't break)
- Dark-first; cosmic black `#040408`, cream text `#F2EDE3` (never pure `#000`/`#fff`).
- Dual-light: accretion orange `#FF8A3D` = action/presence; photon blue `#A8C8FF` = encryption only. Never trade jobs.
- Lock icon is ALWAYS photon blue. No emoji in chrome. No motion bounces. Sentence case (UPPERCASE eyebrows only). Instrument Serif italic = taglines/poetry only, ≤1 per screen.
- Logo = Gargantua silhouette; never substitute.

## Boundaries
- Prototypes have no real crypto/backend — never copy that; crypto goes through the WASM worker (rule: react-hooks-only).
- Don't render in a browser / screenshot unless asked — read HTML/CSS directly.
- If design intent is ambiguous, confirm with the user before implementing.
