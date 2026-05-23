---
name: powehi-design
description: Use this skill to generate well-branded interfaces and assets for Powehi, either for production or throwaway prototypes/mocks. Contains design guidelines, colors, typography, fonts, assets, and UI kit components.
user-invocable: true
---

# Powehi Design

Powehi is an end-to-end encrypted messaging app. The brand merges two black holes: **Pōwehi (M87)** — the only one ever photographed — and **Gargantua (Interstellar)** — the iconic cinematic silhouette. This produces a **dual-light system**: warm orange (action) and cool photon-blue (encryption).

## How to use this skill

Read the `README.md` file within this skill first — it covers:
- Content fundamentals (voice, casing, person, canonical examples)
- Visual foundations (dual-light system, color, type, spacing, motion, layout)
- Iconography rules (Lucide-style inline SVG, sizes, colors, emoji policy)

Then explore:
- `colors_and_type.css` — all CSS variables, drop-in
- `assets/` — logo SVGs (Gargantua silhouette)
- `preview/` — 21 design system spec cards
- `ui_kits/web/` — React/JSX components (Icon, Avatar, Button, Sidebar, Conversation, Composer, Welcome, InfoPanel)
- `ui_kits/mobile/` — mobile screens inside an iOS device frame

## When creating visual artifacts (slides, mocks, prototypes)

Copy assets out and reference locally. Pull `colors_and_type.css` and the JSX components via `<link>` and `<script type="text/babel">` — framework-agnostic, dependency-free.

## When working on production code

Read the rules here to design with the brand. Component implementations are intentionally cosmetic (no real encryption, no real backend) — reuse the visuals and interactions, rebuild logic for your stack.

## If invoked without further guidance

Ask the user what they want to build. Ask the standard discovery questions (surface, audience, fidelity, variations). Act as an expert designer who outputs HTML artifacts or production code.

## Brand non-negotiables (don't break these)

- **Dark-first.** Don't flip to light unless explicitly requested.
- **Dual-light system.** Accretion orange (`#FF8A3D`) for *action and presence*. Photon blue (`#A8C8FF`) for *encryption only*. These don't trade jobs.
- **Lock icon is always photon blue.**
- **Cream, not white,** for primary text (`#F2EDE3`).
- **No emoji in chrome** — only in user-generated content.
- **No bounces** in motion — gentle eases only.
- **Sentence case** everywhere except UPPERCASE eyebrows.
- **Instrument Serif italic** is for *taglines and poetry only* — max once per screen.
- **The logo is the Gargantua silhouette**: black sphere + warm horizontal disk + lensed top halo + photon ring. Never substitute a different mark.
