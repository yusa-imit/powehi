---
paths:
  - "app/**/*.tsx"
  - "app/**/*.ts"
  - "app/**/*.jsx"
---

# React frontend conventions

## Component rules
- Functional components only — no class components
- Use React 19 hooks (useState, useEffect, useMemo, useCallback, use)
- Co-locate component, styles, and tests in the same directory

## State management
- Local state: useState / useReducer
- Global state: Zustand stores (no Redux, no Context for state)
- Server state: TanStack Query
- Form state: TanStack Form
- Routing: TanStack Router (file-based routes)

## Crypto boundary
- NEVER import crypto libraries directly in UI code
- All crypto goes through Comlink worker proxy (`cryptoWorker.methodName()`)
- Raw key material must never appear in React component scope

## Storage
- NO localStorage for anything sensitive
- Dexie (IndexedDB) with encryption layer for persistence
- Zustand in-memory for ephemeral state

## Design system
- Read `DESIGN.md` / invoke `/powehi-design` before building or restyling UI.
- Map tokens in `docs/design/powehi-design-system/project/colors_and_type.css` to Tailwind v4 OKLCH; reuse the `ui_kits/web` & `ui_kits/mobile` components (rebuild logic for our stack).
- Brand non-negotiables (hard): dark-first (`#040408`), cream text (`#F2EDE3`), dual-light (accretion orange `#FF8A3D` = action; photon blue `#A8C8FF` = encryption only), lock icon always photon blue, no emoji in chrome, no motion bounces.
