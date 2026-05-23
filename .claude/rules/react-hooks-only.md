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
