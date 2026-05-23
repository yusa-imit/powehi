# Powehi · Web UI Kit

Browser-based chat app. Dual-light dark theme. No build step — open `index.html`.

## Components
| File | Exports |
|---|---|
| `Icon.jsx` | `Icon` — 19 Lucide-style icons, inline paths |
| `Atoms.jsx` | `Logo` (Gargantua silhouette), `Avatar`, `Button`, `IconBtn`, `Pill` |
| `Sidebar.jsx` | `Sidebar`, `ChatRow` |
| `Conversation.jsx` | `ConversationHeader`, `MessageList`, `MessageBubble`, `Composer` |
| `InfoPanel.jsx` | `InfoPanel` (verification + media + settings) |
| `Welcome.jsx` | `Welcome` (phone → 6-digit code) |
| `App.jsx` | `App` |

## Click-thru flow
Welcome → enter phone → enter 6 digits → app. Search filters chats. Compose & send. ⋯ toggles info panel.

## What this does NOT do
- No real encryption — fingerprints are decorative.
- No persistence — refresh resets seed chats.
- Voice / video buttons alert instead of opening a call.
- No light theme exposed in the UI.
