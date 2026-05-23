---
paths:
  - "**/*.rs"
  - "**/*.ts"
  - "**/*.tsx"
  - "**/*.js"
  - "**/*.jsx"
---

# No plaintext logging

Logging plaintext message content, user identifiers in cleartext, or media filenames
violates the threat model (prd.md threat model section).

When emitting logs:
- Use opaque internal IDs (UUID), not user-supplied identifiers
- Use error categories, not error messages with payload
- Use size buckets (e.g. 1KB / 10KB / 100KB), not raw sizes

Forbidden patterns:
- `tracing::info!("user {} sent message", email)`
- `console.log("decrypted:", message)`
- `info!("envelope: {:?}", envelope)` where envelope contains ciphertext
- Any log statement that includes plaintext content, passwords, tokens, or secrets

Allowed:
- `tracing::info!(user_id = %internal_id, "auth success")`
- `tracing::warn!(envelope_size_bucket = %size_bucket(s), "envelope received")`
