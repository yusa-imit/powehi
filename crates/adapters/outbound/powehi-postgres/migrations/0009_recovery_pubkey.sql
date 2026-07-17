-- Recovery-phrase public key: the raw 32-byte Ed25519 verifying key deterministically
-- derived from the user's BIP-39 recovery phrase (prd.md §8.5). Stored at registration
-- so a user who has lost every authenticated device can prove recovery-phrase possession
-- (a signature over the login nonce) and mint a brand-new device during login, WITHOUT
-- an already-authenticated session. Nullable: pre-existing rows have no stored key and
-- therefore cannot use this path (fail-closed — that is intentional). Never logged.
ALTER TABLE users ADD COLUMN recovery_pubkey BYTEA;
