# Powehi CLI — user guide

`powehi` is the primary Powehi client (ADR-0006, prd.md §7A). The server never sees
plaintext; keys and messages live in an encrypted per-profile store on your machine.

```
cargo run -p powehi-cli -- <subcommand>     # or the built `powehi` binary
```

## Install

Release binaries are built from tags `cli-vX.Y.Z` and published on the GitHub Releases
page: `powehi-macos-arm64`, `powehi-macos-x86_64`, `powehi-linux-x86_64`,
`powehi-linux-arm64` (Linux builds are static). Each release also has `SHA256SUMS`, a
cosign `.sigstore.json` bundle per file, and SLSA provenance (`*.intoto.jsonl`).

```
set -euo pipefail
TAG=cli-v0.1.0; ASSET=powehi-macos-arm64        # pick your platform
BASE=https://github.com/yusa-imit/powehi/releases/download/$TAG
for f in $ASSET SHA256SUMS SHA256SUMS.sigstore.json; do curl -fLO "$BASE/$f"; done
# 1. the checksum list is signed by this repo's release workflow, for exactly this tag
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/yusa-imit/powehi/.github/workflows/cli-release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
# 2. the binary matches the signed list
grep " $ASSET\$" SHA256SUMS | sha256sum -c -        # macOS: shasum -a 256 -c -
chmod +x $ASSET && mv $ASSET /usr/local/bin/powehi
# macOS only, if Gatekeeper blocks it (browser downloads are quarantined; curl's are not):
xattr -d com.apple.quarantine /usr/local/bin/powehi || true
```

Provenance: `slsa-verifier verify-artifact $ASSET --provenance-path multiple.intoto.jsonl
--source-uri github.com/yusa-imit/powehi --source-tag $TAG`. Builds use `--locked`,
`SOURCE_DATE_EPOCH=0` and remapped workspace paths; bit-for-bit reproduction on another
machine is not guaranteed (cargo registry paths and runner images differ), so rely on the
signature and provenance, not on a local rebuild.

The default `--server` stays `https://localhost:8443` until the production endpoint
exists (Phase 9.9).

## Global options

| Option | Env | Default |
|---|---|---|
| `--server <url>` | `POWEHI_SERVER` | `https://localhost:8443` |
| `--profile <name>` | `POWEHI_PROFILE` | `default` |
| `--data-dir <path>` | `POWEHI_DATA_DIR` | per-user data dir |

Each profile has its own encrypted data directory, so one machine can hold several
accounts. Passwords are read from the TTY, never from argv or the environment.

## Quick start (two people)

```
powehi register                      # once per profile; prompts for handle/password
powehi login                         # unlocks the store for this run
powehi invite create --wait 120      # prints an invite link, waits for the peer
powehi invite redeem                 # peer pastes the link on stdin
powehi conversations                 # list "<conversation id> <role> [<n> unread]"
powehi profiles                      # list profile names
powehi verify <conversation>         # compare the Safety Number out of band
powehi verify <conversation> --confirm "<number>"
powehi chat <conversation>           # interactive REPL, live delivery
```

## Commands

| Command | What it does |
|---|---|
| `status` | Server health and detected region |
| `register` / `login` | OPAQUE authentication (RFC 9807); the server never learns the password |
| `invite create [--wait N]` | Make an invite link; with `--wait`, join when the peer's Welcome arrives |
| `invite redeem` | Redeem a link read from stdin |
| `send <conv>` | Send the message body read from stdin (never argv) |
| `inbox` | Fetch, decrypt, store and acknowledge pending messages |
| `read <conv> [--keep] [--last N]` | Show stored messages, then remove them from the store (`--keep` leaves them; `--last N` handles only the newest N, older ones stay stored) |
| `chat <conv>` | Interactive REPL; reconnects up to 3 times, then tells you |
| `verify <conv> [--confirm N]` | Show / record the Safety Number (prd.md §5.6) |
| `conversations [--unread] [--changed] [--role R] [--count]` | List conversation ids, roles, unread counts and a `CHANGED` flag; `--unread` hides conversations with nothing unread, `--changed` shows only those flagged `CHANGED`, `--role creator` / `--role joiner` shows only conversations where you were that side of the invite, `--count` prints just the number of matches |
| `profiles` | List profile names in the data directory (no password) |

`<conv>` accepts a unique prefix of at least 4 characters.

## Safety notes

- If a verified Safety Number later changes, the CLI warns `CHANGED` on stderr; it does
  not block sending (open design question, issue #53).
- A wrong-key error on open usually means a mistyped password. Do not delete record
  files in the profile directory.
- Core dumps are disabled at startup. Message text is wiped from memory where practical;
  terminal scrollback is outside the CLI's control (prd.md §7A.3).
