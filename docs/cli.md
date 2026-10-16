# Powehi CLI — user guide

`powehi` is the primary Powehi client (ADR-0006, prd.md §7A). The server never sees
plaintext; keys and messages live in an encrypted per-profile store on your machine.

```
cargo run -p powehi-cli -- <subcommand>     # or the built `powehi` binary
```

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
powehi conversations                 # list "<conversation id> <role>"
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
| `read <conv>` | Show stored messages, then remove them from the store |
| `chat <conv>` | Interactive REPL; reconnects up to 3 times, then tells you |
| `verify <conv> [--confirm N]` | Show / record the Safety Number (prd.md §5.6) |
| `conversations` | List conversation ids and roles |

`<conv>` accepts a unique prefix of at least 4 characters.

## Safety notes

- If a verified Safety Number later changes, the CLI warns `CHANGED` on stderr; it does
  not block sending (open design question, issue #53).
- A wrong-key error on open usually means a mistyped password. Do not delete record
  files in the profile directory.
- Core dumps are disabled at startup. Message text is wiped from memory where practical;
  terminal scrollback is outside the CLI's control (prd.md §7A.3).
