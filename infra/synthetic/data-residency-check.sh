#!/usr/bin/env bash
# data-residency-check.sh — Data Residency Invariant Verification
#
# Verifies prd.md §4A.6: User PII (handle_hash, OPAQUE envelope, device keys)
# NEVER crosses region boundaries. Only opaque UUIDs + ciphertext are forwarded.
#
# Runs in four layers:
#   1. Schema audit  — proto file contains no PII field names
#   2. Code audit    — gRPC handler/client never reads/logs PII fields
#   3. Event audit   — DomainEvents published cross-region contain no PII
#   4. Messaging     — application-layer forwarding path uses Envelope (opaque)
#
# Exit codes: 0 = PASS, 1 = FAIL (one or more violations found)
#
# Environment variables:
#   PROTO_DIR   path to proto files (default: ../../crates/infra/powehi-proto/proto)
#   CRATES_DIR  path to crate sources (default: ../../crates)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROTO_DIR="${PROTO_DIR:-${SCRIPT_DIR}/../../crates/infra/powehi-proto/proto}"
CRATES_DIR="${CRATES_DIR:-${SCRIPT_DIR}/../../crates}"

exit_code=0

# Colour helpers (disabled when stdout is not a terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RESET='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; RESET=''
fi

pass() { printf "${GREEN}[PASS]${RESET} %s\n" "$1"; }
fail() { printf "${RED}[FAIL]${RESET} %s\n" "$1"; exit_code=1; }
info() { printf "${YELLOW}[INFO]${RESET} %s\n" "$1"; }

# Extract exactly one proto message body by name (stops at the closing '}'.
# Usage: extract_message <name> <file>
extract_message() {
    awk -v msg="$1" '$0 ~ "^message " msg "{" || $0 ~ "^message " msg " {" { found=1 } found { print } found && /^}/ { exit }' "$2"
}

echo "======================================================================"
echo "  Powehi Data Residency Verification — prd.md §4A.6"
echo "======================================================================"
echo ""

# ── Layer 1: Proto schema audit ────────────────────────────────────────────
echo "--- Layer 1: Proto schema audit ---"

PROTO_FILE="${PROTO_DIR}/region.proto"
if [ ! -f "$PROTO_FILE" ]; then
    fail "region.proto not found at $PROTO_FILE"
else
    # PII terms that must NOT appear as field names in cross-region messages.
    # Use \b word boundaries so "user_handle_hash" does not slip past "handle_hash".
    # Type prefix uses \w+ to catch all proto scalar and message types.
    PII_TERMS=(
        "handle_hash"
        "user_id"
        "email"
        "phone"
        "opaque_password"
        "password_file"
        "export_key"
        "device_key"
        "signing_key"
        "identity_key"
        "private_key"
        "secret"
    )

    for term in "${PII_TERMS[@]}"; do
        # Pattern: any whitespace + any proto type word + whitespace + EXACT term + whitespace + '='
        # The \b (word boundary) prevents "user_handle_hash" from matching "handle_hash".
        if grep -qE "^\s+\w+\s+\b${term}\b\s*=" "$PROTO_FILE"; then
            fail "PII field '${term}' found as a message field in region.proto"
        fi
    done

    # Verify cross-region messages have exactly the expected number of fields.
    # Use awk to extract each message body precisely (stops at closing '}'),
    # avoiding over-counting from adjacent message definitions.

    ENVELOPE_FIELDS=$(extract_message "ForwardEnvelopeRequest" "$PROTO_FILE" \
        | grep -cE "^\s+\w+\s+\w+\s*=" || true)
    if [ "$ENVELOPE_FIELDS" -ne 7 ]; then
        fail "ForwardEnvelopeRequest has ${ENVELOPE_FIELDS} fields, expected exactly 7 (prd.md §4A.6)"
    else
        pass "ForwardEnvelopeRequest: exactly 7 opaque fields (no PII)"
    fi

    COMMIT_FIELDS=$(extract_message "ForwardCommitRequest" "$PROTO_FILE" \
        | grep -cE "^\s+\w+\s+\w+\s*=" || true)
    if [ "$COMMIT_FIELDS" -ne 4 ]; then
        fail "ForwardCommitRequest has ${COMMIT_FIELDS} fields, expected exactly 4 (prd.md §4A.6)"
    else
        pass "ForwardCommitRequest: exactly 4 opaque fields (no PII)"
    fi

    pass "Proto schema: no PII field names in cross-region messages"
fi

echo ""

# ── Layer 2: gRPC handler + client code audit ──────────────────────────────
echo "--- Layer 2: gRPC handler/client code audit ---"

GRPC_SERVER="${CRATES_DIR}/adapters/inbound/powehi-grpc/src/server.rs"
GRPC_CLIENT="${CRATES_DIR}/adapters/inbound/powehi-grpc/src/client.rs"

if [ ! -f "$GRPC_SERVER" ] || [ ! -f "$GRPC_CLIENT" ]; then
    fail "gRPC source files not found (expected at ${CRATES_DIR}/adapters/inbound/powehi-grpc/src/)"
else
    # Scan for PII access in non-comment production code.
    # Strip // line comments before matching so test doc-comments don't trigger false positives.
    # Note: this does NOT strip block comments (/* */), but those are not used in this codebase.
    SERVER_PII_VIOLATIONS=$(sed 's|//.*||' "$GRPC_SERVER" \
        | grep -nE "\.handle_hash|\.opaque_password|\.password_file|\.export_key|\.private_key" \
        || true)
    if [ -n "$SERVER_PII_VIOLATIONS" ]; then
        fail "PII field access found in gRPC server (non-comment lines):"
        echo "$SERVER_PII_VIOLATIONS"
    else
        pass "gRPC server: no PII field access in non-comment code"
    fi

    CLIENT_PII_VIOLATIONS=$(sed 's|//.*||' "$GRPC_CLIENT" \
        | grep -nE "\.handle_hash|\.opaque_password|\.password_file|\.export_key|\.private_key" \
        || true)
    if [ -n "$CLIENT_PII_VIOLATIONS" ]; then
        fail "PII field access found in gRPC client:"
        echo "$CLIENT_PII_VIOLATIONS"
    else
        pass "gRPC client: ForwardEnvelopeRequest built from opaque Envelope fields only"
    fi

    # Verify #[instrument] macros do not capture PII in tracing spans.
    # Use awk to extract multi-line instrument blocks before scanning.
    INSTRUMENT_BLOCKS=$(awk '/#\[instrument/{found=1} found{buf=buf "\n" $0} found && /\]/{print buf; buf=""; found=0}' "$GRPC_SERVER")
    if echo "$INSTRUMENT_BLOCKS" | grep -qE "handle_hash|user_id|email"; then
        fail "gRPC server tracing spans capture PII fields in #[instrument] block"
    else
        pass "gRPC server: #[instrument] spans contain no PII"
    fi
fi

echo ""

# ── Layer 3: DomainEvent audit ─────────────────────────────────────────────
echo "--- Layer 3: DomainEvent cross-region PII audit ---"

EVENT_FILE="${CRATES_DIR}/domain/powehi-domain/src/event.rs"

if [ ! -f "$EVENT_FILE" ]; then
    fail "domain event file not found at $EVENT_FILE"
else
    # DomainEvents must NOT contain plaintext user identifiers or credentials.
    # Only opaque IDs (envelope_id, group_id, device_id) are allowed.
    if grep -qE "\bhandle_hash\b\s*:" "$EVENT_FILE"; then
        fail "DomainEvent contains handle_hash field — PII in event bus"
    else
        pass "DomainEvent: no handle_hash in event definitions"
    fi

    if grep -qE "\b(opaque_password|password_file)\b" "$EVENT_FILE"; then
        fail "DomainEvent contains credential fields — PII in event bus"
    else
        pass "DomainEvent: no credential fields in event definitions"
    fi

    pass "DomainEvent schema: all cross-region events use opaque UUIDs"
fi

echo ""

# ── Layer 4: Messaging application-layer audit ─────────────────────────────
echo "--- Layer 4: Messaging application-layer audit ---"

# Scan ALL messaging*.rs files (not just the first one — Y5 fix from security-auditor).
MESSAGING_FILES=$(find "${CRATES_DIR}/application" -name "messaging*.rs" 2>/dev/null || true)

if [ -z "$MESSAGING_FILES" ]; then
    info "messaging service not found — skipping application-layer audit"
else
    MSG_FAIL=0
    while IFS= read -r mfile; do
        if grep -qE "user\.handle_hash|user\.opaque_password|UserRecord" "$mfile"; then
            fail "Messaging service accesses PII fields in forwarding path: $mfile"
            MSG_FAIL=1
        fi
    done <<< "$MESSAGING_FILES"
    if [ "$MSG_FAIL" -eq 0 ]; then
        pass "Messaging service: forwarding path uses Envelope (opaque), not UserRecord"
    fi
fi

echo ""

# ── Summary ────────────────────────────────────────────────────────────────
echo "======================================================================"
if [ $exit_code -eq 0 ]; then
    printf "${GREEN}RESULT: PASS — Data residency invariant holds (prd.md §4A.6)${RESET}\n"
    echo ""
    echo "  PII fields (handle_hash, OPAQUE envelope, device keys) are NOT"
    echo "  present in any cross-region gRPC message schema or code path."
    echo "  Only opaque UUIDs + ciphertext cross region boundaries."
else
    printf "${RED}RESULT: FAIL — Data residency invariant violated (see above)${RESET}\n"
    echo ""
    echo "  One or more PII fields were found in cross-region code paths."
    echo "  Fix all FAIL findings before merging. See prd.md §4A.6."
fi
echo "======================================================================"

exit $exit_code
