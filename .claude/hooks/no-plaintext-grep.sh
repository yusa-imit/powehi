#!/bin/bash
# PostToolUse hook: Warn if edited file contains plaintext logging patterns
# Input: JSON via stdin with tool_input.file_path (Edit/Write tools)
# Exit 0 = no issue, Exit 2 = block with warning

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('tool_input',{}).get('file_path',''))" 2>/dev/null)

if [ -z "$FILE_PATH" ] || [ ! -f "$FILE_PATH" ]; then
  exit 0
fi

check_rust() {
  if grep -nE 'tracing::(info|debug|warn|error)!\(.*plaintext|tracing::(info|debug|warn|error)!\(.*message_content|tracing::(info|debug|warn|error)!\(.*decrypted' "$1" 2>/dev/null; then
    echo "WARNING: Possible plaintext logging detected in $1" >&2
    echo "This violates the threat model. Run security-auditor before committing." >&2
    exit 2
  fi
  if grep -nE 'println!\(.*password|println!\(.*secret|println!\(.*token' "$1" 2>/dev/null; then
    echo "WARNING: Possible secret logging in $1" >&2
    exit 2
  fi
}

check_typescript() {
  if grep -nE 'console\.(log|info|debug|warn)\(.*decrypt|console\.(log|info|debug|warn)\(.*plaintext|console\.(log|info|debug|warn)\(.*password|console\.(log|info|debug|warn)\(.*secret|console\.(log|info|debug|warn)\(.*token' "$1" 2>/dev/null; then
    echo "WARNING: Possible plaintext/secret logging detected in $1" >&2
    echo "This violates the threat model. Remove before committing." >&2
    exit 2
  fi
}

case "$FILE_PATH" in
  *.rs) check_rust "$FILE_PATH" ;;
  *.ts|*.tsx|*.js|*.jsx) check_typescript "$FILE_PATH" ;;
esac

exit 0
