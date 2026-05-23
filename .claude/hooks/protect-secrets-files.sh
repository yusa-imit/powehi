#!/bin/bash
# PreToolUse hook: Block editing of secret/sensitive files
# Input: JSON via stdin with tool_input.file_path (Edit/Write tools)
# Exit 0 = allow, Exit 2 = block

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('tool_input',{}).get('file_path',''))" 2>/dev/null)

if [ -z "$FILE_PATH" ]; then
  exit 0
fi

case "$FILE_PATH" in
  *.env|*.env.*|*/secrets/*|*credentials*|*private_key*|*secret_key*|*.pem|*.key)
    echo "BLOCKED: cannot edit sensitive file $FILE_PATH" >&2
    exit 2
    ;;
  */.claude/settings.local.json)
    # Local settings are personal, allow editing
    exit 0
    ;;
esac

exit 0
