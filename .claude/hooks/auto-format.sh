#!/bin/bash
# PostToolUse hook: Auto-format edited files
# Input: stdin JSON with tool_input.file_path

INPUT=$(cat)
EDITED=$(echo "$INPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('tool_input',{}).get('file_path',''))" 2>/dev/null)

if [ -z "$EDITED" ] || [ ! -f "$EDITED" ]; then
  exit 0
fi

case "$EDITED" in
  *.rs)   cargo fmt -- "$EDITED" 2>/dev/null ;;
  *.ts|*.tsx|*.js|*.jsx) npx biome format --write "$EDITED" 2>/dev/null ;;
  *.tf)   terraform fmt "$EDITED" 2>/dev/null ;;
esac

exit 0
