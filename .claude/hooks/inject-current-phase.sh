#!/bin/bash
# UserPromptSubmit hook: Inject current phase status into Claude context
# Stdout is passed as additionalContext to Claude

PHASE_DIR="docs/phases"
CURRENT_PHASE=""

for dir in "$PHASE_DIR"/phase-*/; do
  if [ -f "$dir/STATUS.md" ]; then
    status=$(head -5 "$dir/STATUS.md" 2>/dev/null)
    if echo "$status" | grep -qi "in.progress\|active\|current"; then
      CURRENT_PHASE="$dir"
      break
    fi
  fi
done

if [ -n "$CURRENT_PHASE" ] && [ -f "${CURRENT_PHASE}STATUS.md" ]; then
  echo "[Current Phase: $(basename "$CURRENT_PHASE")]"
  head -20 "${CURRENT_PHASE}STATUS.md"
fi

exit 0
