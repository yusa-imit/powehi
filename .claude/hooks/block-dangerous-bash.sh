#!/bin/bash
# PreToolUse hook: Block dangerous bash commands
# Input: JSON via stdin with tool_input.command
# Exit 0 = allow, Exit 2 = block (stderr -> Claude feedback)

INPUT=$(cat)
CMD=$(echo "$INPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('tool_input',{}).get('command',''))" 2>/dev/null)

if [ -z "$CMD" ]; then
  exit 0
fi

deny() {
  echo "BLOCKED: $1" >&2
  exit 2
}

# Destructive filesystem operations
echo "$CMD" | grep -qE 'rm\s+-rf\s+/' && deny "rm -rf / detected"
echo "$CMD" | grep -qE 'rm\s+-rf\s+\*' && deny "rm -rf * detected"

# Piped curl-to-shell (supply chain risk)
echo "$CMD" | grep -qE 'curl.*\|.*sh' && deny "piped curl-to-shell"
echo "$CMD" | grep -qE 'wget.*\|.*sh' && deny "piped wget-to-shell"

# Secrets in commands
echo "$CMD" | grep -qE 'AWS_SECRET|HETZNER_TOKEN|PRIVATE_KEY|SECRET_KEY' && deny "secret reference in command"

# Force push
echo "$CMD" | grep -qE 'git\s+push.*--force' && deny "force push"

# Ad-hoc crypto (should use audited libraries)
echo "$CMD" | grep -qE 'openssl\s+(genpkey|genrsa|enc)\s' && deny "ad-hoc crypto operation — use audited libraries"

# Dangerous git operations
echo "$CMD" | grep -qE 'git\s+reset\s+--hard' && deny "git reset --hard"
echo "$CMD" | grep -qE 'git\s+clean\s+-fd' && deny "git clean -fd"

exit 0
