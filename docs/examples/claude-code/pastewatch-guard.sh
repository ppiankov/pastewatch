#!/bin/bash
# Claude Code PreToolUse hook: enforce pastewatch MCP tools for files with secrets
#
# Protocol: exit 0 = allow, exit 2 = block
#   stdout = message shown to Claude
#   stderr = notification shown to the human
#
# Install:
#   1. Copy to ~/.claude/hooks/pastewatch-guard.sh
#   2. chmod +x ~/.claude/hooks/pastewatch-guard.sh
#   3. Add the hook matcher to ~/.claude/settings.json (see settings.json in this directory)
#
# Configuration:
#   PW_SEVERITY - severity threshold for blocking (default: "high")
#   Must match the --min-severity flag on your MCP server registration.
#   Example: PW_SEVERITY=medium for stricter enforcement.

PW_SEVERITY="${PW_SEVERITY:-high}"

# --- Session check ---
# Only enforce if pastewatch MCP is running in THIS Claude Code session.
# Hooks and MCP are both children of the same Claude process.
# If MCP is not running, allow native tools (fail-open).
_claude_pid=${PPID:-0}
pgrep -P "$_claude_pid" -qf 'pastewatch-cli mcp' 2>/dev/null || exit 0

input=$(cat)
tool=$(echo "$input" | jq -r '.tool_name // empty')
file_path=$(echo "$input" | jq -r '.tool_input.file_path // .tool_input.filePath // empty')

# --- BASH: Scan command arguments for inline secrets ---
if [ "$tool" = "Bash" ]; then
  bash_command=$(echo "$input" | jq -r '.tool_input.command // empty')
  [ -z "$bash_command" ] && exit 0

  # Fail-open if pastewatch-cli not installed
  command -v pastewatch-cli &>/dev/null || exit 0

  # Scan the full command string for secrets
  pastewatch-cli guard --quiet --fail-on-severity "$PW_SEVERITY" "$bash_command" >/dev/null 2>&1
  guard_exit=$?

  if [ "$guard_exit" -ne 0 ]; then
    echo "BLOCKED: command contains inline secrets. Do NOT paste credentials, DSNs, or API keys into shell commands. Use environment variables or config files instead."
    echo "Blocked: inline secrets in Bash command" >&2
    exit 2
  fi
  exit 0
fi

# Only check Read, Write, Edit tools
case "$tool" in
  Read|Write|Edit) ;;
  *) exit 0 ;;
esac

# Skip if no file path
[ -z "$file_path" ] && exit 0

# Skip binary/non-text files
case "$file_path" in
  *.png|*.jpg|*.jpeg|*.gif|*.ico|*.bmp|*.webp|*.svg) exit 0 ;;
  *.woff|*.woff2|*.ttf|*.eot|*.otf) exit 0 ;;
  *.zip|*.tar|*.gz|*.bz2|*.xz|*.7z|*.rar) exit 0 ;;
  *.exe|*.dll|*.so|*.dylib|*.a|*.o|*.class|*.pyc) exit 0 ;;
  *.pdf|*.doc|*.docx|*.xls|*.xlsx) exit 0 ;;
  *.mp3|*.mp4|*.wav|*.avi|*.mov|*.mkv) exit 0 ;;
  *.sqlite|*.db) exit 0 ;;
esac

# Skip .git internals
echo "$file_path" | grep -qF '/.git/' && exit 0

# --- PATH PROTECTION: Block access to sensitive directories ---
case "$file_path" in
  "$HOME/.openclaw/"*|"$HOME/.openclaw")
    echo "BLOCKED: $file_path is inside a protected directory. Use pastewatch MCP tools instead."
    echo "Blocked: protected directory - use pastewatch MCP tools" >&2
    exit 2 ;;
esac

# --- WRITE: Check for pastewatch placeholders in content ---
if [ "$tool" = "Write" ]; then
  content=$(echo "$input" | jq -r '.tool_input.content // empty')
  if [ -n "$content" ] && echo "$content" | grep -qE '__PW_[A-Z][A-Z0-9_]*_[0-9]+__'; then
    echo "BLOCKED: content contains pastewatch placeholders (__PW_...__). Use pastewatch_write_file to resolve placeholders back to real values."
    echo "Blocked: pastewatch placeholders in Write" >&2
    exit 2
  fi
fi

# Fail-open if pastewatch-cli not installed
command -v pastewatch-cli &>/dev/null || exit 0

# WO-526@v3: Edit/Write decisions compare proposed content with findings on disk.
if [ "$tool" = "Edit" ] || [ "$tool" = "Write" ]; then
  printf '%s' "$input" | pastewatch-cli guard-mutation --fail-on-severity "$PW_SEVERITY" >/dev/null
  if [ $? -ne 0 ]; then
    echo "BLOCKED: proposed mutation changes protected content. Use pastewatch_read_file and pastewatch_write_file."
    echo "Blocked: protected content in mutation" >&2
    exit 2
  fi
  exit 0
fi

# Read remains a whole-file decision. Only scan existing files.
[ ! -f "$file_path" ] && exit 0

# Scan file at configured severity threshold
pastewatch-cli scan --check --fail-on-severity "$PW_SEVERITY" --file "$file_path" >/dev/null 2>&1
scan_exit=$?

if [ "$scan_exit" -eq 6 ]; then
  echo "BLOCKED: $file_path contains secrets. You MUST use pastewatch_read_file instead. Do NOT use python3, cat, or any workaround."
  echo "Blocked: secrets in Read target - use pastewatch_read_file" >&2
  exit 2
fi

# Clean file or scan error - allow native tool
exit 0
