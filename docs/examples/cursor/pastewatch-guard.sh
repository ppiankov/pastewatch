#!/bin/bash
# Cursor preToolUse hook: enforce pastewatch MCP tools for files with secrets
#
# Protocol: exit 0 = allow, exit 2 = block
#   stdout JSON: {"permission": "allow"} or {"permission": "deny", "agent_message": "..."}
#
# Configuration:
#   PW_SEVERITY — severity threshold for blocking (default: "high")
#   Must match the --min-severity flag on your MCP server registration.

PW_SEVERITY="${PW_SEVERITY:-high}"

deny() {
  local msg="$1"
  printf '{"permission": "deny", "agent_message": "%s"}\n' "$msg"
  exit 2
}

# Fail-open if pastewatch-cli not installed
command -v pastewatch-cli &>/dev/null || exit 0

input=$(cat)
tool=$(echo "$input" | jq -r '.tool_name // empty')
file_path=$(echo "$input" | jq -r '.tool_input.file_path // .tool_input.filePath // empty')

# Only check Read, Write tools
case "$tool" in
  Read|Write) ;;
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

# --- WRITE: Check for pastewatch placeholders in content ---
if [ "$tool" = "Write" ]; then
  content=$(echo "$input" | jq -r '.tool_input.content // empty')
  if [ -n "$content" ] && echo "$content" | grep -qE '__PW_[A-Z][A-Z0-9_]*_[0-9]+__'; then
    deny "BLOCKED: content contains pastewatch placeholders (__PW_...__). Use pastewatch_write_file to resolve placeholders back to real values."
  fi
fi

# --- READ/WRITE: Scan the file on disk for secrets ---
[ ! -f "$file_path" ] && exit 0

pastewatch-cli scan --check --fail-on-severity "$PW_SEVERITY" --file "$file_path" >/dev/null 2>&1
scan_exit=$?

if [ "$scan_exit" -eq 6 ]; then
  case "$tool" in
    Read)
      deny "BLOCKED: $file_path contains secrets. You MUST use pastewatch_read_file instead. Do NOT use cat or any workaround."
      ;;
    Write)
      deny "BLOCKED: $file_path contains secrets on disk. You MUST use pastewatch_write_file instead."
      ;;
  esac
fi

# Clean file or scan error — allow
exit 0
