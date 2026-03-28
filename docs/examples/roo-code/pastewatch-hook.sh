#!/bin/bash
# Cline PreToolUse hook: enforce pastewatch MCP tools for files with secrets
#
# Protocol: JSON stdout
#   {"cancel": true, "errorMessage": "..."} = block
#   {"cancel": false} = allow
#   Non-zero exit without valid JSON = allow (fail-open)
#
# Install:
#   1. Save as your Cline PreToolUse hook (location depends on Cline version)
#   2. chmod +x pastewatch-hook.sh
#   3. Register MCP server in Cline settings (see mcp-config.json in this directory)
#
# Configuration:
#   PW_SEVERITY - severity threshold for blocking (default: "high")
#   Must match the --min-severity flag on your MCP server registration.
#   Example: PW_SEVERITY=medium for stricter enforcement.
#
# Note: This is the pastewatch-only hook. If you have other PreToolUse guards
# (bash safety, doc blocking, etc.), combine them into a single hook script.

PW_SEVERITY="${PW_SEVERITY:-high}"

block() {
  local msg="$1"
  printf '{"cancel": true, "errorMessage": "%s"}\n' "$msg"
  exit 0
}

input=$(cat)
tool_name=$(echo "$input" | jq -r '.preToolUse.toolName // empty')

# --- Session check ---
# Only enforce if pastewatch MCP is running in THIS Cline session.
# Cline runs hooks as children of its node process - check siblings.
_pw_mcp_ok=false
_cline_pid=${PPID:-0}
if command -v pastewatch-cli &>/dev/null && pgrep -P "$_cline_pid" -qf 'pastewatch-cli mcp' 2>/dev/null; then
  _pw_mcp_ok=true
fi

# If MCP not available, allow everything (fail-open)
$_pw_mcp_ok || { echo '{"cancel": false}'; exit 0; }

# ====== BASH GUARD (execute_command) ======
if [ "$tool_name" = "execute_command" ]; then
  command=$(echo "$input" | jq -r '.preToolUse.parameters.command // empty')
  [ -z "$command" ] && { echo '{"cancel": false}'; exit 0; }

  # Block commands that leak secrets via file access (cat .env, grep passwords, etc.)
  guard_output=$(pastewatch-cli guard "$command" 2>&1)
  if [ $? -ne 0 ]; then
    block "$guard_output"
  fi
fi

# ====== FILE GUARD (read_file, write_to_file, edit_file) ======
if [ "$tool_name" = "read_file" ] || [ "$tool_name" = "write_to_file" ] || [ "$tool_name" = "edit_file" ]; then
  pw_path=$(echo "$input" | jq -r '.preToolUse.parameters.path // empty')

  if [ -n "$pw_path" ]; then
    # Skip binary files
    case "$pw_path" in
      *.png|*.jpg|*.jpeg|*.gif|*.ico|*.bmp|*.webp|*.svg|*.woff|*.woff2|*.ttf|\
      *.zip|*.tar|*.gz|*.bz2|*.exe|*.dll|*.so|*.dylib|*.pdf|*.mp3|*.mp4|\
      *.sqlite|*.db|*.pyc|*.o|*.a|*.class)
        ;;  # skip binary - fall through to allow
      *)
        # Check for placeholder leak in write content
        if [ "$tool_name" = "write_to_file" ]; then
          pw_content=$(echo "$input" | jq -r '.preToolUse.parameters.content // empty')
          if [ -n "$pw_content" ] && echo "$pw_content" | grep -qE '__PW\{[A-Z][A-Z0-9_]*_[0-9]+\}__'; then
            block "BLOCKED: content contains pastewatch placeholders. Use pastewatch_write_file to resolve them."
          fi
        fi

        # Scan file on disk for secrets
        if [ -f "$pw_path" ] && command -v pastewatch-cli &>/dev/null; then
          if ! echo "$pw_path" | grep -qF '/.git/'; then
            pastewatch-cli scan --check --fail-on-severity "$PW_SEVERITY" --file "$pw_path" >/dev/null 2>&1
            if [ $? -eq 6 ]; then
              case "$tool_name" in
                read_file) block "BLOCKED: $pw_path contains secrets. You MUST use pastewatch_read_file instead. Do NOT use any workaround." ;;
                write_to_file) block "BLOCKED: $pw_path contains secrets. You MUST use pastewatch_write_file instead. Do NOT delete the file or use any workaround." ;;
                edit_file) block "BLOCKED: $pw_path contains secrets. You MUST use pastewatch_read_file then pastewatch_write_file. Do NOT use any workaround." ;;
              esac
            fi
          fi
        fi
        ;;
    esac
  fi
fi

# Allow by default
echo '{"cancel": false}'
exit 0
