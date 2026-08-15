#!/bin/bash
set -euo pipefail

# Creates ONE single-use grant for personal-profile browser mode.
#
# Why this is a script the human runs and not a setting:
#
# Personal mode is a LARGER grant than shell access. evaluate_script against the
# live profile is arbitrary JavaScript in the origin of every authenticated
# session on this machine — mail, banking, cloud consoles. list_network_requests
# returns Authorization and Cookie headers unless --redactNetworkHeaders is set,
# and upload_file can read a local file into a web page as an exfiltration path.
# A config flag for that would be set-and-forget; this is per-use, expiring, and
# consumed on first use.
#
# bridge.mjs NEVER creates this file. It only reads it, validates it, and unlinks
# it. A second personal session requires running this again.
#
# Honest limit, also stated in SECURITY.md: shell_exec can forge this file. The
# gate stops an unattended model from drifting into personal mode and creates an
# audit record naming the nonce; it does not contain a model that has already
# decided to escalate.

DATA_DIR="${MAC_DEV_BRIDGE_DATA_DIR:-$HOME/Library/Application Support/MacDeveloperBridge}"
APPROVAL_FILE="${MAC_DEV_BRIDGE_PERSONAL_APPROVAL_FILE:-$DATA_DIR/PERSONAL_BROWSER_APPROVED}"
# 15 minutes is the ceiling bridge.mjs enforces at read time; anything longer is
# refused there, so there is no point offering it here.
MAX_TTL_SECONDS=900

usage() {
  cat <<'EOF'
Usage: approve-personal-browser.sh --provider KEY --url-pattern PATTERN [--url-pattern PATTERN ...] [--ttl SECONDS]

  --provider KEY      Provider key from the MCP server registry (e.g. "chrome").
  --url-pattern P     A URLPattern the browser is restricted to. Required, repeatable.
                      Enforcement happens inside the browser via --allowedUrlPattern,
                      not by string matching in the gateway.
  --ttl SECONDS       Grant lifetime, 30..900 seconds. Default 300.

The grant is single-use: the bridge unlinks it when it starts the personal-mode
provider. Run this again for another session.
EOF
}

PROVIDER=""
TTL=300
PATTERNS=()

while (( $# )); do
  case "$1" in
    --provider) PROVIDER="${2:-}"; shift 2 ;;
    --url-pattern) PATTERNS+=("${2:-}"); shift 2 ;;
    --ttl) TTL="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown argument: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n "$PROVIDER" ]] || { printf '--provider is required\n' >&2; exit 2; }
[[ "$PROVIDER" =~ ^[A-Za-z0-9_-]{1,32}$ ]] || { printf 'Invalid --provider (expected [A-Za-z0-9_-]{1,32})\n' >&2; exit 2; }
(( ${#PATTERNS[@]} )) || { printf 'At least one --url-pattern is required. An unrestricted personal browser is not an option this script offers.\n' >&2; exit 2; }
[[ "$TTL" =~ ^[0-9]+$ ]] || { printf 'Invalid --ttl\n' >&2; exit 2; }
(( TTL >= 30 )) || { printf -- '--ttl must be at least 30 seconds\n' >&2; exit 2; }
(( TTL <= MAX_TTL_SECONDS )) || { printf -- '--ttl must be at most %s seconds (bridge.mjs refuses anything longer at read time)\n' "$MAX_TTL_SECONDS" >&2; exit 2; }

for pattern in "${PATTERNS[@]}"; do
  [[ -n "$pattern" ]] || { printf 'Empty --url-pattern\n' >&2; exit 2; }
  case "$pattern" in
    *'"'*) printf 'A --url-pattern may not contain a double quote\n' >&2; exit 2 ;;
  esac
done

mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR" 2>/dev/null || true

NONCE="$(LC_ALL=C tr -dc '0-9a-f' </dev/urandom | head -c 32)"
[[ ${#NONCE} -eq 32 ]] || { printf 'Failed to generate a nonce\n' >&2; exit 1; }
EXPIRES_AT="$(date -u -v "+${TTL}S" '+%Y-%m-%dT%H:%M:%SZ')"

patterns_json=""
for pattern in "${PATTERNS[@]}"; do
  [[ -z "$patterns_json" ]] || patterns_json="$patterns_json, "
  patterns_json="$patterns_json\"$pattern\""
done

umask 077
cat >"$APPROVAL_FILE" <<EOF
{
  "nonce": "$NONCE",
  "expiresAt": "$EXPIRES_AT",
  "provider": "$PROVIDER",
  "allowedUrlPatterns": [$patterns_json]
}
EOF
chmod 600 "$APPROVAL_FILE"

printf 'Approved personal-profile browser mode for provider "%s".\n' "$PROVIDER"
printf '  grant file : %s\n' "$APPROVAL_FILE"
printf '  nonce      : %s   (recorded in the audit log for every call it authorises)\n' "$NONCE"
printf '  expires    : %s   (in %s seconds)\n' "$EXPIRES_AT" "$TTL"
printf '  url pattern: %s\n' "${PATTERNS[@]}"
printf '\nSingle use: the bridge unlinks this file when it starts the provider.\n'
printf 'Revoke before use with: rm -f "%s"\n' "$APPROVAL_FILE"
