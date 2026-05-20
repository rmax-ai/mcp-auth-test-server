#!/usr/bin/env bash
set -euo pipefail

# ─── MCP Auth Test Server ────────────────────────────────────────────
# Orchestrates multi-phase development via Codex CLI.
# Each phase: Codex creates/updates a GH issue -> implements -> commits -> writes handoff.
#
# Usage:
#   ./scripts/iterate.sh setup         # Create phase issues + labels on GitHub
#   ./scripts/iterate.sh all [from]    # Run all phases sequentially (with retry)
#   ./scripts/iterate.sh phase <N>     # Run a single phase
#   ./scripts/iterate.sh from <N>      # Resume from phase N onwards
#   ./scripts/iterate.sh status        # Show phase progress
#   ./scripts/iterate.sh handoff <N>   # Show handoff from phase N
# ──────────────────────────────────────────────────────────────────────

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_NAME="mcp-auth-test-server"
NVM_SETUP='export NVM_DIR="$HOME/.nvm" && [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"'

# ─── Phase definitions ────────────────────────────────────────────────
PHASES=(
  "1:Project scaffold:Set up project structure: pyproject.toml, README, AGENTS.md, Makefile, .gitignore, src/ layout, tests/ layout, empty FastAPI app with health endpoint. No external systems to mock."
  "2:Core MCP framework + No-Auth mode:JSON-RPC handler (base class), tool definitions (echo, ping), /mcp/no-auth endpoint. Tests with httpx TestClient. No external systems to mock."
  "3:Bearer Token auth:Static bearer token middleware, /mcp/bearer-token endpoint, 401 response with WWW-Authenticate header, configurable token. Mock: test tokens only."
  "4:Protected Resource Metadata (RFC 9728) + Auth Server Metadata (RFC 8414):/.well-known/oauth-protected-resource endpoint, /.well-known/oauth-authorization-server endpoint. All auth endpoints return correct WWW-Authenticate with resource_metadata on 401. Mock: discovery documents only."
  "5:OAuth 2.0 Authorization Code + PKCE (3-legged / v2):Full OAuth AS: /authorize (PKCE S256), /token (authorization_code grant), in-memory token store, /mcp/oauth-v2-auth-code endpoint. Mock: simulated browser consent."
  "6:OAuth 2.0 Client Credentials (2-legged / v2):/token (client_credentials grant), /mcp/oauth-v2-client-creds endpoint. Mock: client credentials only."
  "7:OAuth 2.1 (Full Spec):OAuth 2.1-specific AS with: S256 PKCE only (reject plain), no implicit grant, resource parameter (RFC 8707) validation, audience validation, iss parameter (RFC 9207). /mcp/oauth-v21 endpoint. Mock: OAuth 2.1 test client."
  "8:OAuth 1.0a (Legacy):OAuth 1.0a HMAC-SHA1 signature verification middleware, /mcp/oauth-v1 endpoint. Mock: test consumer key/secret."
  "9:Dynamic Client Registration (RFC 7591):/register endpoint, client metadata management, integration with OAuth 2.0 AS. Mock: registration payloads."
  "10:End-to-end tests + Test client:Comprehensive e2e test for every scheme, standalone test client script, test_all_schemes.sh. Mock: all previously defined mocks."
)

# ─── Utilities ────────────────────────────────────────────────────────

green()  { printf '\033[32m%s\033[0m\n' "$*"; }
blue()   { printf '\034[34m%s\033[0m\n' "$*"; }
red()    { printf '\033[31m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }

phase_num()    { echo "${1%%:*}"; }
phase_name()   { local p="${1#*:}"; echo "${p%:*}"; }
phase_desc()   { echo "${1##*:}"; }

require_codex() {
  if ! command -v codex &>/dev/null; then
    if ! eval "$NVM_SETUP" 2>/dev/null; then
      red "Error: nvm not found."
      exit 1
    fi
    if ! command -v codex &>/dev/null; then
      red "Error: codex CLI not found."
      exit 1
    fi
  fi
}

check_phase_range() {
  local n="$1"
  if [ "$n" -lt 1 ] || [ "$n" -gt "${#PHASES[@]}" ]; then
    red "Error: phase $n out of range (1-${#PHASES[@]})"
    exit 1
  fi
}

# ─── Labels / Issues ──────────────────────────────────────────────────

setup_labels() {
  blue "Setting up GitHub labels..."
  for label_info in \
    "status:backlog:5319e7:Not started, awaiting dependencies" \
    "status:ready:7aef7b:Dependencies met, ready to work" \
    "status:in-progress:fbca04:Codex is actively working" \
    "status:in-review:009800:Awaiting review and merge" \
    "status:done:e6e6e6:Completed and merged" \
    "status:blocked:d93f0b:Blocked by dependency"; do
    NAME=$(echo "$label_info" | cut -d: -f1-2)
    COLOR=$(echo "$label_info" | cut -d: -f3)
    DESC=$(echo "$label_info" | cut -d: -f4-)
    gh api "/repos/rmax-ai/$REPO_NAME/labels" --method POST \
      -f "name=$NAME" -f "color=$COLOR" -f "description=$DESC" 2>/dev/null || true
  done
  for label_info in \
    "epic:8250df:High-level feature or milestone" \
    "story:006b75:Individual work item under an epic"; do
    NAME=$(echo "$label_info" | cut -d: -f1)
    COLOR=$(echo "$label_info" | cut -d: -f2)
    DESC=$(echo "$label_info" | cut -d: -f3-)
    gh api "/repos/rmax-ai/$REPO_NAME/labels" --method POST \
      -f "name=$NAME" -f "color=$COLOR" -f "description=$DESC" 2>/dev/null || true
  done
  green "Labels ready."
}

# ─── Generate Codex prompt per phase ─────────────────────────────────

generate_prompt() {
  local num="$1"
  local name="$2"
  local desc="$3"
  local prev_handoff=""
  if [ "$num" -gt 1 ]; then
    local prev=$((num - 1))
    [ -f "$REPO_DIR/HANDOFF-${prev}.md" ] && prev_handoff=$(cat "$REPO_DIR/HANDOFF-${prev}.md")
  fi

  cat <<PROMPT
You are implementing Phase $num of the $REPO_NAME project.

## Project Context

$REPO_NAME is an MCP Auth Test Server — a FastAPI application that exposes
distinct MCP JSON-RPC endpoints for each major authentication scheme.

Tech stack: Python 3.12+, FastAPI, httpx (test client), pytest, ruff.

Repo: https://github.com/rmax-ai/$REPO_NAME
Working directory: $REPO_DIR

## GitHub Issue tracking
Before writing code: find the Phase $num issue, comment "Starting.", label it status:in-progress.
After completing: comment with a summary, close the issue, label status:done.

## Git workflow
- After every meaningful batch: git add -A && git commit -m "phase $num: <desc>" && git push
- Push early and often

## Handoff (CRITICAL)
When done, write HANDOFF-${num}.md at repo root with:
1. Every file created/modified with a brief description
2. Key design decisions
3. Architecture notes for the next phase
4. Any gotchas or incomplete items
5. What the next phase ($((num + 1))) should build on

## Testing
- Use pytest + httpx TestClient
- Every external system needs a realistic mock
- Tests must run offline

$( [ -n "$prev_handoff" ] && echo "## Previous handoff context\n\n$prev_handoff\n" || echo "(First phase — no previous handoff.)\n" )

## Phase $num: $name

$desc

## Acceptance Criteria
- [ ] All code is syntactically valid Python (ruff check)
- [ ] \`pytest tests/ -q -v\` passes
- [ ] HANDOFF-${num}.md written at repo root
- [ ] GitHub issue updated with summary and closed
- [ ] All code committed and pushed
PROMPT
}

# ─── Phase runner ─────────────────────────────────────────────────────

run_phase() {
  local num="$1"
  check_phase_range "$num"
  require_codex

  local phase_def="${PHASES[$((num - 1))]}"
  local name; name=$(phase_name "$phase_def")
  local desc; desc=$(phase_desc "$phase_def")

  blue "╔══════════════════════════════════════════╗"
  blue "║  Phase $num: $name"
  blue "╚══════════════════════════════════════════╝"

  local prompt_file
  prompt_file=$(mktemp /tmp/phase-${num}-prompt-XXXXXX.md)
  generate_prompt "$num" "$name" "$desc" > "$prompt_file"

  yellow "Prompt: $prompt_file"
  yellow "Launching Codex exec..."

  local max_retries=3
  local attempt=1
  while [ $attempt -le $max_retries ]; do
    echo "[$(date)] Phase $num — attempt $attempt/$max_retries"
    if eval "$NVM_SETUP" && cd "$REPO_DIR" && codex exec -C "$REPO_DIR" -s danger-full-access < "$prompt_file"; then
      green "✓ Phase $num completed."
      rm -f "$prompt_file"
      [ -f "$REPO_DIR/HANDOFF-${num}.md" ] && green "  Handoff: HANDOFF-${num}.md ✓" || yellow "  Warning: no handoff found."
      return 0
    else
      yellow "⚠ Attempt $attempt/$max_retries failed. Retrying in 15s..."
      sleep 15
      attempt=$((attempt + 1))
    fi
  done

  red "✗ Phase $num failed after $max_retries attempts."
  return 1
}

run_all() {
  local from="${1:-1}"
  check_phase_range "$from"
  for phase_def in "${PHASES[@]}"; do
    local num; num=$(phase_num "$phase_def")
    [ "$num" -lt "$from" ] && continue
    run_phase "$num" || { red "Stopped at Phase $num. Resume: $0 from $num"; exit 1; }
    cd "$REPO_DIR"
    [ -n "$(git status --porcelain)" ] && { git add -A && git commit -m "phase $num: cleanup" && git push || true; }
  done
  green "All phases complete!"
}

show_status() {
  blue "=== Issues ==="
  gh issue list --json number,title,labels,state 2>/dev/null | python3 -c "
import json, sys
try:
    for i in json.load(sys.stdin):
        labels = ', '.join(l['name'] for l in i.get('labels', []))
        print(f'  #{i[\"number\"]} [{labels:40s}] {i[\"title\"][:60]}')
except: print('  (no issues)')
" 2>/dev/null || true
  echo ""
  blue "=== Handoffs ==="
  for f in "$REPO_DIR"/HANDOFF-*.md; do
    [ -f "$f" ] && green "  $(basename "$f") — $(wc -l < "$f") lines"
  done
  echo ""
  blue "=== Git ==="
  cd "$REPO_DIR" && git log --oneline -5 2>/dev/null || true
  [ -n "$(git status --porcelain)" ] && { yellow "  Uncommitted:"; git status --short; } || green "  Clean"
}

show_handoff() {
  local num="$1"; check_phase_range "$num"
  local file="$REPO_DIR/HANDOFF-${num}.md"
  [ -f "$file" ] && cat "$file" || yellow "Not found: $file"
}

# ─── Main ─────────────────────────────────────────────────────────────

main() {
  local cmd="${1:-help}"; shift 2>/dev/null || true
  mkdir -p "$REPO_DIR/scripts"
  case "$cmd" in
    setup)
      setup_labels
      # Phase issues are created by Hermes directly via gh before running this script
      green "Labels created. Phase issues should be created manually via gh issue create."
      ;;
    all)      run_all "${1:-1}" ;;
    phase)    [ -z "${1:-}" ] && { red "Usage: $0 phase <N>"; exit 1; }; run_phase "$1" ;;
    from)     [ -z "${1:-}" ] && { red "Usage: $0 from <N>"; exit 1; }; run_all "$1" ;;
    status)   show_status ;;
    handoff)  [ -z "${1:-}" ] && { red "Usage: $0 handoff <N>"; exit 1; }; show_handoff "$1" ;;
    help|--help|-h)
      echo "Usage: $0 setup|all|phase|from|status|handoff"
      echo "  setup    — Create labels on GitHub"
      echo "  all [N]  — Run all phases (optionally starting at N)"
      echo "  phase N  — Run a single phase"
      echo "  from N   — Resume from phase N"
      echo "  status   — Show progress overview"
      echo "  handoff N— Show handoff doc from phase N";;
    *) red "Unknown: $cmd"; exit 1;;
  esac
}

main "$@"
