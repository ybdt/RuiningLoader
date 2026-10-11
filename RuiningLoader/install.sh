#!/usr/bin/env bash
# Usage: ./auto-install.sh --ax <path_to_adaptix_server>

set -euo pipefail

RESET="\033[0m"
BOLD="\033[1m"
CYAN="\033[1;36m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
DIM="\033[2m"

info()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()    { echo -e "${GREEN}[+]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
rewrite(){ echo -e "${YELLOW}[~]${RESET} $*"; }
err()   { echo -e "${RED}[✗]${RESET} ${BOLD}$*${RESET}" >&2; }

AX_PATH=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ax)
            AX_PATH="${2:-}"
            if [[ -z "$AX_PATH" ]]; then
                err "--ax requires a path argument."
                exit 1
            fi
            shift 2
            ;;
        *)
            err "Unknown argument: $1"
            echo -e "Usage: $0 ${CYAN}--ax${RESET} <path_to_adaptix_server>"
            exit 1
            ;;
    esac
done

if [[ -z "$AX_PATH" ]]; then
    echo -e "Usage: $0 ${CYAN}--ax${RESET} <path_to_adaptix_server>"
    exit 1
fi

if [[ ! -d "$AX_PATH" ]]; then
    err "Adaptix server path not found: $AX_PATH"
    exit 1
fi

PROFILE="${AX_PATH}/profile.yaml"

if [[ ! -f "$PROFILE" ]]; then
    err "profile.yaml not found at: $PROFILE"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

info "Building main project..."
make -C "$SCRIPT_DIR" --no-print-directory -s
ok "Main build complete."

info "Updating root path in pl_agent.go..."
sed -i "s|filepath\.Abs(\"[^\"]*\")|filepath.Abs(\"$SCRIPT_DIR\")|" "$SCRIPT_DIR/src_service/pl_agent.go"
ok "root path set to: ${DIM}$SCRIPT_DIR${RESET}"

info "Building src_service..."
make -C "$SCRIPT_DIR/src_service" --no-print-directory -s
mkdir -p "$SCRIPT_DIR/src_service/dist"
ok "src_service build complete."

info "Marking crystal_palace tools as executable..."
for bin in link piclink coffparse disassemble; do
    BIN_PATH="$SCRIPT_DIR/crystal_palace/$bin"
    if [[ -f "$BIN_PATH" ]]; then
        chmod +x "$BIN_PATH"
        echo -e "    ${GREEN}[+]${RESET} chmod +x ${DIM}crystal_palace/$bin${RESET}"
    else
        echo -e "    ${YELLOW}[!]${RESET} crystal_palace/$bin not found, skipping."
    fi
done

EXTENDER_FULL_PATH="$SCRIPT_DIR/src_service/dist/config.yaml"

if [[ ! -f "$EXTENDER_FULL_PATH" ]]; then
    err "Extender config not found at: $EXTENDER_FULL_PATH"
    err "Ensure the src_service build produced a dist/ directory."
    exit 1
fi

if grep -qF "$EXTENDER_FULL_PATH" "$PROFILE"; then
    rewrite "Removing existing entry from profile.yaml (will rewrite)..."
    grep -vF "$EXTENDER_FULL_PATH" "$PROFILE" > "${PROFILE}.tmp" && mv "${PROFILE}.tmp" "$PROFILE"
fi

awk -v new_entry="    - \"${EXTENDER_FULL_PATH}\"" '
/^  extenders:/ { in_extenders=1 }
in_extenders && /^  [a-zA-Z]/ && !/^  extenders:/ {
    if (last_extender_line) {
        print last_extender_line
        print new_entry
        last_extender_line=""
        in_extenders=0
    }
}
in_extenders && /^\s+- / {
    if (last_extender_line) print last_extender_line
    last_extender_line=$0
    next
}
{
    if (last_extender_line && !in_extenders) {
        print last_extender_line
        last_extender_line=""
    }
    print
}
END {
    if (last_extender_line) {
        print last_extender_line
        print new_entry
    }
}
' "$PROFILE" > "${PROFILE}.tmp" && mv "${PROFILE}.tmp" "$PROFILE"

ok "Added extender to profile.yaml: ${DIM}$EXTENDER_FULL_PATH${RESET}"

echo ""
echo -e "${GREEN}${BOLD}[✓] StealthPalace installation complete.${RESET}"