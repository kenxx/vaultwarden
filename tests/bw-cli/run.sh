#!/usr/bin/env bash
# End-to-end test of a Vaultwarden server with the official Bitwarden CLI (`bw`):
#   config server -> login -> unlock -> create item -> list -> get password
#   -> lock -> logout
#
# Environment:
#   VW_URL       Server URL (must be https://, the bw CLI refuses plain http). Default: https://localhost:8000
#   BW_EMAIL     Account email.    Default: bw-e2e@example.com
#   BW_PASSWORD  Master password.  Default: Bw-E2e-Test-Password-1
#   BW_REGISTER  1 = register the account first (needs SIGNUPS_ALLOWED=true). Default: 0
#   BW_BIN       bw command to use. Default: `bw` if on PATH, otherwise `npx -y @bitwarden/cli`
#   NODE_EXTRA_CA_CERTS  Set this to your CA / self-signed cert if the server cert is not publicly trusted.
set -euo pipefail

VW_URL="${VW_URL:-https://localhost:8000}"
BW_EMAIL="${BW_EMAIL:-bw-e2e@example.com}"
export BW_PASSWORD="${BW_PASSWORD:-Bw-E2e-Test-Password-1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -n "${BW_BIN:-}" ]]; then
    read -r -a BW <<< "${BW_BIN}"
elif command -v bw > /dev/null; then
    BW=(bw)
else
    BW=(npx -y @bitwarden/cli)
fi

# Isolated CLI state, so this never touches the user's own bw login
export BITWARDENCLI_APPDATA_DIR
BITWARDENCLI_APPDATA_DIR="$(mktemp -d)"
trap 'rm -rf "${BITWARDENCLI_APPDATA_DIR}"' EXIT

PASS=0
FAIL=0
pass() { echo "  [PASS] $1"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL + 1)); }
step() { echo; echo "==> $1"; }
# --nointeraction: fail instead of prompting (e.g. for the master password when locked)
bw() { "${BW[@]}" --nointeraction "$@"; }
status_of() { bw status --raw | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>console.log(JSON.parse(d).status))'; }
expect_status() {
    local got
    got="$(status_of)"
    if [[ "${got}" == "$1" ]]; then pass "status is '$1'"; else fail "status is '${got}', expected '$1'"; fi
}

if [[ "${VW_URL}" != https://* ]]; then
    echo "WARNING: ${VW_URL} is not https. Recent bw CLI versions refuse non-https servers (InsecureUrlNotAllowedError)."
fi

echo "bw version: $("${BW[@]}" --version)"
echo "server:     ${VW_URL}"
echo "account:    ${BW_EMAIL}"

if [[ "${BW_REGISTER:-0}" == "1" ]]; then
    step "register"
    if node "${SCRIPT_DIR}/register.mjs" "${VW_URL}" "${BW_EMAIL}" "${BW_PASSWORD}"; then pass "account registered"; else fail "register"; exit 1; fi
fi

step "config server"
if bw config server "${VW_URL}" > /dev/null; then pass "server set"; else fail "bw config server"; exit 1; fi
expect_status "unauthenticated"

step "login"
if bw login "${BW_EMAIL}" --passwordenv BW_PASSWORD --raw > /dev/null; then pass "login"; else fail "login"; exit 1; fi
expect_status "locked"

step "unlock"
if BW_SESSION="$(bw unlock --passwordenv BW_PASSWORD --raw)" && [[ -n "${BW_SESSION}" ]]; then
    export BW_SESSION
    pass "unlock returned a session key"
else
    fail "unlock"; exit 1
fi
expect_status "unlocked"

step "create item"
ITEM_NAME="bw-e2e-item-$(date +%s)-$$"
ITEM_PASSWORD="E2e-Secret-$RANDOM-$RANDOM"
ITEM_JSON="$(node -e '
    const [name, password] = process.argv.slice(1);
    console.log(JSON.stringify({
        type: 1, name, notes: "created by tests/bw-cli/run.sh", favorite: false,
        login: { username: "e2e-user", password, uris: [{ match: null, uri: "https://example.com" }] },
    }));' "${ITEM_NAME}" "${ITEM_PASSWORD}")"
if ITEM_ID="$(bw encode <<< "${ITEM_JSON}" | bw create item | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>console.log(JSON.parse(d).id))')" && [[ -n "${ITEM_ID}" ]]; then
    pass "created item ${ITEM_ID}"
else
    fail "bw create item"; exit 1
fi

step "sync"
if bw sync > /dev/null; then pass "sync"; else fail "sync"; fi

step "list items"
LIST="$(bw list items --search "${ITEM_NAME}")"
COUNT="$(node -e 'console.log(JSON.parse(process.argv[1]).length)' "${LIST}")"
if [[ "${COUNT}" == "1" ]]; then pass "list found the item"; else fail "list returned ${COUNT} items for ${ITEM_NAME}"; fi

step "get password"
GOT="$(bw get password "${ITEM_ID}")"
if [[ "${GOT}" == "${ITEM_PASSWORD}" ]]; then pass "password matches"; else fail "password mismatch"; fi
GOT="$(bw get username "${ITEM_ID}")"
if [[ "${GOT}" == "e2e-user" ]]; then pass "username matches"; else fail "username mismatch (got '${GOT}')"; fi

step "delete item (cleanup)"
if bw delete item "${ITEM_ID}" --permanent > /dev/null; then pass "item deleted"; else fail "bw delete item"; fi

step "lock"
if bw lock > /dev/null; then pass "lock"; else fail "lock"; fi
unset BW_SESSION
expect_status "locked"
if bw list items > /dev/null 2>&1; then fail "list items still works while locked"; else pass "vault is unreadable while locked"; fi

step "logout"
if bw logout > /dev/null; then pass "logout"; else fail "logout"; fi
expect_status "unauthenticated"

echo
echo "Result: ${PASS} passed, ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]]
