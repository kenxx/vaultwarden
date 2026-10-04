#!/usr/bin/env bash
# End-to-end tests of a Vaultwarden server with the official Bitwarden CLI (`bw`).
#
# Every scenario registers its own fresh account (the server needs SIGNUPS_ALLOWED=true),
# logs in with `bw` and runs a full vault round trip:
#   unlock -> create item -> sync -> list -> get password/username -> delete -> lock -> logout
#
# Scenarios:
#   password        no 2FA; also wrong password
#   totp            authenticator app: missing code, wrong code, valid code
#   email           email 2FA codes (only when MAIL_DIR is set, see local.sh)
#   webauthn+totp   the CLI cannot do WebAuthn, so it must offer/use TOTP;
#                   WebAuthn itself is checked through the identity API with a software key
#   webauthn-only   the CLI must refuse password login cleanly, `bw login --apikey` must work
#
# Environment:
#   VW_URL     Server URL, must be https:// (the bw CLI refuses plain http). Default: https://localhost:8000
#   BW_BIN     bw command. Default: `bw` if on PATH, otherwise `npx -y @bitwarden/cli`
#   MAIL_DIR   Directory the SMTP sink writes to (smtp-sink.mjs). Enables the email scenarios.
#   SCENARIOS  Space separated subset of the scenarios above. Default: all
#   NODE_EXTRA_CA_CERTS  Your CA / self-signed cert if the server cert is not publicly trusted.
set -uo pipefail

VW_URL="${VW_URL:-https://localhost:8000}"
SCENARIOS="${SCENARIOS:-password totp email webauthn+totp webauthn-only}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -n "${BW_BIN:-}" ]]; then
    read -r -a BW <<< "${BW_BIN}"
elif command -v bw > /dev/null; then
    BW=(bw)
else
    BW=(npx -y @bitwarden/cli)
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT
RUN_ID="$(date +%s)-$$"
PASSWORD="Bw-E2e-Test-Password-1"
export BW_PASSWORD="${PASSWORD}"

PASS=0
FAIL=0
FAILED_CHECKS=()
pass() { echo "  [PASS] $1"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL + 1)); FAILED_CHECKS+=("${SCENARIO}: $1"); }
step() { echo "  -- $1"; }
# Runs a command that must succeed (its stdout is discarded)
check() { local name="$1"; shift; if "$@" > /dev/null; then pass "${name}"; else fail "${name}"; fi; }

# --nointeraction: fail instead of prompting (for the master password, a 2FA code, ...)
bw() { "${BW[@]}" --nointeraction "$@"; }
vw() { node "${SCRIPT_DIR}/vw.mjs" "$@" --server "${VW_URL}" --state "${STATE}"; }
json_field() { node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>{const v=JSON.parse(d)[process.argv[1]];console.log(typeof v==="object"?JSON.stringify(v):v)})' "$1"; }
status_is() { [[ "$(bw status | json_field status)" == "$1" ]]; }

# Runs a command that must fail, and checks its output contains the expected message
OUT=""
expect_fail() {
    local name="$1" expected="$2"
    shift 2
    if OUT="$("$@" 2>&1)"; then
        fail "${name}: succeeded but should have failed"
    elif [[ "${OUT}" != *"${expected}"* ]]; then
        fail "${name}: expected '${expected}', got: ${OUT}"
    else
        pass "${name} (\"${expected}\")"
    fi
}

# New account + clean bw CLI state for a scenario. Extra args go to `vw.mjs setup`.
new_account() {
    STATE="${WORK_DIR}/${SCENARIO}.json"
    EMAIL="bw-e2e-${SCENARIO//+/-}-${RUN_ID}@example.com"
    export BITWARDENCLI_APPDATA_DIR="${WORK_DIR}/bw-${SCENARIO}"
    mkdir -p "${BITWARDENCLI_APPDATA_DIR}"
    if vw setup --email "${EMAIL}" --password "${PASSWORD}" "$@" | sed 's/^/     /'; then
        pass "account set up (${EMAIL})"
    else
        fail "account setup"
        return 1
    fi
    check "bw config server" bw config server "${VW_URL}"
    check "status is unauthenticated" status_is unauthenticated
}

# Everything after a successful login
vault_round_trip() {
    check "status is locked after login" status_is locked

    step "unlock"
    if BW_SESSION="$(bw unlock --passwordenv BW_PASSWORD --raw)" && [[ -n "${BW_SESSION}" ]]; then
        export BW_SESSION
        pass "unlock returned a session key"
    else
        fail "unlock"
        return 1
    fi
    check "status is unlocked" status_is unlocked

    step "create / list / get"
    local name="bw-e2e-item-${RUN_ID}-${SCENARIO}" secret="E2e-Secret-${RANDOM}-${RANDOM}" item_id
    item_id="$(node -e '
        const [name, password] = process.argv.slice(1);
        console.log(JSON.stringify({
            type: 1, name, notes: "created by tests/bw-cli/run.sh", favorite: false,
            login: { username: "e2e-user", password, uris: [{ match: null, uri: "https://example.com" }] },
        }));' "${name}" "${secret}" | bw encode | bw create item | json_field id)"
    if [[ -n "${item_id}" && "${item_id}" != "undefined" ]]; then pass "created item"; else fail "bw create item"; return 1; fi
    check "sync" bw sync
    check "list finds the item" test "$(bw list items --search "${name}" | node -e 'let d="";process.stdin.on("data",c=>d+=c).on("end",()=>console.log(JSON.parse(d).length))')" = 1
    check "get password matches" test "$(bw get password "${item_id}")" = "${secret}"
    check "get username matches" test "$(bw get username "${item_id}")" = "e2e-user"
    check "delete item" bw delete item "${item_id}" --permanent

    step "lock / logout"
    check "lock" bw lock
    unset BW_SESSION
    check "status is locked" status_is locked
    expect_fail "vault unreadable while locked" "Vault is locked" bw list items
    check "logout" bw logout
    check "status is unauthenticated" status_is unauthenticated
}

login_ok() {
    if OUT="$(bw login "$@" 2>&1)"; then pass "bw login $*"; else fail "bw login $*: ${OUT}"; return 1; fi
}

scenario_password() {
    new_account || return
    expect_fail "wrong password" "Username or password is incorrect" bw login "${EMAIL}" "Not-The-Password-1"
    login_ok "${EMAIL}" --passwordenv BW_PASSWORD && vault_round_trip
}

scenario_totp() {
    new_account --totp || return
    expect_fail "login without a 2FA code" "Code is required" bw login "${EMAIL}" --passwordenv BW_PASSWORD
    expect_fail "login with a wrong TOTP code" "Invalid TOTP code" bw login "${EMAIL}" --passwordenv BW_PASSWORD --method 0 --code 000000
    login_ok "${EMAIL}" --passwordenv BW_PASSWORD --method 0 --code "$(vw totp)" && vault_round_trip
}

scenario_email() {
    if [[ -z "${MAIL_DIR:-}" ]]; then
        echo "  (skipped: MAIL_DIR not set)"
        return
    fi
    new_account --email-2fa --mail-dir "${MAIL_DIR}" || return
    local since=$(($(date +%s) * 1000))
    # Without a code the CLI asks the server to send one, then stops
    expect_fail "login without a code sends the email" "Code is required" bw login "${EMAIL}" --passwordenv BW_PASSWORD --method 1
    local code
    if code="$(vw mail-code --mail-dir "${MAIL_DIR}" --since "${since}")"; then pass "2FA email received"; else fail "no 2FA email received"; return; fi
    expect_fail "login with a wrong email code" "Token is invalid" bw login "${EMAIL}" --passwordenv BW_PASSWORD --method 1 --code 00000000
    login_ok "${EMAIL}" --passwordenv BW_PASSWORD --method 1 --code "${code}" && vault_round_trip
}

scenario_webauthn_totp() {
    local extra=()
    [[ -n "${MAIL_DIR:-}" ]] && extra=(--email-2fa --mail-dir "${MAIL_DIR}")
    new_account --totp --webauthn "${extra[@]}" || return
    step "WebAuthn through the identity API (software security key)"
    check "WebAuthn login" vw webauthn-login
    if OUT="$(vw webauthn-login --tamper)" && [[ "${OUT}" == *"WebAuthn verification failed"* ]]; then
        pass "bad WebAuthn signature rejected with a readable error"
    else
        fail "bad WebAuthn signature: ${OUT}"
    fi
    if OUT="$(vw webauthn-login --garbage)" && [[ "${OUT}" == *"Invalid WebAuthn response"* ]]; then
        pass "malformed WebAuthn response rejected with a readable error"
    else
        fail "malformed WebAuthn response: ${OUT}"
    fi
    step "bw CLI (has no WebAuthn support, must use another provider)"
    # Forcing WebAuthn must fail with a message meant for people, not an internal error name
    if OUT="$(bw login "${EMAIL}" --passwordenv BW_PASSWORD --method 7 --code not-json 2>&1)"; then
        fail "bw login --method 7 succeeded with a junk code"
    elif [[ "${OUT}" =~ ^(Serde|Webauthn)\.?$ ]]; then
        fail "bw login --method 7 shows an internal error name: ${OUT}"
    else
        pass "bw login --method 7 with a junk code fails readably (\"${OUT}\")"
    fi
    login_ok "${EMAIL}" --passwordenv BW_PASSWORD --method 0 --code "$(vw totp)" && vault_round_trip
}

scenario_webauthn_only() {
    new_account --webauthn || return
    step "WebAuthn through the identity API (software security key)"
    check "WebAuthn login" vw webauthn-login
    step "bw CLI"
    # Same as with the official server: the CLI has no WebAuthn support
    expect_fail "password login is refused cleanly" "No providers available for this client" bw login "${EMAIL}" --passwordenv BW_PASSWORD
    # The supported way for the CLI: a personal API key skips 2FA
    export BW_CLIENTID BW_CLIENTSECRET
    BW_CLIENTID="$(vw get clientId)"
    BW_CLIENTSECRET="$(vw get clientSecret)"
    expect_fail "wrong API key secret" "Incorrect client_secret" env BW_CLIENTSECRET=wrong "${BW[@]}" --nointeraction login --apikey
    login_ok --apikey && vault_round_trip
    unset BW_CLIENTID BW_CLIENTSECRET
}

if [[ "${VW_URL}" != https://* ]]; then
    echo "WARNING: ${VW_URL} is not https. Recent bw CLI versions refuse non-https servers (InsecureUrlNotAllowedError)."
fi
echo "bw version: $("${BW[@]}" --version)"
echo "server:     ${VW_URL}"

for SCENARIO in ${SCENARIOS}; do
    echo
    echo "==> scenario: ${SCENARIO}"
    case "${SCENARIO}" in
        password) scenario_password ;;
        totp) scenario_totp ;;
        email) scenario_email ;;
        webauthn+totp) scenario_webauthn_totp ;;
        webauthn-only) scenario_webauthn_only ;;
        *) fail "unknown scenario" ;;
    esac
done

echo
echo "Result: ${PASS} passed, ${FAIL} failed"
for c in "${FAILED_CHECKS[@]}"; do echo "  FAILED: ${c}"; done
[[ "${FAIL}" -eq 0 ]]
