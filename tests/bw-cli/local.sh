#!/usr/bin/env bash
# Starts a throwaway Vaultwarden (HTTPS with a self-signed cert, SQLite, SMTP sink for
# email 2FA) from a local build and runs run.sh against it.
#
#   cargo build --features sqlite
#   tests/bw-cli/local.sh
#
# Environment:
#   VW_BIN   Vaultwarden binary. Default: target/debug/vaultwarden (or target/release/vaultwarden if only that exists)
#   VW_PORT  HTTPS port. Default: 8443
#   SMTP_PORT  Port for the SMTP sink. Default: 2525
# Everything else (BW_BIN, SCENARIOS, ...) is passed on to run.sh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
VW_PORT="${VW_PORT:-8443}"
SMTP_PORT="${SMTP_PORT:-2525}"

if [[ -z "${VW_BIN:-}" ]]; then
    VW_BIN="${REPO_DIR}/target/debug/vaultwarden"
    [[ -x "${VW_BIN}" ]] || VW_BIN="${REPO_DIR}/target/release/vaultwarden"
fi
[[ -x "${VW_BIN}" ]] || { echo "No vaultwarden binary found, run: cargo build --features sqlite"; exit 1; }

TMP="$(mktemp -d)"
PIDS=()
cleanup() {
    for pid in "${PIDS[@]}"; do kill "${pid}" 2> /dev/null || true; done
    rm -rf "${TMP}"
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
    -addext subjectAltName=DNS:localhost,IP:127.0.0.1 \
    -keyout "${TMP}/key.pem" -out "${TMP}/cert.pem" 2> /dev/null

node "${SCRIPT_DIR}/smtp-sink.mjs" "${SMTP_PORT}" "${TMP}/mail" > "${TMP}/smtp.log" 2>&1 &
PIDS+=($!)

DATA_FOLDER="${TMP}/data" \
    DOMAIN="https://localhost:${VW_PORT}" \
    ROCKET_ADDRESS=127.0.0.1 \
    ROCKET_PORT="${VW_PORT}" \
    ROCKET_TLS="{certs=\"${TMP}/cert.pem\",key=\"${TMP}/key.pem\"}" \
    WEB_VAULT_ENABLED=false \
    SIGNUPS_ALLOWED=true \
    I_REALLY_WANT_VOLATILE_STORAGE=true \
    SMTP_HOST=127.0.0.1 \
    SMTP_PORT="${SMTP_PORT}" \
    SMTP_SECURITY=off \
    SMTP_FROM=vaultwarden@example.com \
    LOGIN_RATELIMIT_MAX_BURST=100 \
    "${VW_BIN}" > "${TMP}/vaultwarden.log" 2>&1 &
PIDS+=($!)

for _ in $(seq 60); do
    curl -fsk "https://localhost:${VW_PORT}/alive" > /dev/null 2>&1 && break
    sleep 1
done
curl -fsk "https://localhost:${VW_PORT}/alive" > /dev/null || { cat "${TMP}/vaultwarden.log"; exit 1; }

# Talking to localhost through an HTTP(S) proxy does not work; bw would use one if set
unset HTTPS_PROXY https_proxy HTTP_PROXY http_proxy GLOBAL_AGENT_HTTPS_PROXY GLOBAL_AGENT_HTTP_PROXY

status=0
VW_URL="https://localhost:${VW_PORT}" MAIL_DIR="${TMP}/mail" NODE_EXTRA_CA_CERTS="${TMP}/cert.pem" \
    "${SCRIPT_DIR}/run.sh" || status=$?

if [[ "${status}" -ne 0 ]]; then
    echo
    echo "==> vaultwarden log (errors/warnings)"
    grep -E '\]\[(ERROR|WARN)\]' -A2 "${TMP}/vaultwarden.log" | tail -60 || true
fi
exit "${status}"
