# bw CLI end-to-end tests

Runs the official Bitwarden CLI (`bw`) against Vaultwarden. Every scenario registers its own
fresh account, logs in, then does a full vault round trip:

`unlock` → `create item` → `sync` → `list items` → `get password` / `get username` → `delete item` → `lock` → `logout`

| Scenario        | What it checks |
|-----------------|----------------|
| `password`      | No 2FA. A wrong password is refused with a clear message. |
| `totp`          | Authenticator app: no code → "Code is required", wrong code refused, valid code works. |
| `email`         | Email 2FA: `bw` triggers the email, the code from it works, a wrong code is refused. Needs `MAIL_DIR`. |
| `webauthn+totp` | WebAuthn checked through the identity API with a software security key (good, tampered and malformed responses). `bw` has no WebAuthn support, so it logs in with TOTP. |
| `webauthn-only` | `bw` password login fails with "No providers available for this client" (same as the official server). `bw login --apikey` works and skips 2FA. |

## Quick start (local build)

`local.sh` starts a throwaway Vaultwarden (HTTPS with a self-signed cert, SQLite, a local SMTP
sink for email codes) and runs all scenarios:

```bash
cargo build --features sqlite
tests/bw-cli/local.sh
```

It needs `node` (18+), `openssl` and `curl`. If `bw` is not on `PATH`, `npx -y @bitwarden/cli` is used.
On failure the server's errors/warnings are printed.

## Against another server

```bash
VW_URL=https://vault.example.com tests/bw-cli/run.sh
```

The server needs `SIGNUPS_ALLOWED=true` (test accounts are created) and a `DOMAIN` that matches
`VW_URL`, or WebAuthn will fail. Set `MAIL_DIR` only if that server sends mail to `smtp-sink.mjs`.

| Variable    | Default |
|-------------|---------|
| `VW_URL`    | `https://localhost:8000` |
| `BW_BIN`    | `bw`, else `npx -y @bitwarden/cli` |
| `MAIL_DIR`  | unset (email scenario skipped) |
| `SCENARIOS` | `password totp email webauthn+totp webauthn-only` |

## Things these tests ran into

- **`bw` refuses plain `http://` servers**, `localhost` included:
  `Error: Insecure URL not allowed. All URLs must use HTTPS.` Use HTTPS. For a self-signed
  certificate, set `NODE_EXTRA_CA_CERTS=/path/to/cert.pem`.
- **`bw` cannot do WebAuthn.** On an account whose only 2FA method is WebAuthn, `bw login`
  stops with "No providers available for this client". Add TOTP or email 2FA as a second method,
  or log in with your personal API key (`bw login --apikey`, then `bw unlock`).
- When `HTTPS_PROXY` is set, `bw` also sends localhost requests through the proxy (`ECONNRESET`).
- Each TOTP time step is accepted only once, so the tests wait for a new 30s step when needed.

## Files

- `run.sh`: the scenarios
- `local.sh`: starts a test server, then runs `run.sh`
- `vw.mjs`: helper for what `bw` cannot do: registration (client-side key derivation), 2FA
  enrollment, TOTP codes, a software WebAuthn security key, reading email codes
- `smtp-sink.mjs`: minimal SMTP server that writes mails to a directory
