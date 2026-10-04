# bw CLI end-to-end test

Runs the official Bitwarden CLI against a Vaultwarden server through a full session:

`config server` → `login` → `unlock` → `create item` → `sync` → `list items` → `get password` / `get username` → `delete item` → `lock` → `logout`

The CLI state goes in a temporary directory, so your own `bw` login is not touched.

## Requirements

- Node.js 18+ (used by `register.mjs` and for JSON parsing)
- `bw` on `PATH`, or let the script use `npx -y @bitwarden/cli`
- **An HTTPS server URL.** Recent `bw` releases refuse plain `http://` servers, including `localhost`
  (`Error: Insecure URL not allowed. All URLs must use HTTPS.`). For a self-signed certificate, point
  `NODE_EXTRA_CA_CERTS` at it.

## Usage

```bash
# Existing account
VW_URL=https://vault.example.com BW_EMAIL=me@example.com BW_PASSWORD='...' ./run.sh

# Fresh local server: create the test account first (needs SIGNUPS_ALLOWED=true)
NODE_EXTRA_CA_CERTS=./cert.pem VW_URL=https://localhost:8000 BW_REGISTER=1 ./run.sh
```

| Variable      | Default                       |
|---------------|-------------------------------|
| `VW_URL`      | `https://localhost:8000`      |
| `BW_EMAIL`    | `bw-e2e@example.com`          |
| `BW_PASSWORD` | `Bw-E2e-Test-Password-1`      |
| `BW_REGISTER` | `0` (`1` = register first)    |
| `BW_BIN`      | `bw`, else `npx -y @bitwarden/cli` |

The script exits non-zero if any check fails. The test item it creates is permanently deleted at the end.

If you run it behind an HTTP(S) proxy (`HTTPS_PROXY`), `bw` sends localhost requests through the proxy too,
so unset it for local servers.
