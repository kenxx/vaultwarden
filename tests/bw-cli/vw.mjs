// Test helper for tests/bw-cli/run.sh. Does the things the `bw` CLI cannot do itself:
// register accounts, enroll 2FA providers, generate TOTP codes, act as a WebAuthn
// security key and read email 2FA codes from the SMTP sink.
//
// All per-account data (secrets, the WebAuthn private key, ...) is kept in the JSON
// state file given with --state.
//
// Usage: node vw.mjs <command> --server <url> --state <file> [options]
//   setup --email <e> --password <p> [--totp] [--webauthn] [--email-2fa --mail-dir <d>]
//         Register the account, enable the requested 2FA providers and create a user API key
//   totp              Print a TOTP code that the server has not seen yet (waits for a new 30s step if needed)
//   mail-code --mail-dir <d>   Print the newest email 2FA code sent to the account
//   webauthn-login [--tamper|--garbage]  Password + WebAuthn login through the identity API (what the web
//                     vault does); --tamper sends a bad signature, --garbage a malformed response, both must fail
//   get <key>         Print a value from the state file
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

// ----- arguments / state -----
const [command, ...rest] = process.argv.slice(2);
const args = {};
for (let i = 0; i < rest.length; i++) {
    if (!rest[i].startsWith("--")) {
        (args._ ??= []).push(rest[i]);
    } else if (rest[i + 1] === undefined || rest[i + 1].startsWith("--")) {
        args[rest[i].slice(2)] = true;
    } else {
        args[rest[i].slice(2)] = rest[++i];
    }
}
const server = (args.server ?? "").replace(/\/$/, "");
const statePath = args.state;
if (!command || !server || !statePath) {
    console.error("Usage: node vw.mjs <command> --server <url> --state <file> [options]");
    process.exit(2);
}
const state = fs.existsSync(statePath) ? JSON.parse(fs.readFileSync(statePath, "utf8")) : {};
const saveState = () => fs.writeFileSync(statePath, JSON.stringify(state, null, 2), { mode: 0o600 });

const die = (msg) => {
    console.error(msg);
    process.exit(1);
};

// ----- encoding helpers -----
const b64 = (buf) => Buffer.from(buf).toString("base64");
const b64url = (buf) => Buffer.from(buf).toString("base64url");
const sha256 = (data) => crypto.createHash("sha256").update(data).digest();

function base32Decode(str) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = "";
    for (const c of str.replace(/=+$/, "").toUpperCase()) {
        const v = alphabet.indexOf(c);
        if (v < 0) throw new Error(`Invalid base32 character '${c}'`);
        bits += v.toString(2).padStart(5, "0");
    }
    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
    return Buffer.from(bytes);
}

// Minimal CBOR encoder, enough for a WebAuthn attestation object and a COSE key
function cbor(value) {
    const head = (major, n) => {
        if (n < 24) return Buffer.from([(major << 5) | n]);
        if (n < 0x100) return Buffer.from([(major << 5) | 24, n]);
        if (n < 0x10000) return Buffer.from([(major << 5) | 25, n >> 8, n & 0xff]);
        const b = Buffer.alloc(5);
        b[0] = (major << 5) | 26;
        b.writeUInt32BE(n, 1);
        return b;
    };
    if (Number.isInteger(value)) return value >= 0 ? head(0, value) : head(1, -1 - value);
    if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
    if (typeof value === "string") {
        const s = Buffer.from(value, "utf8");
        return Buffer.concat([head(3, s.length), s]);
    }
    if (value instanceof Map) {
        const parts = [head(5, value.size)];
        for (const [k, v] of value) parts.push(cbor(k), cbor(v));
        return Buffer.concat(parts);
    }
    throw new Error(`Cannot CBOR-encode ${typeof value}`);
}

// ----- Bitwarden client crypto -----
const KDF_ITERATIONS = 600000;

function hkdfExpand(prk, info, length) {
    const out = [];
    let prev = Buffer.alloc(0);
    for (let i = 1; Buffer.concat(out).length < length; i++) {
        prev = crypto.createHmac("sha256", prk).update(Buffer.concat([prev, Buffer.from(info), Buffer.from([i])])).digest();
        out.push(prev);
    }
    return Buffer.concat(out).subarray(0, length);
}

// EncString type 2: AesCbc256_HmacSha256_B64
function encrypt(data, encKey, macKey) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-cbc", encKey, iv);
    const ct = Buffer.concat([cipher.update(data), cipher.final()]);
    const mac = crypto.createHmac("sha256", macKey).update(Buffer.concat([iv, ct])).digest();
    return `2.${b64(iv)}|${b64(ct)}|${b64(mac)}`;
}

function masterPasswordHash(email, password) {
    const masterKey = crypto.pbkdf2Sync(password, email, KDF_ITERATIONS, 32, "sha256");
    return { masterKey, hash: b64(crypto.pbkdf2Sync(masterKey, password, 1, 32, "sha256")) };
}

// ----- HTTP -----
async function request(method, url, { json, form, token } = {}) {
    // Like the web vault; without it the server logs an error for the missing header
    const headers = { "Bitwarden-Client-Version": "2026.9.0" };
    let body;
    if (json !== undefined) {
        headers["Content-Type"] = "application/json";
        body = JSON.stringify(json);
    } else if (form !== undefined) {
        headers["Content-Type"] = "application/x-www-form-urlencoded";
        body = new URLSearchParams(form).toString();
    }
    if (token) headers.Authorization = `Bearer ${token}`;
    const res = await fetch(`${server}${url}`, { method, headers, body });
    const text = await res.text();
    let data = null;
    try {
        data = text ? JSON.parse(text) : null;
    } catch {
        data = text;
    }
    return { status: res.status, ok: res.ok, data };
}

async function api(method, url, opts) {
    const res = await request(method, url, opts);
    if (!res.ok) die(`${method} ${url} failed: HTTP ${res.status} ${JSON.stringify(res.data)}`);
    return res.data;
}

// Password grant, as the web vault does it. `twoFactor` = { provider, token }
function passwordGrant(twoFactor) {
    const form = {
        grant_type: "password",
        username: state.email,
        password: state.masterPasswordHash,
        scope: "api offline_access",
        client_id: "web",
        deviceType: "9",
        deviceIdentifier: (state.deviceId ??= crypto.randomUUID()),
        deviceName: "bw-cli-e2e",
    };
    if (twoFactor) {
        form.twoFactorProvider = String(twoFactor.provider);
        form.twoFactorToken = twoFactor.token;
    }
    return request("POST", "/identity/connect/token", { form });
}

// ----- TOTP -----
function totpAt(secret, step) {
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(BigInt(step));
    const hmac = crypto.createHmac("sha1", base32Decode(secret)).update(counter).digest();
    const offset = hmac[hmac.length - 1] & 0xf;
    const code = (hmac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
    return code.toString().padStart(6, "0");
}

// The server rejects a code from a time step it has already accepted, so wait for a fresh step
async function freshTotp() {
    let step = Math.floor(Date.now() / 30000);
    if (state.totpLastStep !== undefined && step <= state.totpLastStep) {
        const waitMs = (state.totpLastStep + 1) * 30000 - Date.now() + 500;
        console.error(`(waiting ${Math.ceil(waitMs / 1000)}s for a new TOTP time step)`);
        await new Promise((r) => setTimeout(r, waitMs));
        step = Math.floor(Date.now() / 30000);
    }
    state.totpLastStep = step;
    saveState();
    return totpAt(state.totpSecret, step);
}

// ----- WebAuthn software authenticator -----
const origin = new URL(server).origin;

function webauthnCreate(options) {
    const rpId = options.rp.id;
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = publicKey.export({ format: "jwk" });
    const credId = crypto.randomBytes(32);
    const coseKey = cbor(
        new Map([
            [1, 2], // kty: EC2
            [3, -7], // alg: ES256
            [-1, 1], // crv: P-256
            [-2, Buffer.from(jwk.x, "base64url")],
            [-3, Buffer.from(jwk.y, "base64url")],
        ]),
    );
    const credIdLen = Buffer.alloc(2);
    credIdLen.writeUInt16BE(credId.length);
    const authData = Buffer.concat([
        sha256(rpId),
        Buffer.from([0x41]), // flags: user present + attested credential data
        Buffer.alloc(4), // sign count 0
        Buffer.alloc(16), // AAGUID
        credIdLen,
        credId,
        coseKey,
    ]);
    const attestationObject = cbor(
        new Map([
            ["fmt", "none"],
            ["attStmt", new Map()],
            ["authData", authData],
        ]),
    );
    const clientDataJSON = Buffer.from(
        JSON.stringify({ type: "webauthn.create", challenge: options.challenge, origin, crossOrigin: false }),
    );
    state.webauthn = {
        credId: b64url(credId),
        privateKey: privateKey.export({ type: "pkcs8", format: "pem" }),
        signCount: 0,
    };
    saveState();
    return {
        id: b64url(credId),
        rawId: b64url(credId),
        type: "public-key",
        response: { attestationObject: b64url(attestationObject), clientDataJSON: b64url(clientDataJSON) },
    };
}

function webauthnGet(options, tamper) {
    const wa = state.webauthn;
    if (!wa) die("No WebAuthn credential in state");
    if (!options.allowCredentials?.some((c) => c.id === wa.credId)) die("Server did not offer our WebAuthn credential");
    wa.signCount += 1;
    saveState();
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(wa.signCount);
    const authData = Buffer.concat([sha256(options.rpId), Buffer.from([0x01]), counter]);
    const clientDataJSON = Buffer.from(
        JSON.stringify({ type: "webauthn.get", challenge: options.challenge, origin, crossOrigin: false }),
    );
    const signature = crypto.sign("sha256", Buffer.concat([authData, sha256(clientDataJSON)]), wa.privateKey);
    if (tamper) signature[signature.length - 1] ^= 0xff;
    return JSON.stringify({
        id: wa.credId,
        rawId: wa.credId,
        type: "public-key",
        extensions: {},
        response: {
            authenticatorData: b64url(authData),
            clientDataJson: b64url(clientDataJSON),
            signature: b64url(signature),
            userHandle: null,
        },
    });
}

// ----- Email sink -----
function latestMailCode(mailDir, since = 0) {
    if (!fs.existsSync(mailDir)) return null;
    const files = fs
        .readdirSync(mailDir)
        .map((f) => path.join(mailDir, f))
        .filter((f) => fs.statSync(f).mtimeMs >= since)
        .sort((a, b) => fs.statSync(b).mtimeMs - fs.statSync(a).mtimeMs);
    for (const file of files) {
        const mail = fs.readFileSync(file, "utf8");
        const to = mail.match(/^RCPT TO:\s*<([^>]+)>/im)?.[1]?.toLowerCase();
        if (to !== state.email) continue;
        // Plain text part: "Your two-step verification code is: 123456"
        const code = mail.match(/verification code is:\s*(\d+)/i)?.[1];
        if (code) return code;
    }
    return null;
}

async function waitForMailCode(mailDir, since) {
    for (let i = 0; i < 50; i++) {
        const code = latestMailCode(mailDir, since);
        if (code) return code;
        await new Promise((r) => setTimeout(r, 200));
    }
    die(`No 2FA email for ${state.email} in ${mailDir}`);
}

// ----- commands -----
async function setup() {
    state.email = String(args.email).trim().toLowerCase();
    state.password = String(args.password);
    const { masterKey, hash } = masterPasswordHash(state.email, state.password);
    state.masterPasswordHash = hash;
    saveState();

    // Register
    const encKey = hkdfExpand(masterKey, "enc", 32);
    const macKey = hkdfExpand(masterKey, "mac", 32);
    const userKey = crypto.randomBytes(64);
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    await api("POST", "/identity/accounts/register", {
        json: {
            email: state.email,
            name: "bw-cli e2e",
            masterPasswordHash: hash,
            masterPasswordHint: null,
            key: encrypt(userKey, encKey, macKey),
            kdf: 0,
            kdfIterations: KDF_ITERATIONS,
            keys: {
                publicKey: b64(publicKey.export({ type: "spki", format: "der" })),
                encryptedPrivateKey: encrypt(
                    privateKey.export({ type: "pkcs8", format: "der" }),
                    userKey.subarray(0, 32),
                    userKey.subarray(32),
                ),
            },
        },
    });
    console.log(`registered ${state.email}`);

    const login = await passwordGrant();
    if (!login.ok) die(`Login after register failed: HTTP ${login.status} ${JSON.stringify(login.data)}`);
    const token = login.data.access_token;
    const userId = JSON.parse(Buffer.from(token.split(".")[1], "base64url")).sub;
    const auth = { masterPasswordHash: hash };

    // A user API key, to test `bw login --apikey`
    const apiKey = await api("POST", "/api/accounts/api-key", { json: auth, token });
    state.clientId = `user.${userId}`;
    state.clientSecret = apiKey.apiKey;
    saveState();

    if (args.totp) {
        const { key } = await api("POST", "/api/two-factor/get-authenticator", { json: auth, token });
        state.totpSecret = key;
        const code = await freshTotp();
        await api("POST", "/api/two-factor/authenticator", { json: { ...auth, key, token: code }, token });
        console.log("enabled TOTP");
    }

    if (args.webauthn) {
        const options = await api("POST", "/api/two-factor/get-webauthn-challenge", { json: auth, token });
        const deviceResponse = webauthnCreate(options);
        await api("PUT", "/api/two-factor/webauthn", {
            json: { ...auth, id: 1, name: "bw-cli-e2e virtual key", deviceResponse },
            token,
        });
        console.log("enabled WebAuthn");
    }

    if (args["email-2fa"]) {
        if (!args["mail-dir"]) die("--email-2fa needs --mail-dir");
        const since = Date.now() - 1000;
        await api("POST", "/api/two-factor/send-email", { json: { ...auth, email: state.email }, token });
        const code = await waitForMailCode(args["mail-dir"], since);
        await api("PUT", "/api/two-factor/email", { json: { ...auth, email: state.email, token: code }, token });
        console.log("enabled email 2FA");
    }

    const providers = await api("GET", "/api/two-factor", { token });
    console.log(`enabled providers: ${JSON.stringify(providers.data.map((p) => p.type))}`);
}

async function webauthnLogin() {
    // Step 1: password only, the server must answer with a WebAuthn challenge
    const first = await passwordGrant();
    const challenge = first.data?.TwoFactorProviders2?.["7"];
    if (first.status !== 400 || !challenge) {
        die(`Expected a WebAuthn 2FA challenge, got HTTP ${first.status} ${JSON.stringify(first.data)}`);
    }
    // Step 2: answer the challenge with the security key
    const token = args.garbage ? "not-a-webauthn-response" : webauthnGet(challenge, Boolean(args.tamper));
    const second = await passwordGrant({ provider: 7, token });
    if (args.tamper || args.garbage) {
        if (second.ok) die("Server accepted an invalid WebAuthn response");
        console.log(`rejected as expected: HTTP ${second.status} ${second.data?.message ?? JSON.stringify(second.data)}`);
        return;
    }
    if (!second.ok || !second.data?.access_token) {
        die(`WebAuthn login failed: HTTP ${second.status} ${JSON.stringify(second.data)}`);
    }
    console.log("WebAuthn login succeeded");
}

switch (command) {
    case "setup":
        await setup();
        break;
    case "totp":
        console.log(await freshTotp());
        break;
    case "mail-code":
        console.log(await waitForMailCode(args["mail-dir"], Number(args.since ?? 0)));
        break;
    case "webauthn-login":
        await webauthnLogin();
        break;
    case "get":
        if (state[args._?.[0]] === undefined) die(`No '${args._?.[0]}' in state`);
        console.log(state[args._[0]]);
        break;
    default:
        die(`Unknown command '${command}'`);
}
