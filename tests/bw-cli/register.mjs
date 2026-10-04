// Registers a test account on a Vaultwarden server, doing the client-side
// key derivation the Bitwarden clients do (the `bw` CLI cannot register).
//
// Usage: node register.mjs <server-url> <email> <master-password>
import crypto from "node:crypto";

const [server, emailArg, password] = process.argv.slice(2);
if (!server || !emailArg || !password) {
    console.error("Usage: node register.mjs <server-url> <email> <master-password>");
    process.exit(2);
}

const email = emailArg.trim().toLowerCase();
const KDF_ITERATIONS = 600000;

const b64 = (buf) => Buffer.from(buf).toString("base64");

// HKDF-Expand only (no extract step), as used by the Bitwarden clients to stretch the master key
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

const masterKey = crypto.pbkdf2Sync(password, email, KDF_ITERATIONS, 32, "sha256");
const masterPasswordHash = b64(crypto.pbkdf2Sync(masterKey, password, 1, 32, "sha256"));
const stretchedEnc = hkdfExpand(masterKey, "enc", 32);
const stretchedMac = hkdfExpand(masterKey, "mac", 32);

const userKey = crypto.randomBytes(64);
const encryptedUserKey = encrypt(userKey, stretchedEnc, stretchedMac);

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const publicKeyDer = publicKey.export({ type: "spki", format: "der" });
const privateKeyDer = privateKey.export({ type: "pkcs8", format: "der" });
const encryptedPrivateKey = encrypt(privateKeyDer, userKey.subarray(0, 32), userKey.subarray(32));

const res = await fetch(`${server.replace(/\/$/, "")}/identity/accounts/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
        email,
        name: "bw-cli e2e",
        masterPasswordHash,
        masterPasswordHint: null,
        key: encryptedUserKey,
        kdf: 0,
        kdfIterations: KDF_ITERATIONS,
        keys: { publicKey: b64(publicKeyDer), encryptedPrivateKey },
    }),
});

if (!res.ok) {
    console.error(`Registration failed: HTTP ${res.status} ${await res.text()}`);
    process.exit(1);
}
console.log(`Registered ${email}`);
