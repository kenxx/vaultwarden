// Minimal SMTP server that accepts every message and writes it to a directory,
// so email 2FA codes can be read by the tests. Not for anything but local testing.
//
// Usage: node smtp-sink.mjs <port> <mail-dir>
import fs from "node:fs";
import net from "node:net";
import path from "node:path";

const [port, mailDir] = process.argv.slice(2);
if (!port || !mailDir) {
    console.error("Usage: node smtp-sink.mjs <port> <mail-dir>");
    process.exit(2);
}
fs.mkdirSync(mailDir, { recursive: true });
let counter = 0;

net.createServer((socket) => {
    let buffer = "";
    let inData = false;
    let envelope = [];
    let data = [];
    const reply = (line) => socket.write(`${line}\r\n`);
    reply("220 bw-cli-e2e smtp sink");

    socket.on("data", (chunk) => {
        buffer += chunk.toString("utf8");
        let idx;
        while ((idx = buffer.indexOf("\r\n")) >= 0) {
            const line = buffer.slice(0, idx);
            buffer = buffer.slice(idx + 2);
            if (inData) {
                if (line === ".") {
                    inData = false;
                    const file = path.join(mailDir, `${Date.now()}-${process.pid}-${counter++}.eml`);
                    fs.writeFileSync(file, `${envelope.join("\r\n")}\r\n\r\n${data.join("\r\n")}`);
                    envelope = [];
                    data = [];
                    reply("250 OK");
                } else {
                    data.push(line.startsWith("..") ? line.slice(1) : line);
                }
                continue;
            }
            const cmd = line.slice(0, 4).toUpperCase();
            if (cmd === "EHLO") {
                reply("250-bw-cli-e2e");
                reply("250 8BITMIME");
            } else if (cmd === "HELO") {
                reply("250 bw-cli-e2e");
            } else if (cmd === "MAIL" || cmd === "RCPT") {
                envelope.push(line);
                reply("250 OK");
            } else if (cmd === "DATA") {
                inData = true;
                reply("354 End data with <CR><LF>.<CR><LF>");
            } else if (cmd === "QUIT") {
                reply("221 Bye");
                socket.end();
            } else {
                // RSET, NOOP, ...
                reply("250 OK");
            }
        }
    });
    socket.on("error", () => {});
}).listen(Number(port), "127.0.0.1", () => console.log(`smtp sink on 127.0.0.1:${port}, writing to ${mailDir}`));
