# Security (protocol v5)

[Русская версия](SECURITY_RU.md)

What the tunnel protects against since v5, how, and what is still up to you.

## What was wrong in v4

| # | v4 problem | Impact |
|---|---|---|
| 1 | The cloud function checked the token only in `HELLO`; `PING`/`SYNC` and stream frames were processed for **any** WebSocket connection. | Anyone who knew the gateway URL got the **service account's IAM token** and the adapter's connection ID from a single `PING` — and could open TCP connections to your `target` (a free open proxy on your bill). |
| 2 | `CONNECT` to `/_adapter` set `adapterConnId = connId` unconditionally. | Anyone could take over the adapter slot and receive your helpers' traffic (or just break the tunnel). |
| 3 | `DISCONNECT` of any `/_adapter` connection broadcast `PEER_GONE` to every helper. | One-shot remote DoS. |
| 4 | Adapter and helpers accepted any frame arriving on their WebSocket. | With an IAM token (see 1) one could inject `OPEN`/`DATA`/`PEER_GONE` via `wsSend`. |
| 5 | `/conn-ids` accepted `Bearer <authToken>`, and the function sent it the IAM token in a header — often over plain HTTP. | Shared secret and IAM token leaked to anyone on the path to the VPS; response could be forged. |
| 6 | With `AUTH_TOKEN` unset the function compared against the string `"undefined"`. | Password-less tunnel on misconfiguration. |
| 7 | Payload went through the function / gateway in the clear. | The cloud provider could read the traffic. |

## How v5 works

Secrets:

* **`authToken`** — shared by the function, adapter and helpers (`AUTH_TOKEN` env in the function). At least 16 characters.
* **`e2eKey`** — shared **only** by the adapter and helpers, **never** given to the function. Optional but strongly recommended.

Separate keys are derived per purpose with HMAC-SHA256 (see `adapter-and-helper/internal/secure/secure.go`; the JS and C# implementations are checked against it with shared test vectors in `testdata/vectors.json`).

1. **HELLO** carries an HMAC over a timestamp and the role (`adapter`/`helper`), not the secret itself. Allowed clock skew: 5 minutes. Bad HELLO → `HELLO_ERR` and the connection is closed.
2. **Connection ticket.** Every later client→function message ends with a 16-byte ticket `HMAC(role, connectionId)`. The connection ID is supplied by API Gateway and cannot be spoofed, so a ticket is useless on any other connection. Messages without a valid ticket are dropped and the connection closed. The function no longer **changes state** (adapter slot, helper list) on unauthenticated messages.
3. **Function frames are signed.** Everything the function sends to a client (`HELLO_OK`, `PONG`, `PEER_CONN`, `PEER_GONE`, relay-mode `OPEN_FAIL`/`RST`) is signed and bound to the recipient's connection ID. Clients drop anything unsigned — an IAM token no longer lets anyone inject control frames.
4. **Helper↔adapter stream frames** are always encrypted and authenticated (AES-256-CTR + HMAC-SHA256; the direction is part of the MAC so reflected frames are rejected). The header (type, stream ID, seq) stays readable for relay routing but is MAC-protected. The key comes from `e2eKey`, or from `authToken` if unset (then the function could, in theory, decrypt — so set `e2eKey`).
5. **`/conn-ids`**: timestamped HMAC request auth (no secret on the wire), signed response, no IAM token. Without a valid signature the endpoint answers `404`. Even over plain HTTP nothing secret leaks and responses can't be forged.
6. **Config validation**: short secrets, `e2eKey == authToken`, `ws://` to a non-loopback host, empty `AUTH_TOKEN` in the function → refuse to start. Missing reconnect settings get safe defaults.
7. **MAUI client** keeps `authToken` and `e2eKey` in the platform secret store (`SecureStorage`: Keychain / Android Keystore / DPAPI), migrating values saved by older versions. Platforms without `SecureStorage` (Linux GTK) keep using `Preferences`.

## Still up to you

* **Generate secrets** randomly: `openssl rand -hex 32` (two different ones for `authToken` and `e2eKey`).
* **Set `e2eKey`** on the adapter and every helper. Without it the function (i.e. the cloud provider) holds the key to your traffic.
* **Service account.** The function's IAM token is still handed to authenticated adapters/helpers (direct `wsSend` needs it). Keep the bridge in a **dedicated cloud folder** containing nothing but this function and gateway, and grant the account no other roles.
* **Inside the tunnel** use a protocol with its own authentication (VLESS/Xray, Shadowsocks, SOCKS with a password). All helpers with the right secrets are fully trusted: they share keys and can open connections to your `target`.
* **Helpers listen on loopback only** (`127.x.x.x`); otherwise anyone on the LAN can use your tunnel (the Go helper warns about a non-loopback address).
* **MAUI config export** (`btf://…`) contains both secrets — share it over private channels only.
* **Clocks** must be in sync (±5 minutes), otherwise `HELLO` is rejected with `clock skew`.

## Known residual risks

* Whoever can decrypt TLS to API Gateway (or the provider itself) can replay a captured `HELLO` within 5 minutes and obtain the IAM token. The provider issues that token anyway; for anyone else this requires breaking TLS.
* Traffic volume and timing, connection IDs and frame headers are visible to the provider — encryption hides content, not the fact that a tunnel is used.
* Helpers trust each other (shared keys): a helper with valid secrets can disturb another helper's streams.

## Verifying

```bash
cd adapter-and-helper && go test ./...                 # Go vectors, tamper/reflection rejection
node --test tests/cloud-function.test.js               # function vectors + v4 attacks
dotnet run -c Release --project tests/maui-services    # C# (MAUI services) vectors
(cd tests/e2e && npm install) && SIM_INSTANCES=3 tests/e2e/run.sh   # full local e2e incl. attacks
```
