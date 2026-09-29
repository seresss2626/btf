# Changelog

### What's new — 2026-05-15

This release is heavily optimised. The helper now reorders out-of-order frames on receive, pre-registers streams before sending `OPEN` (so the first DATA packets after `OPEN_OK` are never dropped), uses an async per-stream write queue so a slow local consumer no longer stalls every other stream, and does a graceful half-close on `FIN` so HTTP responses are no longer truncated. In practice: connections are established noticeably faster and the tunnel is significantly more stable, especially on mobile.
Also, multiple clients (helpers) can now connect to the same adapter/function simultaneously without interfering with each other. The previous "one adapter — one function — one client" limitation no longer applies.

### What's new — 2026-05-16

The adapter's HTTP endpoint path is now configurable via the new `http.path` setting in `adapter.config.yaml` (default `/conn-ids`), so you can rename it to something non-fingerprintable without editing source code. Correspondingly, the cloud function env var `ADAPTER_URL` has been renamed to `HTTP_URL` and its format has changed: it now expects the **full** URL of the adapter's endpoint (including the path), e.g. `https://your-server:8080/conn-ids`, instead of just the HTTP base. If you upgrade an existing deployment, update both the adapter config and the function's env variable. See [Customizing endpoint paths](README.md#customizing-endpoint-paths) for details.

### What's new — 2026-06-15

A round of stability and performance hardening across all components. **Backward compatibility is preserved** — wire protocol, config format, and cloud-function env vars are unchanged, so mixed-version setups keep working (updating all three together is still recommended).

Highlights: the Go helper no longer drops the first response bytes (pre-registers streams + reorders incoming frames); reorder buffers are capped so a lost frame resets the stream instead of hanging forever; `wsSend` calls have a timeout and the gRPC client recovers from transient startup errors; the upstream waits briefly before reconnecting; the adapter's public HTTP endpoint got timeouts and constant-time auth; the Cloud Function fans out to helpers in parallel; and the MAUI client's write-coalescing was rewritten to drop a quadratic copy and a blocking read.

### What's new — 2026-06-22

MAUI Client now easily builds for Linux and works on Linux. 

### What's new — 2026-07-14

More robustness fixes across the Go side and the MAUI client; **wire protocol and configs are unchanged**, so mixed-version setups keep working.

Highlights: TCP half-close is now handled correctly on the Go helper/adapter — a peer `FIN` shuts down the right direction (the local app sees EOF while reverse traffic keeps flowing), a clean local EOF sends `FIN` while a forwarding failure sends `RST`, and the socket is fully closed only once both directions finish (no more truncated reverse traffic); transient `wsSend` failures (timeouts, 429, 5xx) no longer evict a healthy peer — only a definitive "connection not found" does, and a compare-and-clear stops a slow/old failure from dropping a peer that just reconnected; a single lost frame no longer stalls a stream forever — a per-stream gap timer resets it if the missing frame doesn't arrive in time (both Go and MAUI); and the MAUI client's start/stop lifecycle is serialized so reconnecting can't race the previous session's teardown.


### What's new — 2026-09-29 (v5, security)

**Breaking — update the function, the adapter and all helpers/MAUI together.** Details in [SECURITY.md](SECURITY.md).

- Fixed critical v4 holes: unauthenticated `PING`/`SYNC` returned the service account's IAM token, unauthenticated `OPEN` turned the tunnel into an open proxy, and any `CONNECT` to `/_adapter` hijacked the adapter slot.
- `HELLO` proves the secret with an HMAC (the secret never travels); every later message carries a connection-bound ticket; unauthenticated connections are closed.
- All function frames are signed; adapter and helpers drop anything unsigned — an IAM token no longer allows frame injection.
- Helper↔adapter stream frames are encrypted and authenticated. New **`bridge.e2eKey`** setting (and **E2E Key** field in MAUI): a key the function never sees, so neither the function nor the provider can read the traffic.
- `/conn-ids`: HMAC instead of `Bearer <authToken>`, signed response, no IAM token.
- `AUTH_TOKEN` is required (≥16 chars); config validation with safe defaults.
- Helper shortIds are now allocated by the adapter — no more collisions across function instances (including helpers connecting before the adapter).
- The helper no longer aborts connections that are being opened on every periodic `PEER_CONN`.
- MAUI stores secrets in `SecureStorage`.
- New function env var `LOG_LEVEL` (the function no longer logs every frame by default).
- Tests: shared Go/JS/C# vectors, function attack tests, local end-to-end harness (`tests/e2e`), CI.
