// Bridge to Freedom v5 — Yandex Cloud Function
// Discovery service: exchanges connection IDs between adapter and helper.
// Optionally relays helper's stream frames to the adapter (relay mode).
//
// Env:
//   AUTH_TOKEN (required, >= 16 chars) — shared secret, same as bridge.authToken
//              in the adapter/helper configs. Generate with `openssl rand -hex 32`.
//   HTTP_URL   (required) — full URL of the adapter's HTTP endpoint, e.g.
//              https://your-server:3001/<random-path>, used to recover
//              connection IDs on cold start.
//   LOG_LEVEL  (optional) — "debug" logs every frame; default logs only state
//              changes and security events.
//
// Security model (v5, see SECURITY.md):
//   * HELLO carries an HMAC over a timestamp, never the raw secret.
//   * Every other message from a client must end with a 16-byte ticket
//     HMAC(role, connectionId). The connectionId comes from API Gateway and
//     can't be spoofed, so a ticket is useless on any other connection.
//     Messages without a valid ticket are dropped and the connection is closed.
//   * Every frame this function sends to a client is signed (HMAC bound to the
//     destination connectionId), so clients can reject frames injected by
//     anyone else holding an IAM token.
//   * The function never learns e2eKey: stream payloads relayed in relay mode
//     are opaque to it when e2eKey is configured on adapter and helpers.

const https = require('https');
const http = require('http');
const crypto = require('crypto');

const AUTH_TOKEN = (process.env.AUTH_TOKEN || '').trim();
const HTTP_URL = (process.env.HTTP_URL || '').trim() || null;
const DEBUG = (process.env.LOG_LEVEL || '').toLowerCase() === 'debug';
const MIN_SECRET_LEN = 16;

// Refuse to run with a missing/weak secret. (v4 compared against the string
// "undefined" when AUTH_TOKEN was unset.)
const CONFIG_ERROR = AUTH_TOKEN.length < MIN_SECRET_LEN
  ? `AUTH_TOKEN env var must be set to at least ${MIN_SECRET_LEN} characters`
  : null;
if (CONFIG_ERROR) console.error('FATAL CONFIG: ' + CONFIG_ERROR);

const httpsAgent = new https.Agent({ keepAlive: true });
const httpAgent = new http.Agent({ keepAlive: true });

function dbg(...a) { if (DEBUG) console.log(...a); }

// --- Crypto (mirrors adapter-and-helper/internal/secure/secure.go) ---------

const TAG_LEN = 16;
const HELLO_VERSION = 0x05;
const MAX_SKEW_MS = 5 * 60 * 1000;

function kdf(secret, label) {
  return crypto.createHmac('sha256', Buffer.from(secret, 'utf-8')).update('btf5/' + label).digest();
}
function hmac(key, ...parts) {
  const m = crypto.createHmac('sha256', key);
  for (const p of parts) m.update(p);
  return m.digest();
}
const ZERO = Buffer.from([0]);
const K = CONFIG_ERROR ? null : {
  hello: kdf(AUTH_TOKEN, 'hello'),
  ticket: kdf(AUTH_TOKEN, 'ticket'),
  ctl: kdf(AUTH_TOKEN, 'ctl'),
  connIds: kdf(AUTH_TOKEN, 'connids'),
};

function safeEqualBuf(a, b) {
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// Returns null if OK, or a short reason string.
function verifyHello(role, payload, nowMs) {
  if (payload.length !== 1 + 8 + 32 || payload[0] !== HELLO_VERSION) return 'bad version';
  const tsBuf = payload.subarray(1, 9);
  const ts = Number(tsBuf.readBigUInt64BE(0));
  const want = hmac(K.hello, Buffer.from(role), ZERO, tsBuf);
  if (!safeEqualBuf(want, payload.subarray(9))) return 'auth failed';
  if (Math.abs(nowMs - ts) > MAX_SKEW_MS) return 'clock skew';
  return null;
}

function ticketFor(role, connId) {
  return hmac(K.ticket, Buffer.from(role), ZERO, Buffer.from(connId, 'utf-8')).subarray(0, TAG_LEN);
}

// Strips and checks the trailing ticket. Returns the frame or null.
function checkTicket(role, connId, buf) {
  if (buf.length < 9 + TAG_LEN) return null;
  const frame = buf.subarray(0, buf.length - TAG_LEN);
  const tag = buf.subarray(buf.length - TAG_LEN);
  return safeEqualBuf(ticketFor(role, connId), tag) ? frame : null;
}

// Appends the control signature bound to the destination connection.
function signCtl(destConnId, frame) {
  const tag = hmac(K.ctl, Buffer.from(destConnId, 'utf-8'), ZERO, frame).subarray(0, TAG_LEN);
  return Buffer.concat([frame, tag]);
}

// The MAC also covers `assign` (helper connId the adapter should allocate a
// shortId for) and `want` (the shortId that helper already uses), '' if
// absent, so a MITM can't tamper with them.
function connIdsAuthHeader(ts, assign = '', want = '') {
  return 'BTF5 ' + ts + '.' + hmac(K.connIds, Buffer.from('req'), ZERO, Buffer.from(ts), ZERO,
    Buffer.from(assign, 'utf-8'), ZERO, Buffer.from(want)).toString('hex');
}
function connIdsRespOk(ts, body, sigHex) {
  if (typeof sigHex !== 'string' || !/^[0-9a-f]{64}$/i.test(sigHex)) return false;
  const want = hmac(K.connIds, Buffer.from('resp'), ZERO, Buffer.from(ts), ZERO, body);
  return safeEqualBuf(want, Buffer.from(sigHex, 'hex'));
}

// Message type names for logging.
const MSG_NAMES = {
  0x01: 'HELLO', 0x02: 'HELLO_OK', 0x03: 'HELLO_ERR',
  0x04: 'PEER_CONN', 0x05: 'PEER_GONE', 0x06: 'SYNC',
  0x10: 'OPEN', 0x11: 'OPEN_OK', 0x12: 'OPEN_FAIL',
  0x20: 'DATA', 0x21: 'FIN', 0x22: 'RST',
  0xF0: 'PING', 0xF1: 'PONG',
};
function msgName(type) { return MSG_NAMES[type] || '0x' + type.toString(16); }

// --- State (local cache per instance) ---
// Only ever populated from AUTHENTICATED messages or the signed /conn-ids
// response. (v4 set adapterConnId on any CONNECT to /_adapter, letting anyone
// hijack the adapter slot and receive helpers' traffic.)
let adapterConnId = null;
// Multi-helper support: each helper connection gets a unique 1-byte short ID
// (1..255). The helper stamps this ID into the top byte of every streamID it
// allocates, so the adapter can route per-stream frames back to the right
// helper.
const helpers = new Map();        // connId -> shortId
const usedShortIds = new Set();   // for fast allocation
// Helpers whose shortId was confirmed by the adapter (the single authority)
// for the current adapter connection. Entries not in here were allocated
// locally while the adapter was unreachable and get re-confirmed later.
const confirmed = new Set();      // connId

// Sets the known adapter connection. A different adapter connection means
// the adapter restarted and its shortId table is new: drop confirmations.
function setAdapter(id) {
  if (id && id !== adapterConnId) confirmed.clear();
  adapterConnId = id;
}
let _initPromise = null;
let _inflightFetch = null; // shared in-flight /conn-ids refresh (coalesces concurrent lookups)
let _rejected = 0;         // unauthenticated messages seen by this instance

function allocateShortId() {
  for (let i = 1; i <= 255; i++) {
    if (!usedShortIds.has(i)) {
      usedShortIds.add(i);
      return i;
    }
  }
  console.warn('allocateShortId: pool exhausted (>255 helpers)');
  return 0;
}

function rememberHelper(connId) {
  if (!connId) return 0;
  const existing = helpers.get(connId);
  if (existing) return existing;
  const sid = allocateShortId();
  if (sid !== 0) helpers.set(connId, sid);
  return sid;
}

function forgetHelper(connId) {
  const sid = helpers.get(connId);
  if (sid) {
    helpers.delete(connId);
    usedShortIds.delete(sid);
  }
  confirmed.delete(connId);
  return sid || 0;
}

// --- Protocol constants ---
const MSG_HELLO     = 0x01;
const MSG_HELLO_OK  = 0x02;
const MSG_HELLO_ERR = 0x03;
const MSG_PEER_CONN = 0x04;
const MSG_PEER_GONE = 0x05;
const MSG_SYNC      = 0x06;
const MSG_PING      = 0xF0;
const MSG_PONG      = 0xF1;
const MSG_OPEN      = 0x10;
const MSG_OPEN_FAIL = 0x12;
const MSG_RST       = 0x22;

// --- Helpers ---

function httpGet(url, headers) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const agent = url.startsWith('https') ? httpsAgent : httpAgent;
    const p = new URL(url);
    const req = mod.request({
      hostname: p.hostname, port: p.port || (p.protocol === 'https:' ? 443 : 80),
      path: p.pathname + p.search, method: 'GET', agent,
      headers: headers || {},
    }, res => {
      const chunks = [];
      let size = 0;
      res.on('data', c => {
        size += c.length;
        if (size > 64 * 1024) { req.destroy(new Error('response too large')); return; }
        chunks.push(c);
      });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('error', reject);
    // Bound the GET so a slow/hung adapter HTTP endpoint can't wedge the
    // coalesced refresh (every concurrent frame awaiting it would stall).
    req.setTimeout(2500, () => req.destroy(new Error('timeout')));
    req.end();
  });
}

// Fetch connection IDs from the adapter's HTTP endpoint (cold start / stale
// cache). The request carries a time-limited HMAC (not the raw secret) and the
// response must carry a valid signature, so a man-in-the-middle on a plain
// HTTP link can neither learn the secret nor inject a fake adapter ID.
// The IAM token is NOT sent any more (v4 sent it in clear text).
//
// `assign` (optional): a newly authenticated helper connId. The adapter then
// allocates its shortId — the adapter is the single authority, because
// function instances don't share memory and used to hand out colliding IDs.
async function fetchConnIds(maxAttempts = 3, assign = '', want = 0) {
  if (!HTTP_URL || !K) return;
  let url = HTTP_URL;
  const wantStr = assign && want ? String(want) : '';
  if (assign) {
    const u = new URL(HTTP_URL);
    u.searchParams.set('assign', assign);
    if (wantStr) u.searchParams.set('want', wantStr);
    url = u.toString();
  }
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const ts = String(Date.now());
      dbg(`fetchConnIds attempt=${attempt}`);
      const r = await httpGet(url, { 'Authorization': connIdsAuthHeader(ts, assign, wantStr) });
      if (r.status === 200 && r.body.length) {
        if (!connIdsRespOk(ts, r.body, r.headers['x-btf-sig'])) {
          console.error('fetchConnIds: response signature INVALID — ignoring (MITM, or adapter/function version or AUTH_TOKEN mismatch)');
          return;
        }
        const data = JSON.parse(r.body.toString('utf-8'));
        if (typeof data.adapterConnId === 'string' && data.adapterConnId) setAdapter(data.adapterConnId);
        if (Array.isArray(data.helpers)) {
          // The adapter's table is authoritative: replace ours.
          helpers.clear();
          usedShortIds.clear();
          confirmed.clear();
          for (const h of data.helpers) {
            if (h && typeof h.connId === 'string' && h.connId && Number.isInteger(h.shortId) && h.shortId >= 1 && h.shortId <= 255) {
              helpers.set(h.connId, h.shortId);
              usedShortIds.add(h.shortId);
              confirmed.add(h.connId);
            }
          }
        }
        dbg(`fetchConnIds OK adapter=${adapterConnId ? 'set' : 'null'} helpers=${helpers.size}`);
        return;
      }
      console.log(`fetchConnIds attempt=${attempt} status=${r.status}`);
    } catch (e) {
      console.error(`fetchConnIds attempt=${attempt} err=${e.message || e}`);
    }
    // Wait before retry (500ms, 1s)
    if (attempt < maxAttempts) await new Promise(r => setTimeout(r, attempt * 500));
  }
  console.warn('fetchConnIds: all retries exhausted, proceeding without conn-ids');
}

// Coalesced /conn-ids refresh. Concurrent callers share ONE in-flight GET.
function refreshConnIds(maxAttempts = 1) {
  if (_inflightFetch) return _inflightFetch;
  _inflightFetch = fetchConnIds(maxAttempts)
    .catch(e => { console.error(`refreshConnIds err=${(e && e.message) || e}`); })
    .finally(() => { _inflightFetch = null; });
  return _inflightFetch;
}

if (!CONFIG_ERROR) _initPromise = fetchConnIds();

// Ensure the local cache knows the peer of interest, refreshing from the
// adapter's HTTP endpoint if needed. `requiredHelperConnId` makes the helper
// check specific to one connection (see v4 notes on shortId collisions).
async function ensurePeerKnown(which, requiredHelperConnId = null) {
  if (which === 'adapter' && adapterConnId) return;
  if (which === 'helper') {
    if (requiredHelperConnId) {
      if (helpers.has(requiredHelperConnId)) return;
    } else if (helpers.size > 0) {
      return;
    }
  }
  dbg(`ensurePeerKnown: ${which} unknown, refreshing conn-ids`);
  await refreshConnIds(requiredHelperConnId ? 2 : 3);
}

const WSAPI_HOST = 'apigateway-connections.api.cloud.yandex.net';

// WS management API — send binary data to a connection.
async function wsSend(connId, data, token) {
  const b64 = Buffer.from(data).toString('base64');
  const body = JSON.stringify({ data: b64, type: 'BINARY' });
  const start = Date.now();
  return new Promise((resolve) => {
    const req = https.request({
      hostname: WSAPI_HOST,
      path: `/apigateways/websocket/v1/connections/${encodeURIComponent(connId)}:send`,
      method: 'POST', agent: httpsAgent,
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token, 'Content-Length': Buffer.byteLength(body) },
    }, res => {
      res.resume();
      res.on('end', () => {
        const ms = Date.now() - start;
        if (res.statusCode >= 300) console.error(`wsSend FAIL status=${res.statusCode} ms=${ms}`);
        else dbg(`wsSend OK bytes=${data.length} ms=${ms}`);
        resolve(res.statusCode);
      });
    });
    req.on('error', e => { console.error(`wsSend ERR err=${e.message} ms=${Date.now() - start}`); resolve(500); });
    // Bound the call so a hung YC API request can't burn the whole function
    // execution timeout (and so the relay retry path can react promptly).
    req.setTimeout(3000, () => { console.error(`wsSend TIMEOUT ms=${Date.now() - start}`); req.destroy(new Error('timeout')); });
    req.write(body);
    req.end();
  });
}

// Close a WebSocket connection (used to kick unauthenticated clients).
async function wsDisconnect(connId, token) {
  if (!token) return;
  return new Promise((resolve) => {
    const req = https.request({
      hostname: WSAPI_HOST,
      path: `/apigateways/websocket/v1/connections/${encodeURIComponent(connId)}`,
      method: 'DELETE', agent: httpsAgent,
      headers: { 'Authorization': 'Bearer ' + token },
    }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', () => resolve(500));
    req.setTimeout(2000, () => req.destroy(new Error('timeout')));
    req.end();
  });
}

// Sends a control frame to a client, signed for that client's connection.
function sendCtl(destConnId, frame, token) {
  return wsSend(destConnId, signCtl(destConnId, frame), token);
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// True for wsSend HTTP statuses that mean "this connectionId is gone", as
// opposed to transient errors (429 rate limit, 5xx, our 500 timeout sentinel).
function connIdGone(status) { return status === 400 || status === 404 || status === 410; }

// Relay a single (already ticket-checked) helper stream frame to the adapter.
// The frame is sealed by the helper; we forward it untouched. Returns null on
// success, or a signed OPEN_FAIL/RST response for the helper when the adapter
// is genuinely unreachable.
async function relayToAdapter(frame, type, streamId, token, helperConnId) {
  const deadline = Date.now() + 8500; // stay under the 10s function timeout
  let healed = false;                 // re-fetched a fresh id at least once
  for (let attempt = 1; attempt <= 4 && Date.now() < deadline; attempt++) {
    if (!adapterConnId) {
      await refreshConnIds(1);
      if (!adapterConnId) {
        if (Date.now() < deadline) await sleep(300);
        continue;
      }
    }
    const id = adapterConnId;
    const st = await wsSend(id, frame, token);
    if (st < 400) {
      if (attempt > 1) dbg(`relay ${msgName(type)} stream=${streamId} OK (attempt ${attempt})`);
      return null;
    }
    console.error(`relay ${msgName(type)} stream=${streamId} status=${st} attempt=${attempt}`);
    // Never null adapterConnId here (shared by concurrent invocations);
    // re-fetch the authoritative id instead.
    if (!healed && Date.now() < deadline) {
      healed = true;
      const before = adapterConnId;
      await refreshConnIds(1);
      if (adapterConnId && adapterConnId !== before) continue;
    }
    if (Date.now() < deadline) await sleep(300);
  }
  console.warn(`relay ${msgName(type)} stream=${streamId}: adapter unreachable after retries, signalling helper`);
  const resp = type === MSG_OPEN
    ? encodeStreamFrame(MSG_OPEN_FAIL, streamId, Buffer.from('adapter unreachable'))
    : encodeStreamFrame(MSG_RST, streamId);
  return binaryResp(signCtl(helperConnId, resp));
}

// Send the same control frame to many helper connections in parallel, dropping
// any the WS API reports as gone.
// `frame` may be a Buffer or a function (connId) => Buffer for per-helper frames.
async function notifyHelpers(connIds, frame, token, label) {
  if (!connIds.length) return;
  const results = await Promise.all(connIds.map(id =>
    sendCtl(id, typeof frame === 'function' ? frame(id) : frame, token).then(st => ({ id, st }))));
  for (const { id, st } of results) {
    if (connIdGone(st)) {
      console.log(`${label}: helper is gone (status=${st}), dropping`);
      forgetHelper(id);
    } else if (st >= 400) {
      console.log(`${label}: transient wsSend to helper (status=${st}), keeping`);
    }
  }
}

// --- Protocol encode helpers ---

// Frame: [1B type][4B streamID=0][4B seqID=0][payload]
function encodeControl(type, payload) {
  const p = payload || Buffer.alloc(0);
  const buf = Buffer.alloc(9 + p.length);
  buf[0] = type;
  p.copy(buf, 9);
  return buf;
}

// HELLO_OK payload: [2B ownIdLen][ownId][2B peerIdLen][peerId][2B tokenLen][token][1B helperShortId?]
function encodeHelloOK(ownId, peerId, iamToken, helperShortId = 0) {
  const o = Buffer.from(ownId || '', 'utf-8');
  const p = Buffer.from(peerId || '', 'utf-8');
  const t = Buffer.from(iamToken || '', 'utf-8');
  const extra = helperShortId ? 1 : 0;
  const buf = Buffer.alloc(2 + o.length + 2 + p.length + 2 + t.length + extra);
  let off = 0;
  buf.writeUInt16BE(o.length, off); off += 2; o.copy(buf, off); off += o.length;
  buf.writeUInt16BE(p.length, off); off += 2; p.copy(buf, off); off += p.length;
  buf.writeUInt16BE(t.length, off); off += 2; t.copy(buf, off); off += t.length;
  if (extra) buf[off] = helperShortId;
  return buf;
}

// PEER_CONN payload: [2B peerIdLen][peerId][2B tokenLen][token][1B helperShortId?]
function encodePeerConn(peerId, iamToken, helperShortId = 0) {
  const p = Buffer.from(peerId || '', 'utf-8');
  const t = Buffer.from(iamToken || '', 'utf-8');
  const extra = helperShortId ? 1 : 0;
  const buf = Buffer.alloc(2 + p.length + 2 + t.length + extra);
  let off = 0;
  buf.writeUInt16BE(p.length, off); off += 2; p.copy(buf, off); off += p.length;
  buf.writeUInt16BE(t.length, off); off += 2; t.copy(buf, off); off += t.length;
  if (extra) buf[off] = helperShortId;
  return buf;
}

// PONG payload: [2B tokenLen][token][1B helperShortId?]
// The trailing byte (helper-bound only) is the helper's confirmed shortId.
function encodePong(iamToken, helperShortId = 0) {
  const t = Buffer.from(iamToken || '', 'utf-8');
  const buf = Buffer.alloc(2 + t.length + (helperShortId ? 1 : 0));
  buf.writeUInt16BE(t.length, 0);
  t.copy(buf, 2);
  if (helperShortId) buf[2 + t.length] = helperShortId;
  return buf;
}

// Encode a stream-level frame (OPEN_FAIL, RST) with a specific streamId.
function encodeStreamFrame(type, streamId, payload) {
  const p = payload || Buffer.alloc(0);
  const buf = Buffer.alloc(9 + p.length);
  buf[0] = type;
  buf.writeUInt32BE(streamId, 1);
  buf.writeUInt32BE(0, 5); // seqID = 0
  p.copy(buf, 9);
  return buf;
}

function binaryResp(buf) {
  return { statusCode: 200, headers: { 'Content-Type': 'application/octet-stream' }, body: buf.toString('base64'), isBase64Encoded: true };
}

// Reply to a client with a control frame signed for its connection.
function ctlResp(connId, frame) { return binaryResp(signCtl(connId, frame)); }

// Drops an unauthenticated message and closes the offending connection.
async function reject(route, connId, token, why) {
  _rejected++;
  if (_rejected <= 20 || _rejected % 1000 === 0) {
    console.warn(`SECURITY: rejected ${route} message (${why}); total rejected by this instance=${_rejected}`);
  }
  await wsDisconnect(connId, token);
  return { statusCode: 200 };
}

// --- Handler ---
module.exports.handler = async function (event, context) {
  try { return await handle(event, context); }
  catch (e) { console.error('ERROR:', e.stack || e); return { statusCode: 200 }; }
};

async function handle(event, context) {
  if (CONFIG_ERROR) {
    console.error('FATAL CONFIG: ' + CONFIG_ERROR);
    return { statusCode: 500 };
  }
  if (_initPromise) { await _initPromise; _initPromise = null; }

  const rc = event.requestContext || {};
  const connId = rc.connectionId;
  const ev = rc.eventType;
  const token = context.token?.access_token || '';
  const route = rc.apiGateway?.operationContext?.route || '';

  if (route !== 'adapter' && route !== 'helper') {
    console.warn(`unknown route event=${ev}`);
    return { statusCode: 200 };
  }
  dbg(`event route=${route} type=${ev} state=[adapter=${adapterConnId ? 'set' : 'null'} helpers=${helpers.size}]`);

  if (ev === 'CONNECT') {
    // Nothing is trusted until the client authenticates with HELLO.
    return { statusCode: 200 };
  }

  if (ev === 'DISCONNECT') {
    if (route === 'adapter') {
      // Only react to the KNOWN adapter going away; an unauthenticated
      // connect/disconnect must not be able to tear down every helper.
      if (connId && adapterConnId === connId) {
        adapterConnId = null;
        confirmed.clear();
        console.log('adapter DISCONNECT (known adapter)');
        await Promise.all(Array.from(helpers.keys()).map(h => sendCtl(h, encodeControl(MSG_PEER_GONE), token)));
      }
    } else {
      const sid = forgetHelper(connId);
      if (sid && adapterConnId) {
        console.log(`helper DISCONNECT shortId=${sid}`);
        await sendCtl(adapterConnId, encodeControl(MSG_PEER_GONE, Buffer.from([sid])), token);
      }
    }
    return { statusCode: 200 };
  }

  if (ev !== 'MESSAGE') {
    console.warn(`${route}: unknown event type=${ev}`);
    return { statusCode: 200 };
  }

  const raw = event.isBase64Encoded ? Buffer.from(event.body || '', 'base64') : Buffer.from(event.body || '');
  if (raw.length < 9) return reject(route, connId, token, 'too short');

  // --- HELLO: the only message accepted without a ticket ---
  if (raw[0] === MSG_HELLO) {
    const why = verifyHello(route, raw.subarray(9), Date.now());
    if (why) {
      console.warn(`SECURITY: ${route} HELLO rejected (${why})`);
      // Tell the client why only for clock skew (not secret, and useful).
      // No state changes, nothing secret in the reply; the client closes the
      // connection itself (closing it here could drop the reply).
      return binaryResp(encodeControl(MSG_HELLO_ERR, Buffer.from(why === 'clock skew' ? 'clock skew' : 'auth failed')));
    }
    return route === 'adapter' ? adapterHello(connId, token) : helperHello(connId, token);
  }

  // --- Everything else must carry a valid ticket ---
  const frame = checkTicket(route, connId, raw);
  if (!frame) return reject(route, connId, token, 'missing/invalid ticket');

  const type = frame[0];
  const streamId = frame.readUInt32BE(1);
  dbg(`${route} MESSAGE type=${msgName(type)} streamId=${streamId} len=${frame.length}`);

  return route === 'adapter'
    ? adapterMessage(connId, token, type, frame)
    : helperMessage(connId, token, type, streamId, frame);
}

// --- ADAPTER ---

// PEER_CONN telling every known helper about the adapter; each helper also
// gets its adapter-confirmed shortId (0 if not confirmed yet).
function announceAdapterToHelpers(token, label) {
  return notifyHelpers(Array.from(helpers.keys()),
    id => encodeControl(MSG_PEER_CONN, encodePeerConn(adapterConnId, token, confirmed.has(id) ? helpers.get(id) : 0)),
    token, label);
}

async function adapterHello(connId, token) {
  setAdapter(connId);
  // (No /conn-ids fetch here: the adapter only answers it after HELLO_OK.
  // Its fresh helper table is rebuilt by its proactive SYNC right after.)
  await announceAdapterToHelpers(token, 'adapter HELLO');
  console.log(`adapter authenticated helpers=${helpers.size}`);
  // Adapter HELLO_OK carries no peerId; helpers are announced via PEER_CONN.
  return ctlResp(connId, encodeControl(MSG_HELLO_OK, encodeHelloOK(connId, '', token, 0)));
}

async function adapterMessage(connId, token, type) {
  if (type === MSG_PING) {
    // Authenticated PING: safe to (re-)learn the adapter connId from it.
    if (adapterConnId !== connId) {
      console.log('adapter PING: re-learned adapter connId');
      setAdapter(connId);
    }
    if (helpers.size === 0 || confirmed.size < helpers.size) await refreshConnIds(1);
    // Cross-notify each helper of the adapter (covers cross-instance state loss).
    await announceAdapterToHelpers(token, 'adapter PING');
    return ctlResp(connId, encodeControl(MSG_PONG, encodePong(token)));
  }
  if (type === MSG_SYNC) {
    if (adapterConnId !== connId) setAdapter(connId);
    if (helpers.size === 0) await ensurePeerKnown('helper');
    if (helpers.size === 0) {
      dbg('adapter SYNC -> PEER_GONE (no helpers)');
      return ctlResp(connId, encodeControl(MSG_PEER_GONE));
    }
    // Announce every known helper: first one as the response, the rest pushed.
    const entries = Array.from(helpers); // [[connId, shortId], ...]
    const [firstConnId, firstShort] = entries[0];
    const rest = entries.slice(1);
    if (rest.length) {
      await Promise.all(rest.map(([hConnId, sid]) =>
        sendCtl(connId, encodeControl(MSG_PEER_CONN, encodePeerConn(hConnId, token, sid)), token)));
    }
    // The adapter's table now mirrors ours (unique by construction here).
    for (const [hConnId] of entries) confirmed.add(hConnId);
    return ctlResp(connId, encodeControl(MSG_PEER_CONN, encodePeerConn(firstConnId, token, firstShort)));
  }
  console.warn(`adapter MESSAGE: unhandled type=${msgName(type)}`);
  return { statusCode: 200 };
}

// --- HELPER ---

// Returns { shortId, confirmed } for an authenticated helper connection.
//
// shortIds are allocated by the ADAPTER (single authority): function instances
// don't share memory and used to hand out colliding IDs. `claimed` is the ID
// the helper currently stamps into its streams (sent in PING/SYNC; 0 if
// unknown) — the adapter keeps it when free, so instances converge on the
// helper's own ID. Only when the adapter is unreachable do we allocate
// locally (unconfirmed; re-confirmed on a later PING). The confirmed ID is
// sent back to the helper in PONG/PEER_CONN so it can switch if needed.
const _assigning = new Map(); // connId -> Promise
async function helperShortIdFor(connId, claimed = 0) {
  const known = helpers.get(connId);
  if (known && confirmed.has(connId) && (!claimed || claimed === known)) {
    return { shortId: known, confirmed: true };
  }
  if (!_assigning.has(connId)) {
    _assigning.set(connId, fetchConnIds(2, connId, claimed || known || 0)
      .catch(e => console.error(`assign err=${(e && e.message) || e}`))
      .finally(() => _assigning.delete(connId)));
  }
  await _assigning.get(connId);
  const got = helpers.get(connId);
  if (got && confirmed.has(connId)) {
    dbg(`helper shortId=${got} confirmed by adapter`);
    return { shortId: got, confirmed: true };
  }
  if (got) return { shortId: got, confirmed: false };
  // Adapter unreachable: provisional local allocation (prefer the claim).
  let sid = 0;
  if (claimed && !usedShortIds.has(claimed)) {
    helpers.set(connId, claimed);
    usedShortIds.add(claimed);
    sid = claimed;
  } else {
    sid = rememberHelper(connId);
  }
  console.warn(`helper shortId=${sid} allocated provisionally (adapter unreachable)`);
  return { shortId: sid, confirmed: false };
}

// The claimed shortId a helper sends in its PING/SYNC payload (v5).
function claimOf(frame) { return frame.length > 9 ? frame[9] : 0; }

async function announceHelperToAdapter(connId, shortId, token, label) {
  if (!adapterConnId) await ensurePeerKnown('adapter');
  if (!adapterConnId) return;
  const frame = encodeControl(MSG_PEER_CONN, encodePeerConn(connId, token, shortId));
  const st = await sendCtl(adapterConnId, frame, token);
  if (st >= 400) {
    // Cached adapter id may be stale: re-fetch (never null it) and re-push once.
    const before = adapterConnId;
    await refreshConnIds(1);
    if (adapterConnId && adapterConnId !== before) {
      const st2 = await sendCtl(adapterConnId, frame, token);
      dbg(`${label}: re-pushed to healed adapter status=${st2}`);
    }
  }
}

async function helperHello(connId, token) {
  const { shortId } = await helperShortIdFor(connId, 0);
  await announceHelperToAdapter(connId, shortId, token, 'helper HELLO');
  console.log(`helper authenticated shortId=${shortId} adapter=${adapterConnId ? 'known' : 'unknown'}`);
  return ctlResp(connId, encodeControl(MSG_HELLO_OK, encodeHelloOK(connId, adapterConnId, token, shortId)));
}

async function helperMessage(connId, token, type, streamId, frame) {
  const isCtl = type === MSG_PING || type === MSG_SYNC;
  const { shortId, confirmed: ok } = await helperShortIdFor(connId, isCtl ? claimOf(frame) : 0);
  const confirmedId = ok ? shortId : 0;

  // Stream frames (0x10..0x22): relay to adapter. The frame is sealed by the
  // helper; we only look at its header.
  if (type >= MSG_OPEN && type <= MSG_RST) {
    // (No shortId ownership check here: per-instance shortId maps can
    // legitimately disagree on a cold instance, and all helpers share the
    // same secrets anyway — see SECURITY.md, "trust between helpers".)
    const errResp = await relayToAdapter(frame, type, streamId, token, connId);
    return errResp || { statusCode: 200 };
  }
  if (type === MSG_PING) {
    await announceHelperToAdapter(connId, shortId, token, 'helper PING');
    return ctlResp(connId, encodeControl(MSG_PONG, encodePong(token, confirmedId)));
  }
  if (type === MSG_SYNC) {
    if (!adapterConnId) await ensurePeerKnown('adapter');
    if (adapterConnId) {
      return ctlResp(connId, encodeControl(MSG_PEER_CONN, encodePeerConn(adapterConnId, token, confirmedId)));
    }
    return ctlResp(connId, encodeControl(MSG_PEER_GONE));
  }
  console.warn(`helper MESSAGE: unhandled type=${msgName(type)}`);
  return { statusCode: 200 };
}

// Exposed for tests only.
module.exports._test = { signCtl, ticketFor, verifyHello, connIdsAuthHeader, connIdsRespOk, kdf };
