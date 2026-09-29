// Tests for bridge-cloud/index.js. Run: node --test tests/
// No network: https.request is stubbed and records wsSend / disconnect calls.
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const path = require('path');
const { EventEmitter } = require('events');

const V = require('../testdata/vectors.json');
process.env.AUTH_TOKEN = V.authToken;
delete process.env.HTTP_URL;

const https = require('https');
const calls = [];
https.request = (opts, cb) => {
  const req = new EventEmitter();
  let body = '';
  req.write = b => { body += b; };
  req.setTimeout = () => {};
  req.end = () => {
    calls.push({ method: opts.method, path: opts.path, body: body ? JSON.parse(body) : null });
    const res = new EventEmitter();
    res.statusCode = 200;
    res.resume = () => {};
    cb(res);
    res.emit('end');
  };
  return req;
};

const fn = require(path.join(__dirname, '..', 'bridge-cloud', 'index.js'));
const { signCtl, ticketFor, kdf } = fn._test;

const CTX = { token: { access_token: 'IAM-SECRET-TOKEN' } };
const ev = (route, type, connId, buf) => ({
  requestContext: { connectionId: connId, eventType: type, apiGateway: { operationContext: { route } } },
  body: buf ? buf.toString('base64') : undefined, isBase64Encoded: true,
});
const frame = (t, sid = 0, payload = Buffer.alloc(0)) => {
  const b = Buffer.alloc(9 + payload.length); b[0] = t; b.writeUInt32BE(sid >>> 0, 1); payload.copy(b, 9); return b;
};
const hmac = (k, ...p) => { const m = crypto.createHmac('sha256', k); p.forEach(x => m.update(x)); return m.digest(); };
function hello(role, ts = Date.now()) {
  const t = Buffer.alloc(8); t.writeBigUInt64BE(BigInt(ts));
  return frame(0x01, 0, Buffer.concat([Buffer.from([5]), t, hmac(kdf(V.authToken, 'hello'), Buffer.from(role), Buffer.from([0]), t)]));
}
const withTicket = (role, connId, f) => Buffer.concat([f, ticketFor(role, connId)]);
const respBuf = r => Buffer.from(r.body, 'base64');
const verifyCtl = (dest, msg) => {
  const f = msg.subarray(0, msg.length - 16);
  return signCtl(dest, f).equals(msg) ? f : null;
};
const sent = () => calls.filter(c => c.method === 'POST');
const disconnects = () => calls.filter(c => c.method === 'DELETE');

// ---- cross-language vectors ----

test('vectors: HELLO, ticket, ctl signature, conn-ids match Go', () => {
  const ts = Buffer.alloc(8); ts.writeBigUInt64BE(BigInt(V.tsMs));
  const helloMac = hmac(kdf(V.authToken, 'hello'), Buffer.from('helper'), Buffer.from([0]), ts);
  assert.strictEqual(Buffer.concat([Buffer.from([5]), ts, helloMac]).toString('hex'), V.helloHelper);
  assert.strictEqual(fn._test.verifyHello('helper', Buffer.from(V.helloHelper, 'hex'), V.tsMs), null);
  assert.strictEqual(fn._test.verifyHello('adapter', Buffer.from(V.helloHelper, 'hex'), V.tsMs), 'auth failed');
  assert.strictEqual(fn._test.verifyHello('helper', Buffer.from(V.helloHelper, 'hex'), V.tsMs + 6 * 60000), 'clock skew');
  assert.strictEqual(ticketFor('helper', V.ticketConnId).toString('hex'), V.ticketHelper);
  assert.strictEqual(signCtl(V.ctlDest, Buffer.from(V.ctlFrame, 'hex')).toString('hex'), V.ctlSigned);
  assert.strictEqual(fn._test.connIdsAuthHeader(String(V.tsMs)), V.connIdsAuth);
  assert.ok(fn._test.connIdsRespOk(String(V.tsMs), Buffer.from(V.connIdsBody), V.connIdsSig));
  assert.ok(!fn._test.connIdsRespOk(String(V.tsMs + 1), Buffer.from(V.connIdsBody), V.connIdsSig));
});

test('vectors: peer seal (AES-256-CTR + HMAC) matches Go', () => {
  const seal = (secret, dir) => {
    const f = Buffer.from(V.peerFrame, 'hex'), iv = Buffer.from(V.peerIv, 'hex');
    const c = crypto.createCipheriv('aes-256-ctr', kdf(secret, 'peer-enc'), iv);
    const ct = Buffer.concat([c.update(f.subarray(9)), c.final()]);
    const body = Buffer.concat([f.subarray(0, 9), iv, ct]);
    return Buffer.concat([body, hmac(kdf(secret, 'peer-mac'), Buffer.from(dir), body).subarray(0, 16)]).toString('hex');
  };
  assert.strictEqual(seal(V.e2eKey, 'H'), V.peerSealedH);
  assert.strictEqual(seal(V.e2eKey, 'A'), V.peerSealedA);
  assert.strictEqual(seal(V.authToken, 'H'), V.peerSealedNoE2E);
});

// ---- behaviour / attacks (these all succeeded against v4) ----

test('legit adapter + helper flow works and every reply is signed', async () => {
  let r = await fn.handler(ev('adapter', 'CONNECT', 'adapter-1'), CTX);
  r = await fn.handler(ev('adapter', 'MESSAGE', 'adapter-1', hello('adapter')), CTX);
  const ok = verifyCtl('adapter-1', respBuf(r));
  assert.ok(ok, 'adapter HELLO_OK signed for adapter-1');
  assert.strictEqual(ok[0], 0x02);

  calls.length = 0;
  r = await fn.handler(ev('helper', 'MESSAGE', 'helper-1', hello('helper')), CTX);
  const hok = verifyCtl('helper-1', respBuf(r));
  assert.ok(hok && hok[0] === 0x02, 'helper HELLO_OK signed');
  assert.ok(hok.includes(Buffer.from('adapter-1')), 'helper learns adapter id');
  // Adapter was told about the helper with a signed PEER_CONN.
  const push = sent().find(c => c.path.includes('adapter-1'));
  assert.ok(push && verifyCtl('adapter-1', Buffer.from(push.body.data, 'base64')), 'PEER_CONN to adapter signed');

  r = await fn.handler(ev('helper', 'MESSAGE', 'helper-1', withTicket('helper', 'helper-1', frame(0xF0))), CTX);
  const pong = verifyCtl('helper-1', respBuf(r));
  assert.ok(pong && pong[0] === 0xF1, 'PONG with ticket');

  // Relay: sealed frame forwarded verbatim (ticket stripped).
  calls.length = 0;
  const sealed = Buffer.concat([frame(0x10, (1 << 24) | 5), crypto.randomBytes(32)]);
  r = await fn.handler(ev('helper', 'MESSAGE', 'helper-1', withTicket('helper', 'helper-1', sealed)), CTX);
  assert.deepStrictEqual(Buffer.from(sent()[0].body.data, 'base64'), sealed);
  assert.ok(sent()[0].path.includes('adapter-1'));
});

test('ATTACK: PING/SYNC without auth do not leak the IAM token', async () => {
  for (const t of [0xF0, 0x06]) {
    calls.length = 0;
    const r = await fn.handler(ev('helper', 'MESSAGE', 'attacker', frame(t)), CTX);
    assert.ok(!r.body || !respBuf(r).includes(Buffer.from('IAM-SECRET-TOKEN')), 'no token in reply');
    assert.strictEqual(sent().length, 0, 'nothing sent anywhere');
    assert.strictEqual(disconnects().length, 1, 'attacker disconnected');
  }
});

test('ATTACK: forged/other-connection ticket rejected', async () => {
  calls.length = 0;
  // Valid ticket for helper-1 replayed on attacker's connection.
  const r = await fn.handler(ev('helper', 'MESSAGE', 'attacker', withTicket('helper', 'helper-1', frame(0xF0))), CTX);
  assert.ok(!r.body);
  // Helper ticket on the adapter route.
  const r2 = await fn.handler(ev('adapter', 'MESSAGE', 'helper-1', withTicket('helper', 'helper-1', frame(0xF0))), CTX);
  assert.ok(!r2.body);
  assert.strictEqual(sent().length, 0);
});

test('ATTACK: unauthenticated OPEN is not relayed (no open proxy)', async () => {
  calls.length = 0;
  await fn.handler(ev('helper', 'MESSAGE', 'attacker', frame(0x10, (1 << 24) | 5)), CTX);
  assert.strictEqual(sent().length, 0);
});

test('ATTACK: adapter slot cannot be hijacked by CONNECT/PING/DISCONNECT', async () => {
  await fn.handler(ev('adapter', 'CONNECT', 'evil-adapter'), CTX);
  await fn.handler(ev('adapter', 'MESSAGE', 'evil-adapter', frame(0xF0)), CTX);
  calls.length = 0;
  await fn.handler(ev('adapter', 'DISCONNECT', 'evil-adapter'), CTX);
  assert.strictEqual(sent().length, 0, 'no PEER_GONE broadcast for unknown adapter');
  calls.length = 0;
  const sealed = Buffer.concat([frame(0x10, (1 << 24) | 7), crypto.randomBytes(32)]);
  await fn.handler(ev('helper', 'MESSAGE', 'helper-1', withTicket('helper', 'helper-1', sealed)), CTX);
  assert.ok(sent()[0].path.includes('adapter-1'), 'traffic still goes to the real adapter');
});

test('ATTACK: HELLO with wrong token, wrong role, legacy v4 or stale timestamp rejected', async () => {
  const bad = [
    frame(0x01, 0, Buffer.concat([Buffer.from([1]), Buffer.from(V.authToken)])), // v4 raw-token HELLO
    hello('adapter'),                                                            // role mismatch on helper route
    hello('helper', Date.now() - 10 * 60000),                                    // replay outside window
    frame(0x01, 0, Buffer.concat([Buffer.from([5]), crypto.randomBytes(40)])),
  ];
  for (const b of bad) {
    calls.length = 0;
    const r = await fn.handler(ev('helper', 'MESSAGE', 'attacker', b), CTX);
    const buf = respBuf(r);
    assert.strictEqual(buf[0], 0x03, 'HELLO_ERR');
    assert.ok(!buf.includes(Buffer.from('IAM-SECRET-TOKEN')));
    assert.strictEqual(sent().length, 0, 'no state change / nothing sent');
  }
});
