// TEST-ONLY end-to-end checks. Started by run.sh after sim/fakeyc/adapter/helpers.
// Usage: node e2e.js <echoPort> <simWsPort> <simCtlPort> <helperDirect> <helperRelay> <helperWrongKey> <adapterHttp> <authToken>
'use strict';
const net = require('net');
const http = require('http');
const crypto = require('crypto');
const WebSocket = require('ws');

const [echoPort, wsPort, ctlPort, hDirect, hRelay, hWrong, adapterHttp] = process.argv.slice(2, 9).map(Number);
const IAM = process.env.SIM_IAM_TOKEN || 'IAM-SECRET-TOKEN-SIM';

let echoConns = 0;
const echo = net.createServer(s => { echoConns++; s.pipe(s); });

let failures = 0;
function check(name, ok, extra = '') {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${extra ? '  (' + extra + ')' : ''}`);
  if (!ok) failures++;
}
const sleep = ms => new Promise(r => setTimeout(r, ms));

// Sends `size` random bytes through the tunnel and checks they come back intact.
function echoThrough(port, size, timeoutMs = 20000) {
  return new Promise(resolve => {
    const data = crypto.randomBytes(size);
    const got = [];
    let n = 0;
    const s = net.connect(port, '127.0.0.1');
    const t = setTimeout(() => { s.destroy(); resolve(false); }, timeoutMs);
    s.on('connect', () => s.write(data));
    s.on('data', c => {
      got.push(c); n += c.length;
      if (n >= size) { clearTimeout(t); s.end(); resolve(Buffer.concat(got).equals(data)); }
    });
    s.on('error', () => { clearTimeout(t); resolve(false); });
    s.on('close', () => { clearTimeout(t); resolve(n >= size && Buffer.concat(got).equals(data)); });
  });
}

function httpReq(method, port, p, headers = {}, body = null) {
  return new Promise(resolve => {
    const r = http.request({ host: '127.0.0.1', port, path: p, method, headers }, res => {
      const c = []; res.on('data', d => c.push(d)); res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(c) }));
    });
    r.on('error', e => resolve({ status: 0, body: Buffer.from(String(e)) }));
    if (body) r.write(body);
    r.end();
  });
}
const frame = (t, sid = 0, payload = Buffer.alloc(0)) => {
  const b = Buffer.alloc(9 + payload.length); b[0] = t; b.writeUInt32BE(sid >>> 0, 1); b.writeUInt32BE(1, 5); payload.copy(b, 9); return b;
};

async function main() {
  await new Promise(r => echo.listen(echoPort, '127.0.0.1', r));
  // Wait for helpers to come up and discover the adapter.
  for (let i = 0; i < 60; i++) { if (await echoThrough(hDirect, 16, 2000)) break; await sleep(500); }

  // --- Functional ---
  const par = await Promise.all(Array.from({ length: 16 }, () => echoThrough(hDirect, 256 * 1024)));
  check('direct mode: 16 parallel streams x 256 KiB echoed intact', par.every(Boolean), `${par.filter(Boolean).length}/16`);
  check('direct mode: single 4 MiB stream echoed intact', await echoThrough(hDirect, 4 * 1024 * 1024, 60000));
  const rel = await Promise.all(Array.from({ length: 4 }, () => echoThrough(hRelay, 64 * 1024)));
  check('relay mode: 4 parallel streams x 64 KiB echoed intact', rel.every(Boolean), `${rel.filter(Boolean).length}/4`);

  // --- Wrong e2eKey helper must not get through ---
  const before = echoConns;
  const wrong = await echoThrough(hWrong, 1024, 8000);
  await sleep(500);
  check('helper with wrong e2eKey cannot open streams', !wrong && echoConns === before, `echoConns +${echoConns - before}`);

  // --- Attack: unauthenticated PING on /_helper (v4 leaked the IAM token) ---
  const leak = await new Promise(resolve => {
    const ws = new WebSocket(`ws://127.0.0.1:${wsPort}/_helper`);
    const got = [];
    ws.on('open', () => ws.send(frame(0xF0)));
    ws.on('message', d => got.push(Buffer.from(d)));
    ws.on('close', () => resolve({ closed: true, got }));
    setTimeout(() => { ws.terminate(); resolve({ closed: false, got }); }, 3000);
  });
  check('ATTACK unauthenticated PING: no IAM token, connection closed',
    leak.closed && !Buffer.concat(leak.got).includes(Buffer.from(IAM)), `closed=${leak.closed} bytes=${Buffer.concat(leak.got).length}`);

  // --- Attack: hijack the adapter slot by connecting to /_adapter ---
  await new Promise(resolve => {
    const ws = new WebSocket(`ws://127.0.0.1:${wsPort}/_adapter`);
    ws.on('open', () => { ws.send(frame(0xF0)); setTimeout(() => { ws.close(); resolve(); }, 1000); });
    ws.on('error', resolve);
    ws.on('close', resolve);
  });
  await sleep(500);
  check('ATTACK adapter-slot hijack: tunnel still works afterwards', await echoThrough(hDirect, 64 * 1024));

  // --- Attack: inject frames with a leaked IAM token straight into the adapter ---
  const conns = JSON.parse((await httpReq('GET', ctlPort, '/debug/conns')).body);
  const beforeInj = echoConns;
  for (const a of conns.adapter) {
    await httpReq('POST', ctlPort, `/send?conn=${a}`, { Authorization: 'Bearer ' + IAM }, frame(0x10, (1 << 24) | 4242)); // v4 plaintext OPEN
    await httpReq('POST', ctlPort, `/send?conn=${a}`, { Authorization: 'Bearer ' + IAM },
      Buffer.concat([frame(0x10, (1 << 24) | 4243), crypto.randomBytes(40)]));                              // fake sealed OPEN
  }
  await sleep(1500);
  check('ATTACK IAM-token frame injection into adapter: no target connection opened',
    conns.adapter.length > 0 && echoConns === beforeInj, `adapters=${conns.adapter.length} echoConns +${echoConns - beforeInj}`);

  // --- Attack: forged PEER_GONE into helpers must not kill live streams ---
  const live = net.connect(hDirect, '127.0.0.1');
  await new Promise(r => live.on('connect', r));
  live.write('ping1');
  await new Promise(r => live.once('data', r));
  for (const h of conns.helper) {
    await httpReq('POST', ctlPort, `/send?conn=${h}`, { Authorization: 'Bearer ' + IAM }, frame(0x05)); // unsigned PEER_GONE
  }
  await sleep(1000);
  const alive = await new Promise(resolve => {
    live.once('data', d => resolve(d.toString() === 'ping2'));
    live.once('close', () => resolve(false));
    live.write('ping2');
    setTimeout(() => resolve(false), 10000);
  });
  live.destroy();
  check('ATTACK forged PEER_GONE: live stream survives', alive);

  // --- /conn-ids endpoint ---
  const r1 = await httpReq('GET', adapterHttp, '/secret-path');
  const r2 = await httpReq('GET', adapterHttp, '/secret-path', { Authorization: 'Bearer ' + process.argv[9] });
  check('/conn-ids: no auth -> 404', r1.status === 404, String(r1.status));
  check('/conn-ids: legacy raw-token Bearer -> 404', r2.status === 404, String(r2.status));

  echo.close();
  console.log(failures ? `\n${failures} FAILED` : '\nALL PASSED');
  process.exit(failures ? 1 : 0);
}
main().catch(e => { console.error(e); process.exit(2); });
