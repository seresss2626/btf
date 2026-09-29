// TEST-ONLY local simulator of Yandex API Gateway (WebSocket) + the
// WebSocket management API, running the real bridge-cloud/index.js handler
// in-process. Usage: node sim.js <wsPort> <ctlPort>
//   ws://127.0.0.1:<wsPort>/_adapter and /_helper  -> function routes
//   http://127.0.0.1:<ctlPort>/send?conn=ID         -> deliver bytes (wsSend)
//   http://127.0.0.1:<ctlPort>/disconnect?conn=ID   -> close connection
//   http://127.0.0.1:<ctlPort>/debug/conns          -> JSON {adapter:[..],helper:[..]} (tests only)
'use strict';
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const path = require('path');
const { EventEmitter } = require('events');
const { WebSocketServer } = require('ws');

const [wsPort, ctlPort] = process.argv.slice(2).map(Number);
const IAM = process.env.SIM_IAM_TOKEN || 'IAM-SECRET-TOKEN-SIM';
const conns = new Map(); // connId -> { ws, route }
const stats = { delivered: 0, rejectedAuth: 0, disconnects: 0 };

function deliver(connId, buf) {
  const c = conns.get(connId);
  if (!c) return 404;
  c.ws.send(buf, { binary: true });
  stats.delivered++;
  return 200;
}
function disconnect(connId) {
  const c = conns.get(connId);
  if (!c) return 404;
  stats.disconnects++;
  c.ws.close();
  return 200;
}

// Route the function's REST calls to the WS API to the local connections.
const realRequest = https.request;
https.request = (opts, cb) => {
  if (opts.hostname !== 'apigateway-connections.api.cloud.yandex.net') return realRequest(opts, cb);
  const req = new EventEmitter();
  let body = '';
  req.write = b => { body += b; };
  req.setTimeout = () => {};
  req.end = () => setImmediate(() => {
    let code;
    if ((opts.headers || {}).Authorization !== 'Bearer ' + IAM) code = 401;
    else {
      const m = /\/connections\/([^/:]+)(:send)?$/.exec(opts.path);
      const id = m && decodeURIComponent(m[1]);
      if (opts.method === 'POST' && m && m[2]) code = deliver(id, Buffer.from(JSON.parse(body).data, 'base64'));
      else if (opts.method === 'DELETE' && m) code = disconnect(id);
      else code = 400;
    }
    const res = new EventEmitter();
    res.statusCode = code;
    res.resume = () => {};
    cb(res);
    res.emit('end');
  });
  return req;
};

// Real YC runs several independent function instances with separate memory.
// SIM_INSTANCES>1 loads the module several times and spreads invocations
// randomly, which exercises cold-start recovery via the signed /conn-ids.
const modPath = path.join(__dirname, '..', '..', 'bridge-cloud', 'index.js');
const instances = [];
for (let i = 0; i < Number(process.env.SIM_INSTANCES || 1); i++) {
  delete require.cache[require.resolve(modPath)];
  instances.push(require(modPath));
}
const ctx = { token: { access_token: IAM } };

async function invoke(route, type, connId, data) {
  const event = {
    requestContext: { connectionId: connId, eventType: type, apiGateway: { operationContext: { route } } },
    body: data ? data.toString('base64') : undefined,
    isBase64Encoded: true,
  };
  const fn = instances[Math.floor(Math.random() * instances.length)];
  return fn.handler(event, ctx);
}

const wss = new WebSocketServer({ host: '127.0.0.1', port: wsPort });
wss.on('connection', async (ws, req) => {
  const route = req.url === '/_adapter' ? 'adapter' : req.url === '/_helper' ? 'helper' : null;
  if (!route) { ws.close(); return; }
  const connId = 'c' + crypto.randomBytes(8).toString('hex');
  conns.set(connId, { ws, route });
  // Listeners are attached synchronously; MESSAGE invocations wait for the
  // CONNECT invocation (like the real gateway) but may run concurrently with
  // each other.
  const connected = invoke(route, 'CONNECT', connId);
  ws.on('message', async (data) => {
    await connected;
    const r = await invoke(route, 'MESSAGE', connId, Buffer.from(data));
    if (r && r.body && ws.readyState === ws.OPEN) ws.send(Buffer.from(r.body, 'base64'), { binary: true });
  });
  ws.on('close', async () => {
    conns.delete(connId);
    await connected;
    await invoke(route, 'DISCONNECT', connId);
  });
});

http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  if (u.pathname === '/debug/conns') {
    const out = { adapter: [], helper: [], stats };
    for (const [id, c] of conns) out[c.route].push(id);
    res.end(JSON.stringify(out));
    return;
  }
  const chunks = [];
  req.on('data', c => chunks.push(c));
  req.on('end', () => {
    if (req.headers.authorization !== 'Bearer ' + IAM) { stats.rejectedAuth++; res.statusCode = 401; res.end(); return; }
    // REST form used by the MAUI client: POST /apigateways/websocket/v1/connections/<id>:send {data,type}
    const rest = /^\/apigateways\/websocket\/v1\/connections\/([^/:]+):send$/.exec(u.pathname);
    if (rest) {
      res.statusCode = deliver(decodeURIComponent(rest[1]), Buffer.from(JSON.parse(Buffer.concat(chunks).toString()).data, 'base64'));
      res.end();
      return;
    }
    const id = u.searchParams.get('conn');
    res.statusCode = u.pathname === '/send' ? deliver(id, Buffer.concat(chunks))
      : u.pathname === '/disconnect' ? disconnect(id) : 400;
    res.end();
  });
}).listen(ctlPort, '127.0.0.1');

console.log(`sim ready ws=${wsPort} ctl=${ctlPort}`);
