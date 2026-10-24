// Cave Game relay server (WebSocket). Run:  npm i ws  &&  node server.js
// Works behind any host that gives you HTTPS: clients connect with wss://your-host (port 443).
const http = require('http');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8080;
const MAX_PLAYERS = 16;          // per room
const TICK_MS = 100;             // state broadcast rate (10 Hz): small + steady = Chromebook friendly
const MAX_EDITS = 100000;        // per room (deduplicated by block position)

const rooms = new Map();
let nextId = 1;

// If cavegame.html sits next to this file, the same server hands the game out too:
// one address (https://your-host/) for both the page and wss://your-host -- the easiest setup for a school network.
const fs = require('fs'), path = require('path'), zlib = require('zlib');
let gameRaw = null, gameGz = null;
try { gameRaw = fs.readFileSync(path.join(__dirname, 'cavegame.html')); gameGz = zlib.gzipSync(gameRaw, { level: 9 }); } catch {}
const server = http.createServer((req, res) => {
  if (gameRaw && (req.url === '/' || req.url.startsWith('/?') || req.url.startsWith('/index'))) {
    const gz = /gzip/.test(req.headers['accept-encoding'] || '');
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'public, max-age=300', ...(gz ? { 'content-encoding': 'gzip' } : {}) });
    res.end(gz ? gameGz : gameRaw);
    return;
  }
  res.writeHead(200, { 'content-type': 'text/plain' });
  res.end('Cave Game server is running\n');
});
const wss = new WebSocketServer({ server, maxPayload: 16 * 1024, perMessageDeflate: { threshold: 512 } });

function room(name) {
  let r = rooms.get(name);
  if (!r) { r = { clients: new Map(), edits: new Map() }; rooms.set(name, r); }
  return r;
}
const send = (ws, o) => { if (ws.readyState === 1) ws.send(JSON.stringify(o)); };
const num = (v, lo, hi) => (Number.isFinite(+v) ? Math.min(hi, Math.max(lo, +v)) : 0);

wss.on('connection', (ws) => {
  ws.alive = true; ws.rate = 0; ws.room = null; ws.id = null; ws.state = null; ws.dirty = false; ws.needAll = false;
  ws.on('pong', () => { ws.alive = true; });
  ws.on('message', (buf) => {
    if (++ws.rate > 80) return;                           // flood protection (80 msgs / second)
    let m; try { m = JSON.parse(buf); } catch { return; }
    if (!m || typeof m.t !== 'string') return;

    if (m.t === 'h') {                                    // hello: join a room
      if (ws.room) return;
      const name = String(m.room || 'main').toLowerCase().replace(/[^a-z0-9_.-]/g, '').slice(0, 40) || 'main';
      const r = room(name);
      if (r.clients.size >= MAX_PLAYERS) { ws.close(1013, 'room full'); return; }
      ws.room = r; ws.roomName = name; ws.id = 'p' + (nextId++);
      ws.name = String(m.name || 'Player').replace(/[^\w .-]/g, '').slice(0, 16) || 'Player';
      r.clients.set(ws.id, ws);
      send(ws, { t: 'w', id: ws.id, n: r.clients.size });
      const all = [...r.edits.values()];                  // late joiners get every edit so far
      for (let i = 0; i < all.length; i += 400) send(ws, { t: 'e', l: all.slice(i, i + 400) });
      ws.needAll = true;
      return;
    }
    if (!ws.room) return;

    if (m.t === 's' && m.s) {                             // player state
      const s = m.s;
      ws.state = { n: ws.name, x: num(s.x, -3e7, 3e7), y: num(s.y, -64, 512), z: num(s.z, -3e7, 3e7),
                   yw: num(s.yw, -10, 10), pt: num(s.pt, -2, 2), sk: String(s.sk || 'steve').replace(/[^a-z]/g, '').slice(0, 12), hd: num(s.hd, 0, 65535) | 0 };
      ws.dirty = true;
    } else if (m.t === 'e' && Array.isArray(m.l)) {       // block edits
      const out = [];
      for (const q of m.l.slice(0, 200)) {
        if (!Array.isArray(q) || q.length < 4) continue;
        const x = q[0] | 0, y = q[1] | 0, z = q[2] | 0, v = q[3] | 0;
        if (y < 0 || y > 255 || v < 0 || v > 65535 || Math.abs(x) > 3e7 || Math.abs(z) > 3e7) continue;
        out.push([x, y, z, v]);
        ws.room.edits.set(x + ',' + y + ',' + z, [x, y, z, v]);
      }
      if (ws.room.edits.size > MAX_EDITS) { const k = ws.room.edits.keys().next().value; ws.room.edits.delete(k); }
      if (out.length) for (const c of ws.room.clients.values()) if (c !== ws) send(c, { t: 'e', l: out });
    } else if (m.t === 'c' && typeof m.m === 'string') {  // chat
      const text = m.m.slice(0, 90);
      for (const c of ws.room.clients.values()) if (c !== ws) send(c, { t: 'c', n: ws.name, m: text });
    }
  });
  ws.on('close', () => {
    if (!ws.room) return;
    ws.room.clients.delete(ws.id);
    for (const c of ws.room.clients.values()) send(c, { t: 'l', id: ws.id });
    if (ws.room.clients.size === 0) rooms.delete(ws.roomName);   // empty rooms are forgotten
  });
});

// one batched message per client per tick (only changed players)
setInterval(() => {
  for (const r of rooms.values()) {
    const dirty = [];
    for (const c of r.clients.values()) if (c.dirty && c.state) { dirty.push([c.id, c.state]); }
    for (const c of r.clients.values()) {
      let list = dirty.filter((q) => q[0] !== c.id);
      if (c.needAll) { list = [...r.clients.values()].filter((o) => o !== c && o.state).map((o) => [o.id, o.state]); c.needAll = false; }
      if (list.length) send(c, { t: 'p', l: list });
    }
    for (const c of r.clients.values()) c.dirty = false;
  }
}, TICK_MS);

// once a second: reset rate limits, drop dead connections
setInterval(() => {
  for (const ws of wss.clients) {
    ws.rate = 0;
    if (!ws.alive) { ws.terminate(); continue; }
    ws.alive = false; try { ws.ping(); } catch {}
  }
}, 1000);

server.listen(PORT, () => console.log('Cave Game server listening on port ' + PORT));
