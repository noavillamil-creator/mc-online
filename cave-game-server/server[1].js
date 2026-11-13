// Cave Game account + multiplayer relay server.
// Render runs this file. Neon stores accounts and revocable login sessions.
// Required environment variable: DATABASE_URL
// Optional first-owner bootstrap: OWNER_SETUP_KEY
// Install: npm install && npm start

'use strict';

const http = require('http');
const crypto = require('crypto');
const { promisify } = require('util');
const { Pool } = require('pg');
const { WebSocketServer } = require('ws');

const PORT = Number(process.env.PORT || 8080);
const MAX_PLAYERS = 16;          // per room
const TICK_MS = 100;             // state broadcast rate (10 Hz)
const MAX_EDITS = 100000;        // per room (deduplicated by block position)
const SESSION_DAYS = 14;
const AUTH_RATE_LIMIT = 25;      // school/shared Wi-Fi can put many players behind one public IP
const AUTH_RATE_WINDOW = 15 * 60 * 1000;
const BODY_LIMIT = 8 * 1024;
const WORLD_REQUEST_LIMIT = 24 * 1024 * 1024;
const WORLD_JSON_LIMIT = 20 * 1024 * 1024;
const OWNER_SETUP_KEY = process.env.OWNER_SETUP_KEY || '';

if (!process.env.DATABASE_URL) {
  console.error('FATAL: DATABASE_URL is missing. Add the Neon pooled connection string in Render → Environment.');
  process.exit(1);
}

// Render is a long-running Node.js host, so node-postgres (pg) is the right fit.
// Keep the pooled Neon URL in DATABASE_URL; never hardcode credentials here.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 15000,
  keepAlive: true
});
pool.on('error', (err) => console.error('Unexpected idle PostgreSQL error:', err.message));

const scryptAsync = promisify(crypto.scrypt);
const rooms = new Map();
const authRates = new Map();
let nextId = 1;

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS accounts (
  id BIGSERIAL PRIMARY KEY,
  username TEXT NOT NULL,
  username_norm TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'player'
    CHECK (role IN ('owner', 'admin', 'moderator', 'player')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS account_sessions (
  id BIGSERIAL PRIMARY KEY,
  account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  token_hash CHAR(64) NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS account_sessions_account_id_idx ON account_sessions(account_id);
CREATE INDEX IF NOT EXISTS account_sessions_expires_at_idx ON account_sessions(expires_at);
CREATE TABLE IF NOT EXISTS account_bans (
  id BIGSERIAL PRIMARY KEY,
  account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  reason TEXT NOT NULL DEFAULT '',
  banned_by BIGINT NOT NULL REFERENCES accounts(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  revoked_by BIGINT REFERENCES accounts(id)
);
CREATE INDEX IF NOT EXISTS account_bans_account_active_idx ON account_bans(account_id, expires_at) WHERE revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS account_worlds (
  id BIGSERIAL PRIMARY KEY,
  account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  world_id TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT 'New World',
  seed TEXT NOT NULL DEFAULT '',
  mode TEXT NOT NULL DEFAULT 'survival',
  room_code TEXT NOT NULL DEFAULT '',
  thumb TEXT NOT NULL DEFAULT '',
  world_data JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(account_id, world_id)
);
CREATE INDEX IF NOT EXISTS account_worlds_account_updated_idx
  ON account_worlds(account_id, updated_at DESC);
`;

function safeEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function tokenHash(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}
function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(body)
  });
  res.end(body);
}
function cors(req, res) {
  // The game may be opened from file:// or hosted on a different static site.
  // Authentication uses explicit bearer tokens, not cookies or credentials.
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Max-Age', '600');
  res.setHeader('Vary', 'Origin');
}
function readJson(req, maxBytes = BODY_LIMIT) {
  return new Promise((resolve, reject) => {
    let raw = '';
    let tooLarge = false;
    let settled = false;
    req.on('data', (chunk) => {
      if (tooLarge) return;
      raw += chunk;
      if (Buffer.byteLength(raw, 'utf8') > maxBytes) {
        tooLarge = true;
        settled = true;
        reject(Object.assign(new Error('Request is too large.'), { status: 413 }));
      }
    });
    req.on('end', () => {
      if (tooLarge) return;
      try { resolve(raw ? JSON.parse(raw) : {}); }
      catch { reject(Object.assign(new Error('Invalid JSON.'), { status: 400 })); }
    });
    req.on('error', (err) => { if (!settled) reject(err); });
  });
}
function rateAllowed(req, key) {
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
  const id = key + ':' + ip;
  const now = Date.now();
  let entry = authRates.get(id);
  if (!entry || now - entry.start > AUTH_RATE_WINDOW) entry = { start: now, count: 0 };
  entry.count++;
  authRates.set(id, entry);
  return entry.count <= AUTH_RATE_LIMIT;
}
function validUsername(value) {
  if (typeof value !== 'string') throw Object.assign(new Error('Enter a username.'), { status: 400 });
  const username = value.trim();
  if (!/^[A-Za-z0-9_.-]{3,16}$/.test(username)) {
    throw Object.assign(new Error('Username must be 3–16 characters: letters, numbers, periods, underscores, or hyphens.'), { status: 400 });
  }
  return { username, normalized: username.toLowerCase() };
}
function validPassword(value) {
  if (typeof value !== 'string') throw Object.assign(new Error('Enter a password.'), { status: 400 });
  const password = value;
  const bytes = Buffer.byteLength(password, 'utf8');
  if (bytes < 10) throw Object.assign(new Error('Password must be at least 10 characters.'), { status: 400 });
  if (bytes > 128) throw Object.assign(new Error('Password must be 128 bytes or fewer.'), { status: 400 });
  return password;
}
async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const derived = await scryptAsync(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  return 'scrypt$' + salt.toString('base64url') + '$' + Buffer.from(derived).toString('base64url');
}
async function verifyPassword(password, encoded) {
  try {
    const parts = String(encoded).split('$');
    if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
    const salt = Buffer.from(parts[1], 'base64url');
    const expected = Buffer.from(parts[2], 'base64url');
    if (salt.length !== 16 || expected.length !== 64) return false;
    const actual = Buffer.from(await scryptAsync(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }));
    return crypto.timingSafeEqual(actual, expected);
  } catch { return false; }
}
async function createSession(accountId) {
  const token = crypto.randomBytes(32).toString('base64url');
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000);
  await pool.query(
    'INSERT INTO account_sessions (account_id, token_hash, expires_at) VALUES ($1, $2, $3)',
    [accountId, tokenHash(token), expiresAt]
  );
  return token;
}
async function getAccountForToken(token) {
  if (!token || typeof token !== 'string' || token.length > 200) return null;
  const { rows } = await pool.query(
    `SELECT a.id, a.username, a.role
       FROM account_sessions s
       JOIN accounts a ON a.id = s.account_id
      WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > NOW()
        AND NOT EXISTS (
          SELECT 1 FROM account_bans b
           WHERE b.account_id = a.id AND b.revoked_at IS NULL
             AND (b.expires_at IS NULL OR b.expires_at > NOW())
        )
      LIMIT 1`,
    [tokenHash(token)]
  );
  return rows[0] || null;
}
function bearerToken(req) {
  const match = /^Bearer\s+(.+)$/i.exec(String(req.headers.authorization || ''));
  return match ? match[1].trim() : '';
}
async function getActiveBan(accountId) {
  const result = await pool.query(
    `SELECT id, reason, expires_at FROM account_bans
      WHERE account_id = $1 AND revoked_at IS NULL
        AND (expires_at IS NULL OR expires_at > NOW())
      ORDER BY created_at DESC LIMIT 1`,
    [accountId]
  );
  return result.rows[0] || null;
}
async function requireOwner(req) {
  const account = await getAccountForToken(bearerToken(req));
  if (!account) throw Object.assign(new Error('Sign in again to use the Owner Panel.'), { status: 401 });
  if (account.role !== 'owner') throw Object.assign(new Error('Owner permission required.'), { status: 403 });
  return account;
}
function validAccountId(value) {
  const id = String(value == null ? '' : value);
  if (!/^[1-9][0-9]{0,17}$/.test(id)) throw Object.assign(new Error('Invalid account ID.'), { status: 400 });
  return id;
}
async function getManageableAccount(value, actor) {
  const id = validAccountId(value);
  const result = await pool.query('SELECT id, username, role FROM accounts WHERE id = $1 LIMIT 1', [id]);
  const target = result.rows[0];
  if (!target) throw Object.assign(new Error('Account not found.'), { status: 404 });
  if (String(target.id) === String(actor.id)) throw Object.assign(new Error('You cannot moderate your own Owner account.'), { status: 403 });
  if (target.role === 'owner') throw Object.assign(new Error('The Owner account is protected.'), { status: 403 });
  return target;
}
function disconnectAccount(accountId, reason) {
  let count = 0;
  for (const ws of wss.clients) {
    if (ws.account && String(ws.account.id) === String(accountId) && ws.readyState === 1) {
      send(ws, { t: 'x', message: reason });
      ws.close(4003, 'moderated by owner');
      count++;
    }
  }
  return count;
}

async function registerAccount(body) {
  const { username, normalized } = validUsername(body.username);
  const password = validPassword(body.password);
  const ownerKey = typeof body.ownerKey === 'string' ? body.ownerKey : '';
  if (body.ownerKey != null && typeof body.ownerKey !== 'string') throw Object.assign(new Error('Invalid owner setup key.'), { status: 400 });
  const passwordHash = await hashPassword(password);
  const client = await pool.connect();
  let account;
  try {
    await client.query('BEGIN');
    // Serializes first-owner claims so two people cannot both claim the owner role.
    await client.query('SELECT pg_advisory_xact_lock($1)', [84612831]);
    let role = 'player';
    if (ownerKey) {
      if (!OWNER_SETUP_KEY) throw Object.assign(new Error('Owner setup is not enabled on the server. Add OWNER_SETUP_KEY in Render first.'), { status: 503 });
      if (!safeEqual(ownerKey, OWNER_SETUP_KEY)) throw Object.assign(new Error('Owner setup key is incorrect.'), { status: 403 });
      const existingOwner = await client.query("SELECT id FROM accounts WHERE role = 'owner' LIMIT 1");
      if (existingOwner.rowCount) throw Object.assign(new Error('An owner account has already been created.'), { status: 409 });
      role = 'owner';
    }
    const result = await client.query(
      'INSERT INTO accounts (username, username_norm, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING id, username, role',
      [username, normalized, passwordHash, role]
    );
    account = result.rows[0];
    await client.query('COMMIT');
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch {}
    if (err && err.code === '23505') throw Object.assign(new Error('That username is already taken.'), { status: 409 });
    throw err;
  } finally {
    client.release();
  }
  const token = await createSession(account.id);
  return { token, account };
}

async function loginAccount(body) {
  const { normalized } = validUsername(body.username);
  const password = validPassword(body.password);
  const result = await pool.query(
    'SELECT id, username, role, password_hash FROM accounts WHERE username_norm = $1 LIMIT 1',
    [normalized]
  );
  const account = result.rows[0];
  if (!account || !(await verifyPassword(password, account.password_hash))) {
    throw Object.assign(new Error('Invalid username or password.'), { status: 401 });
  }
  const ban = await getActiveBan(account.id);
  if (ban) {
    const until = ban.expires_at ? new Date(ban.expires_at).toLocaleString('en-US', { timeZone: 'UTC' }) + ' UTC' : 'permanently';
    const why = ban.reason ? ' Reason: ' + ban.reason : '';
    throw Object.assign(new Error('This account is banned until ' + until + '.' + why), { status: 403 });
  }
  await pool.query('UPDATE accounts SET last_login_at = NOW() WHERE id = $1', [account.id]);
  const token = await createSession(account.id);
  return { token, account: { id: account.id, username: account.username, role: account.role } };
}

const server = http.createServer(async (req, res) => {
  cors(req, res);
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  const path = new URL(req.url, 'http://localhost').pathname;

  try {
    if (req.method === 'GET' && (path === '/' || path === '/health')) {
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
      return res.end('Cave Game account + multiplayer server is running\n');
    }
    if (req.method === 'GET' && path === '/api/health') {
      await pool.query('SELECT 1');
      return sendJson(res, 200, { ok: true, database: true });
    }
    if (req.method === 'POST' && (path === '/api/register' || path === '/api/login')) {
      const action = path.endsWith('/register') ? 'register' : 'login';
      if (!rateAllowed(req, action)) return sendJson(res, 429, { ok: false, error: 'Too many attempts. Please wait 15 minutes and try again.' });
      const body = await readJson(req);
      const result = action === 'register' ? await registerAccount(body) : await loginAccount(body);
      return sendJson(res, 200, { ok: true, token: result.token, account: result.account });
    }
    if (req.method === 'GET' && path === '/api/me') {
      const account = await getAccountForToken(bearerToken(req));
      if (!account) return sendJson(res, 401, { ok: false, error: 'Your session expired. Please sign in again.' });
      return sendJson(res, 200, { ok: true, account });
    }
    if (req.method === 'POST' && path === '/api/logout') {
      const token = bearerToken(req);
      if (token) await pool.query('UPDATE account_sessions SET revoked_at = NOW() WHERE token_hash = $1 AND revoked_at IS NULL', [tokenHash(token)]);
      return sendJson(res, 200, { ok: true });
    }

    // Account-owned singleplayer worlds. Every query is scoped by the authenticated account ID.
    const worldRoute = /^\/api\/worlds(?:\/([^/]+))?$/.exec(path);
    if (worldRoute) {
      const account = await getAccountForToken(bearerToken(req));
      if (!account) return sendJson(res, 401, { ok: false, error: 'Sign in again to access your saved worlds.' });
      let worldId = null;
      if (worldRoute[1]) {
        try { worldId = decodeURIComponent(worldRoute[1]); }
        catch { throw Object.assign(new Error('Invalid world ID.'), { status: 400 }); }
        if (!/^[A-Za-z0-9_-]{1,80}$/.test(worldId)) {
          throw Object.assign(new Error('Invalid world ID.'), { status: 400 });
        }
      }

      if (req.method === 'GET' && !worldId) {
        const result = await pool.query(
          `SELECT world_id AS id, name, seed, mode, room_code AS "roomCode", thumb,
                  (EXTRACT(EPOCH FROM created_at) * 1000)::double precision AS created,
                  (EXTRACT(EPOCH FROM updated_at) * 1000)::double precision AS last
             FROM account_worlds
            WHERE account_id = $1
            ORDER BY updated_at DESC, id DESC`,
          [account.id]
        );
        return sendJson(res, 200, { ok: true, worlds: result.rows });
      }

      if (req.method === 'GET' && worldId) {
        const result = await pool.query(
          'SELECT world_data FROM account_worlds WHERE account_id = $1 AND world_id = $2 LIMIT 1',
          [account.id, worldId]
        );
        if (!result.rowCount) return sendJson(res, 404, { ok: false, error: 'World not found in this account.' });
        return sendJson(res, 200, { ok: true, world: result.rows[0].world_data });
      }

      if (req.method === 'PUT' && worldId) {
        const body = await readJson(req, WORLD_REQUEST_LIMIT);
        const world = body && body.world && typeof body.world === 'object' ? body.world : body;
        if (!world || typeof world !== 'object' || Array.isArray(world)) {
          throw Object.assign(new Error('World data must be a JSON object.'), { status: 400 });
        }
        if (String(world.id || '') !== worldId) {
          throw Object.assign(new Error('World ID does not match the save URL.'), { status: 400 });
        }
        const serialized = JSON.stringify(world);
        if (Buffer.byteLength(serialized, 'utf8') > WORLD_JSON_LIMIT) {
          throw Object.assign(new Error('This world save is larger than the 20 MB account-save limit.'), { status: 413 });
        }
        const name = String(world.name || 'New World').trim().slice(0, 64) || 'New World';
        const seed = String(world.seed == null ? '' : world.seed).slice(0, 128);
        const mode = ['survival', 'creative', 'hardcore'].includes(String(world.mode)) ? String(world.mode) : 'survival';
        const roomCode = String(world.roomCode || '').trim().slice(0, 40);
        const thumb = typeof world.thumb === 'string' ? world.thumb.slice(0, 500000) : '';
        const createdAt = new Date(Number(world.created) > 0 ? Number(world.created) : Date.now());
        await pool.query(
          `INSERT INTO account_worlds
             (account_id, world_id, name, seed, mode, room_code, thumb, world_data, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, NOW())
           ON CONFLICT (account_id, world_id) DO UPDATE SET
             name = EXCLUDED.name,
             seed = EXCLUDED.seed,
             mode = EXCLUDED.mode,
             room_code = EXCLUDED.room_code,
             thumb = EXCLUDED.thumb,
             world_data = EXCLUDED.world_data,
             updated_at = NOW()`,
          [account.id, worldId, name, seed, mode, roomCode, thumb, serialized, createdAt]
        );
        return sendJson(res, 200, {
          ok: true,
          world: { id: worldId, name, seed, mode, roomCode, thumb, created: createdAt.getTime(), last: Date.now() }
        });
      }

      if (req.method === 'DELETE' && worldId) {
        const result = await pool.query(
          'DELETE FROM account_worlds WHERE account_id = $1 AND world_id = $2',
          [account.id, worldId]
        );
        if (!result.rowCount) return sendJson(res, 404, { ok: false, error: 'World not found in this account.' });
        return sendJson(res, 200, { ok: true, deleted: worldId });
      }
      return sendJson(res, 405, { ok: false, error: 'Method not allowed for this world route.' });
    }

    if (req.method === 'POST' && path.startsWith('/api/owner/')) {
      const actor = await requireOwner(req);
      const body = await readJson(req);

      if (path === '/api/owner/overview') {
        const accountsResult = await pool.query(
          `SELECT a.id::text AS id, a.username, a.role, a.created_at, a.last_login_at,
                  COUNT(*) OVER() AS total_count,
                  (b.id IS NOT NULL) AS is_banned, b.reason AS ban_reason, b.expires_at AS ban_expires_at
             FROM accounts a
             LEFT JOIN LATERAL (
               SELECT id, reason, expires_at FROM account_bans
                WHERE account_id = a.id AND revoked_at IS NULL
                  AND (expires_at IS NULL OR expires_at > NOW())
                ORDER BY created_at DESC LIMIT 1
             ) b ON TRUE
            ORDER BY a.created_at DESC LIMIT 250`
        );
        const online = [];
        for (const r of rooms.values()) {
          for (const ws of r.clients.values()) {
            if (ws.account) online.push({
              accountId: String(ws.account.id), username: ws.account.username,
              role: ws.account.role, room: ws.roomName, playerId: ws.id,
              joinedAt: ws.joinedAt || Date.now()
            });
          }
        }
        online.sort((a, b) => a.username.localeCompare(b.username));
        return sendJson(res, 200, { ok: true, accounts: accountsResult.rows, online, accountCount: Number(accountsResult.rows[0] && accountsResult.rows[0].total_count || 0) });
      }

      if (path === '/api/owner/kick') {
        const target = await getManageableAccount(body.accountId, actor);
        const count = disconnectAccount(target.id, 'You were kicked by the server owner.');
        return sendJson(res, 200, { ok: true, disconnected: count, message: count ? 'Player kicked.' : 'That account is not online.' });
      }

      if (path === '/api/owner/ban') {
        const target = await getManageableAccount(body.accountId, actor);
        const reason = typeof body.reason === 'string' ? body.reason.trim().slice(0, 200) : '';
        let expiresAt = null;
        if (body.durationHours !== null && body.durationHours !== '') {
          const hours = Number(body.durationHours);
          if (!Number.isFinite(hours) || hours < 1 || hours > 8760) {
            throw Object.assign(new Error('Ban duration must be 1–8760 hours, or blank for permanent.'), { status: 400 });
          }
          expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000);
        }
        await pool.query(
          `UPDATE account_bans SET revoked_at = NOW(), revoked_by = $2
            WHERE account_id = $1 AND revoked_at IS NULL`, [target.id, actor.id]
        );
        await pool.query(
          'INSERT INTO account_bans (account_id, reason, banned_by, expires_at) VALUES ($1, $2, $3, $4)',
          [target.id, reason, actor.id, expiresAt]
        );
        // Revoke existing sessions as well, so unbanning requires a fresh sign-in.
        await pool.query(
          'UPDATE account_sessions SET revoked_at = NOW() WHERE account_id = $1 AND revoked_at IS NULL',
          [target.id]
        );
        const disconnected = disconnectAccount(target.id, 'You were banned by the server owner.');
        return sendJson(res, 200, { ok: true, disconnected, message: 'Account banned.' });
      }

      if (path === '/api/owner/unban') {
        const target = await getManageableAccount(body.accountId, actor);
        const result = await pool.query(
          `UPDATE account_bans SET revoked_at = NOW(), revoked_by = $2
            WHERE account_id = $1 AND revoked_at IS NULL`, [target.id, actor.id]
        );
        return sendJson(res, 200, { ok: true, changed: result.rowCount, message: 'Active bans cleared.' });
      }

      if (path === '/api/owner/role') {
        const target = await getManageableAccount(body.accountId, actor);
        const role = String(body.role || '').toLowerCase();
        if (!['player', 'moderator', 'admin'].includes(role)) {
          throw Object.assign(new Error('Choose Player, Moderator, or Admin.'), { status: 400 });
        }
        const result = await pool.query(
          `UPDATE accounts SET role = $1 WHERE id = $2 AND role <> 'owner'
           RETURNING id::text AS id, username, role`, [role, target.id]
        );
        if (!result.rowCount) throw Object.assign(new Error('That account could not be changed.'), { status: 409 });
        for (const ws of wss.clients) {
          if (ws.account && String(ws.account.id) === String(target.id)) {
            ws.account.role = role;
            send(ws, { t: 'r', role });
          }
        }
        return sendJson(res, 200, { ok: true, account: result.rows[0], message: 'Role updated.' });
      }

      return sendJson(res, 404, { ok: false, error: 'Unknown Owner Panel action.' });
    }
    return sendJson(res, 404, { ok: false, error: 'Not found.' });
  } catch (err) {
    const status = Number(err.status) || (err.code ? 503 : 500);
    if (status >= 500) console.error('HTTP request failed:', err.message);
    return sendJson(res, status, { ok: false, error: status === 500 ? 'Server error. Please try again.' : err.message });
  }
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
  ws.alive = true; ws.rate = 0; ws.room = null; ws.id = null; ws.state = null; ws.dirty = false; ws.needAll = false; ws.joining = false; ws.account = null;
  ws.on('pong', () => { ws.alive = true; });
  ws.authTimer = setTimeout(() => { if (!ws.account && !ws.joining) ws.close(4001, 'authentication required'); }, 12000);
  ws.on('message', async (buf) => {
    if (++ws.rate > 80) return;
    let m; try { m = JSON.parse(buf); } catch { return; }
    if (!m || typeof m.t !== 'string') return;

    if (m.t === 'h') { // Authenticated hello: the account username is authoritative.
      if (ws.room || ws.joining) return;
      ws.joining = true;
      try {
        const account = await getAccountForToken(m.token);
        if (ws.readyState !== 1) return;
        if (!account) {
          send(ws, { t: 'a', ok: false, message: 'Please sign in again before joining multiplayer.' });
          ws.close(4001, 'authentication required');
          return;
        }
        const name = String(m.room || 'main').toLowerCase().replace(/[^a-z0-9_.-]/g, '').slice(0, 40) || 'main';
        const r = room(name);
        if (r.clients.size >= MAX_PLAYERS) { ws.close(1013, 'room full'); return; }
        clearTimeout(ws.authTimer);
        ws.account = account;
        ws.name = account.username;
        ws.room = r; ws.roomName = name; ws.id = 'p' + (nextId++); ws.joinedAt = Date.now();
        r.clients.set(ws.id, ws);
        send(ws, { t: 'w', id: ws.id, n: r.clients.size, account: { username: account.username, role: account.role } });
        const all = [...r.edits.values()];
        for (let i = 0; i < all.length; i += 400) send(ws, { t: 'e', l: all.slice(i, i + 400) });
        ws.needAll = true;
      } catch (err) {
        console.error('WebSocket authentication failed:', err.message);
        send(ws, { t: 'a', ok: false, message: 'Could not verify your account. Please try again.' });
        ws.close(1011, 'authentication check failed');
      } finally {
        ws.joining = false;
      }
      return;
    }
    if (!ws.room || !ws.account) return;

    if (m.t === 's' && m.s) { // player state
      const s = m.s;
      ws.state = { n: ws.name, x: num(s.x, -3e7, 3e7), y: num(s.y, -64, 512), z: num(s.z, -3e7, 3e7),
                   yw: num(s.yw, -10, 10), pt: num(s.pt, -2, 2), sk: String(s.sk || 'steve').replace(/[^a-z]/g, '').slice(0, 12), hd: num(s.hd, 0, 65535) | 0 };
      ws.dirty = true;
    } else if (m.t === 'e' && Array.isArray(m.l)) { // block edits
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
    } else if (m.t === 'c' && typeof m.m === 'string') { // chat
      const text = m.m.slice(0, 90);
      for (const c of ws.room.clients.values()) if (c !== ws) send(c, { t: 'c', n: ws.name, m: text });
    }
  });
  ws.on('close', () => {
    clearTimeout(ws.authTimer);
    if (!ws.room) return;
    ws.room.clients.delete(ws.id);
    for (const c of ws.room.clients.values()) send(c, { t: 'l', id: ws.id });
    if (ws.room.clients.size === 0) rooms.delete(ws.roomName);
  });
});

// one batched message per client per tick (only changed players)
setInterval(() => {
  for (const r of rooms.values()) {
    const dirty = [];
    for (const c of r.clients.values()) if (c.dirty && c.state) dirty.push([c.id, c.state]);
    for (const c of r.clients.values()) {
      let list = dirty.filter((q) => q[0] !== c.id);
      if (c.needAll) { list = [...r.clients.values()].filter((o) => o !== c && o.state).map((o) => [o.id, o.state]); c.needAll = false; }
      if (list.length) send(c, { t: 'p', l: list });
    }
    for (const c of r.clients.values()) c.dirty = false;
  }
}, TICK_MS);

// Once a second: reset rate limits, drop dead connections, and prune old auth throttles.
setInterval(() => {
  for (const ws of wss.clients) {
    ws.rate = 0;
    if (!ws.alive) { ws.terminate(); continue; }
    ws.alive = false; try { ws.ping(); } catch {}
  }
  const cutoff = Date.now() - AUTH_RATE_WINDOW;
  for (const [key, value] of authRates) if (value.start < cutoff) authRates.delete(key);
}, 1000);

async function start() {
  await pool.query('SELECT 1');
  await pool.query(SCHEMA_SQL);
  server.listen(PORT, () => console.log('Cave Game account + multiplayer server listening on port ' + PORT));
}
start().catch((err) => {
  console.error('Could not start Cave Game server / initialize Neon:', err.message);
  process.exit(1);
});

process.on('SIGTERM', async () => {
  try { await pool.end(); } catch {}
  process.exit(0);
});
