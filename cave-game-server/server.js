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
const guestJoinRates = new Map();
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
  if (!r) {
    const now = Date.now();
    r = {
      clients: new Map(), edits: new Map(), hostId: null, mobState: [], signs: new Map(),
      clock: { tod: 0.1, dayNum: 0, dayLength: 1200, daylight: true, lastAt: now, lastBroadcast: 0, initialized: false },
      weather: { type: 'clear', until: now + 900000 },
      rules: { doDaylightCycle: true, doWeatherCycle: true, doMobSpawning: true },
      difficulty: 'normal'
    };
    rooms.set(name, r);
  }
  return r;
}
const send = (ws, o) => { if (ws.readyState === 1) ws.send(JSON.stringify(o)); };
const num = (v, lo, hi) => (Number.isFinite(+v) ? Math.min(hi, Math.max(lo, +v)) : 0);
function roomState(r) {
  const now = Date.now();
  return {
    t: 'room', tod: r.clock.tod, dayNum: r.clock.dayNum, dayLength: r.clock.dayLength,
    weather: r.weather.type, weatherLeft: Math.max(0, r.weather.until - now) / 1000,
    rules: r.rules, difficulty: r.difficulty, hostId: r.hostId
  };
}
function broadcastRoom(r) { const msg = roomState(r); for (const c of r.clients.values()) send(c, msg); }
function broadcastHost(r) { for (const c of r.clients.values()) send(c, { t: 'host', id: r.hostId, you: c.id === r.hostId }); }
function attachRoomClient(ws, r, roomName) {
  ws.room = r; ws.roomName = roomName; ws.id = 'p' + (nextId++); ws.joinedAt = Date.now();
  r.clients.set(ws.id, ws);
  if (!r.hostId) r.hostId = ws.id;
  send(ws, {
    t: 'w', id: ws.id, n: r.clients.size, guest: !!ws.guest, name: ws.name,
    account: ws.account ? { username: ws.account.username, role: ws.account.role } : undefined,
    role: ws.account ? ws.account.role : 'guest', host: ws.id === r.hostId, hostId: r.hostId
  });
  const all = [...r.edits.values()];
  for (let i = 0; i < all.length; i += 400) send(ws, { t: 'e', l: all.slice(i, i + 400) });
  if (r.signs.size) send(ws, { t: 'signs', l: [...r.signs.values()] });
  if (r.mobState.length) send(ws, { t: 'mobs', l: r.mobState });
  send(ws, roomState(r));
  ws.needAll = true;
  broadcastHost(r);
}
function validMobState(list) {
  if (!Array.isArray(list)) return [];
  return list.slice(0, 64).map((m) => {
    if (!m || typeof m !== 'object') return null;
    const id = String(m.id || '').slice(0, 40), kind = String(m.kind || '').replace(/[^a-z_]/g, '').slice(0, 24);
    const type = m.type === 'animal' ? 'animal' : 'mob';
    if (!/^[A-Za-z0-9_.:-]{1,40}$/.test(id) || !/^[a-z_]{1,24}$/.test(kind)) return null;
    return { id, type, kind, x: num(m.x, -3e7, 3e7), y: num(m.y, -64, 512), z: num(m.z, -3e7, 3e7), yaw: num(m.yaw, -20, 20), hp: num(m.hp, 0, 1000), dim: num(m.dim, 0, 1) | 0 };
  }).filter(Boolean);
}
async function handleRoomCommand(ws, raw) {
  const reply = (text, ok = true) => send(ws, { t: 'cmd', ok, text: String(text).slice(0, 240) });
  const role = ws.account && ws.account.role;
  if (!ws.account || !['admin', 'owner'].includes(role)) { reply('Permission denied: only Admins and the Owner can use multiplayer commands.', false); return; }
  const words = String(raw || '').trim().replace(/^\//, '').match(/(?:[^\s"]+|"[^"]*")+/g) || [];
  const a = words.map(v => v.replace(/^"|"$/g, ''));
  const cmd = (a.shift() || '').toLowerCase(), r = ws.room;
  if (!r || !cmd) return;
  const findPlayer = (name) => [...r.clients.values()].find(c => c.name.toLowerCase() === String(name || '').toLowerCase());
  const canModerate = (target) => {
    if (!target || target === ws) return false;
    if (!target.account) return true;
    if (target.account.role === 'owner') return false;
    return role === 'owner' || !['admin'].includes(target.account.role);
  };
  if (cmd === 'help') { reply('Admin commands: /list, /say <message>, /kick <player>, /ban <username> [1h|1d|7d|permanent], /time set|add <value>, /weather clear|cloudy|rain|thunder, /difficulty peaceful|normal, /gamerule <rule> true|false, /op and /deop (Owner only). Gameplay commands are also Admin/Owner-only.'); return; }
  if (cmd === 'list') { reply('Online (' + r.clients.size + '): ' + [...r.clients.values()].map(c => c.name + (c.account ? ' [' + c.account.role + ']' : ' [guest]')).join(', ')); return; }
  if (cmd === 'say') { const text = a.join(' ').slice(0, 180); if (!text) { reply('Usage: /say <message>', false); return; } for (const c of r.clients.values()) send(c, { t: 'c', n: 'Server', m: text }); return; }
  if (cmd === 'kick') {
    const target = findPlayer(a[0]); if (!target) { reply('Player not found in this room.', false); return; }
    if (!canModerate(target)) { reply('You cannot kick that account.', false); return; }
    send(target, { t: 'x', message: 'You were kicked by ' + ws.name + '.' }); target.close(4003, 'kicked by moderator');
    reply('Kicked ' + target.name + '.'); return;
  }
  if (cmd === 'ban') {
    const username = String(a[0] || '').trim();
    if (!/^[A-Za-z0-9_.-]{3,16}$/.test(username)) { reply('Usage: /ban <username> [1h|1d|7d|permanent] [reason]', false); return; }
    const found = await pool.query('SELECT id, username, role FROM accounts WHERE username_norm = $1 LIMIT 1', [username.toLowerCase()]);
    const target = found.rows[0]; if (!target) { reply('Account not found. Guests can be removed with /kick.', false); return; }
    if (String(target.id) === String(ws.account.id) || target.role === 'owner' || (role !== 'owner' && target.role === 'admin')) { reply('You cannot ban that account.', false); return; }
    let duration = null, reasonParts = a.slice(1);
    const dm = /^(\d+)(m|h|d)$/i.exec(reasonParts[0] || '');
    if ((reasonParts[0] || '').toLowerCase() === 'permanent') { duration = null; reasonParts.shift(); }
    else if (dm) { const n = Number(dm[1]), unit = dm[2].toLowerCase(), mins = n * (unit === 'm' ? 1 : unit === 'h' ? 60 : 1440); if (mins < 1 || mins > 525600) { reply('Ban duration must be between 1 minute and 365 days.', false); return; } duration = new Date(Date.now() + mins * 60000); reasonParts.shift(); }
    const reason = reasonParts.join(' ').slice(0, 200) || ('Banned by ' + ws.name);
    await pool.query('UPDATE account_bans SET revoked_at = NOW(), revoked_by = $2 WHERE account_id = $1 AND revoked_at IS NULL', [target.id, ws.account.id]);
    await pool.query('INSERT INTO account_bans (account_id, reason, banned_by, expires_at) VALUES ($1, $2, $3, $4)', [target.id, reason, ws.account.id, duration]);
    await pool.query('UPDATE account_sessions SET revoked_at = NOW() WHERE account_id = $1 AND revoked_at IS NULL', [target.id]);
    const disconnected = disconnectAccount(target.id, 'You were banned by ' + ws.name + '.');
    reply('Banned ' + target.username + (duration ? ' until ' + duration.toISOString() : ' permanently') + '. Disconnected ' + disconnected + ' session(s).'); return;
  }
  if (cmd === 'op' || cmd === 'deop') {
    if (role !== 'owner') { reply('Only the Owner can change account roles.', false); return; }
    const username = String(a[0] || '').toLowerCase();
    if (!/^[a-z0-9_.-]{3,16}$/.test(username)) { reply('Usage: /' + cmd + ' <username>', false); return; }
    const targetRole = cmd === 'op' ? 'admin' : 'player';
    const upd = await pool.query("UPDATE accounts SET role = $1 WHERE username_norm = $2 AND role <> 'owner' RETURNING id, username, role", [targetRole, username]);
    if (!upd.rowCount) { reply('Account not found or protected.', false); return; }
    for (const c of wss.clients) if (c.account && String(c.account.id) === String(upd.rows[0].id)) { c.account.role = targetRole; send(c, { t: 'r', role: targetRole }); }
    reply(upd.rows[0].username + ' is now ' + targetRole + '.'); return;
  }
  if (cmd === 'unban') {
    if (role !== 'owner') { reply('Only the Owner can unban accounts.', false); return; }
    const username = String(a[0] || '').toLowerCase();
    if (!/^[a-z0-9_.-]{3,16}$/.test(username)) { reply('Usage: /unban <username>', false); return; }
    const q = await pool.query('UPDATE account_bans b SET revoked_at = NOW(), revoked_by = $1 FROM accounts a WHERE b.account_id = a.id AND a.username_norm = $2 AND b.revoked_at IS NULL', [ws.account.id, username]);
    reply('Cleared ' + q.rowCount + ' active ban(s).'); return;
  }
  if (cmd === 'time') {
    const sub = (a[0] || '').toLowerCase(), val = (a[1] || '').toLowerCase();
    const presets = { day: 1000, noon: 6000, night: 13000, midnight: 18000, sunrise: 23000, sunset: 12000 };
    let n = presets[val] != null ? presets[val] : Number(val);
    if (sub !== 'set' && sub !== 'add' || !Number.isFinite(n)) { reply('Usage: /time set|add <day|night|ticks>', false); return; }
    if (sub === 'add') n += r.clock.tod * 24000;
    r.clock.tod = ((n % 24000) + 24000) % 24000 / 24000; r.clock.dayNum = Math.max(0, r.clock.dayNum + (sub === 'set' ? Math.floor(n / 24000) : Math.floor(n / 24000)));
    r.clock.lastAt = Date.now(); broadcastRoom(r); reply('Room time set to ' + Math.round(r.clock.tod * 24000) + '.'); return;
  }
  if (cmd === 'weather') {
    const type = String(a[0] || '').toLowerCase(); if (!['clear', 'cloudy', 'rain', 'thunder'].includes(type)) { reply('Usage: /weather clear|cloudy|rain|thunder [seconds]', false); return; }
    const sec = Math.max(30, Math.min(86400, Number(a[1]) || 600)); r.weather = { type, until: Date.now() + sec * 1000 }; broadcastRoom(r); reply('Room weather set to ' + type + '.'); return;
  }
  if (cmd === 'difficulty') {
    const v = String(a[0] || '').toLowerCase(); if (!['peaceful', 'normal'].includes(v)) { reply('This build supports /difficulty peaceful|normal.', false); return; }
    r.difficulty = v; broadcastRoom(r); reply('Room difficulty set to ' + v + '.'); return;
  }
  if (cmd === 'gamerule') {
    const key = String(a[0] || '').toLowerCase(), val = String(a[1] || '').toLowerCase() !== 'false';
    const aliases = { dodaylightcycle: 'doDaylightCycle', doweathercycle: 'doWeatherCycle', domobspawning: 'doMobSpawning' };
    const prop = aliases[key]; if (!prop || !['true', 'false'].includes(String(a[1] || '').toLowerCase())) { reply('Usage: /gamerule doDaylightCycle|doWeatherCycle|doMobSpawning true|false', false); return; }
    r.rules[prop] = val; broadcastRoom(r); reply('Gamerule ' + prop + ' = ' + val + '.'); return;
  }
  const localCommands = new Set(['gamemode', 'gm', 'give', 'tp', 'teleport', 'effect', 'clear', 'xp', 'experience', 'heal', 'feed', 'spawnpoint', 'kill']);
  const hostCommands = new Set(['summon', 'setblock', 'fill']);
  // Entity-wide kill commands must execute on the room host so the authoritative mob simulation changes once.
  if (cmd === 'kill' && /^@(e|a|p)(?:\[|$)/.test(String(a[0] || '').toLowerCase())) hostCommands.add('kill');
  if (localCommands.has(cmd) && !hostCommands.has(cmd)) { send(ws, { t: 'exec', command: '/' + [cmd, ...a].join(' ') }); reply('Command accepted.'); return; }
  if (hostCommands.has(cmd)) {
    const host = r.clients.get(r.hostId);
    if (!host) { reply('Room host is not connected.', false); return; }
    send(host, { t: 'exec', command: '/' + [cmd, ...a].join(' ') }); reply('World command sent to room host.'); return;
  }
  reply('Unknown or unsupported multiplayer command: /' + cmd, false);
}
function guestJoinAllowed(ws) {
  const ip = String(ws._socket && ws._socket.remoteAddress || 'unknown').slice(0, 80);
  const now = Date.now();
  let entry = guestJoinRates.get(ip);
  if (!entry || now - entry.start >= 60_000) entry = { start: now, count: 0 };
  entry.count++;
  guestJoinRates.set(ip, entry);
  return entry.count <= 20; // temporary guests: modest per-IP join throttle
}
function makeGuestName(raw, r) {
  const supplied = String(raw || '').trim();
  if (!/^[A-Za-z0-9_.-]{3,10}$/.test(supplied)) return null;
  const base = 'Guest-' + supplied;
  const used = new Set([...r.clients.values()].map((c) => String(c.name || '').toLowerCase()));
  if (!used.has(base.toLowerCase())) return base;
  for (let i = 2; i < 100; i++) {
    const suffix = String(i);
    const candidate = (base.slice(0, 16 - suffix.length) + suffix).slice(0, 16);
    if (!used.has(candidate.toLowerCase())) return candidate;
  }
  return null;
}

wss.on('connection', (ws) => {
  ws.alive = true; ws.rate = 0; ws.room = null; ws.id = null; ws.state = null; ws.dirty = false; ws.needAll = false; ws.joining = false; ws.account = null; ws.guest = false; ws.name = '';
  ws.on('pong', () => { ws.alive = true; });
  ws.authTimer = setTimeout(() => { if (!ws.account && !ws.guest && !ws.joining) ws.close(4001, 'authentication required'); }, 12000);
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
        attachRoomClient(ws, r, name);
      } catch (err) {
        console.error('WebSocket authentication failed:', err.message);
        send(ws, { t: 'a', ok: false, message: 'Could not verify your account. Please try again.' });
        ws.close(1011, 'authentication check failed');
      } finally {
        ws.joining = false;
      }
      return;
    }
    if (m.t === 'g') { // Temporary guest hello: no account, database session, or account privileges.
      if (ws.room || ws.joining) return;
      if (!guestJoinAllowed(ws)) {
        send(ws, { t: 'a', ok: false, message: 'Too many guest joins from this network. Please wait a minute.' });
        ws.close(4429, 'guest rate limit');
        return;
      }
      ws.joining = true;
      try {
        const nameRoom = String(m.room || 'main').toLowerCase().replace(/[^a-z0-9_.-]/g, '').slice(0, 40) || 'main';
        const r = room(nameRoom);
        if (r.clients.size >= MAX_PLAYERS) { ws.close(1013, 'room full'); return; }
        const guestName = makeGuestName(m.name, r);
        if (!guestName) {
          send(ws, { t: 'a', ok: false, message: 'Guest name must be 3–10 letters, numbers, dots, underscores or hyphens.' });
          ws.close(4400, 'invalid guest name');
          return;
        }
        clearTimeout(ws.authTimer);
        ws.guest = true;
        ws.name = guestName;
        attachRoomClient(ws, r, nameRoom);
      } catch (err) {
        console.error('WebSocket guest join failed:', err.message);
        send(ws, { t: 'a', ok: false, message: 'Could not join as a guest. Please try again.' });
        ws.close(1011, 'guest join failed');
      } finally {
        ws.joining = false;
      }
      return;
    }
    if (!ws.room || (!ws.account && !ws.guest)) return;

    if (m.t === 's' && m.s) { // player state
      const s = m.s;
      const dg = Array.isArray(s.dg) && s.dg.length >= 5 ? [num(s.dg[0], -3e7, 3e7) | 0, num(s.dg[1], -64, 512) | 0, num(s.dg[2], -3e7, 3e7) | 0, num(s.dg[3], 0, 0.99), num(s.dg[4], 0, 1) | 0] : null;
      ws.state = { n: ws.name, x: num(s.x, -3e7, 3e7), y: num(s.y, -64, 512), z: num(s.z, -3e7, 3e7),
                   yw: num(s.yw, -10, 10), pt: num(s.pt, -2, 2), sk: String(s.sk || 'steve').replace(/[^a-z]/g, '').slice(0, 12),
                   hd: num(s.hd, 0, 65535) | 0, ar: String(s.ar || '').slice(0, 24), oh: num(s.oh, 0, 65535) | 0,
                   bk: s.bk ? 1 : 0, dg };
      ws.dirty = true;
    } else if (m.t === 'clock' && ws.id === ws.room.hostId) {
      const c = ws.room.clock, first = !c.initialized;
      if (first || m.force) {
        c.tod = num(m.tod, 0, 0.999999); c.dayNum = num(m.dayNum, 0, 1e7) | 0;
        c.dayLength = num(m.dayLength, 60, 86400); c.initialized = true; c.lastAt = Date.now();
        if (first && typeof m.weather === 'string' && ['clear','cloudy','rain','thunder'].includes(m.weather)) ws.room.weather = { type: m.weather, until: Date.now() + 600000 };
        if (m.rules && typeof m.rules === 'object') for (const k of ['doDaylightCycle','doWeatherCycle','doMobSpawning']) if (typeof m.rules[k] === 'boolean') ws.room.rules[k] = m.rules[k];
        if (['peaceful','normal'].includes(m.difficulty)) ws.room.difficulty = m.difficulty;
        broadcastRoom(ws.room);
      }
    } else if (m.t === 'mobs' && ws.id === ws.room.hostId) {
      const list = validMobState(m.l); ws.room.mobState = list;
      for (const c of ws.room.clients.values()) if (c !== ws) send(c, { t: 'mobs', l: list });
    } else if (m.t === 'mh') {
      const id = String(m.id || '').slice(0, 40), mob = ws.room.mobState.find(v => v.id === id);
      const sx = ws.state ? ws.state.x : 0, sz = ws.state ? ws.state.z : 0;
      const damage = num(m.damage, 0, 25);
      if (mob && damage > 0 && Math.hypot(sx - mob.x, sz - mob.z) <= 8) {
        const host = ws.room.clients.get(ws.room.hostId);
        if (host) send(host, { t: 'mh', id, damage, x: sx, z: sz });
      }
    } else if (m.t === 'sign' && m.sign && typeof m.sign === 'object') {
      const v = m.sign, x = num(v.x, -3e7, 3e7) | 0, y = num(v.y, 0, 255) | 0, z = num(v.z, -3e7, 3e7) | 0, dim = num(v.dim, 0, 1) | 0;
      const lines = Array.isArray(v.lines) ? v.lines.slice(0, 4).map(q => String(q || '').replace(/[\x00-\x1f]/g, '').slice(0, 15)) : [];
      while (lines.length < 4) lines.push('');
      const sign = { x, y, z, dim, lines, wall: !!v.wall, hanging: !!v.hanging, rotation: num(v.rotation, 0, 15) | 0 };
      ws.room.signs.set(dim + ':' + x + ',' + y + ',' + z, sign);
      for (const c of ws.room.clients.values()) if (c !== ws) send(c, { t: 'sign', sign });
    } else if (m.t === 'cmd' && typeof m.m === 'string') {
      try { await handleRoomCommand(ws, m.m.slice(0, 200)); }
      catch (err) { console.error('Room command failed:', err.message); send(ws, { t: 'cmd', ok: false, text: 'Command failed on the server.' }); }
    } else if (m.t === 'e' && Array.isArray(m.l)) { // block edits
      const out = [];
      for (const q of m.l.slice(0, 200)) {
        if (!Array.isArray(q) || q.length < 4) continue;
        const x = q[0] | 0, y = q[1] | 0, z = q[2] | 0, v = q[3] | 0;
        if (y < 0 || y > 255 || v < 0 || v > 65535 || Math.abs(x) > 3e7 || Math.abs(z) > 3e7) continue;
        out.push([x, y, z, v]);
        ws.room.edits.set(x + ',' + y + ',' + z, [x, y, z, v]);
        const dim = v >= 32768 ? 1 : 0;
        ws.room.signs.delete(dim + ':' + x + ',' + y + ',' + z);
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
    const r = ws.room;
    r.clients.delete(ws.id);
    for (const c of r.clients.values()) send(c, { t: 'l', id: ws.id });
    if (r.hostId === ws.id) {
      r.hostId = r.clients.size ? r.clients.keys().next().value : null;
      broadcastHost(r);
    }
    if (r.clients.size === 0) rooms.delete(ws.roomName);
  });
});

// one batched message per client per tick (only changed players)
setInterval(() => {
  const now = Date.now();
  for (const r of rooms.values()) {
    const elapsed = Math.max(0, Math.min(1000, now - (r.clock.lastAt || now)));
    r.clock.lastAt = now;
    if (r.rules.doDaylightCycle) {
      const next = r.clock.tod + elapsed / (Math.max(60, r.clock.dayLength) * 1000);
      if (next >= 1) r.clock.dayNum += Math.floor(next);
      r.clock.tod = next % 1;
    }
    if (r.rules.doWeatherCycle && now >= r.weather.until) {
      const roll = Math.random();
      const type = roll < 0.65 ? 'clear' : roll < 0.8 ? 'cloudy' : roll < 0.95 ? 'rain' : 'thunder';
      r.weather = { type, until: now + (type === 'clear' ? 900000 : 300000) };
    }
    const dirty = [];
    for (const c of r.clients.values()) if (c.dirty && c.state) dirty.push([c.id, c.state]);
    for (const c of r.clients.values()) {
      let list = dirty.filter((q) => q[0] !== c.id);
      if (c.needAll) { list = [...r.clients.values()].filter((o) => o !== c && o.state).map((o) => [o.id, o.state]); c.needAll = false; }
      if (list.length) send(c, { t: 'p', l: list });
    }
    for (const c of r.clients.values()) c.dirty = false;
    if (now - (r.clock.lastBroadcast || 0) >= 1000) { r.clock.lastBroadcast = now; broadcastRoom(r); }
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
  const guestCutoff = Date.now() - 60_000;
  for (const [key, value] of guestJoinRates) if (value.start < guestCutoff) guestJoinRates.delete(key);
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
