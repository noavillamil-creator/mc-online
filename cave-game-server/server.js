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
const WORLD_BODY_LIMIT = 8 * 1024 * 1024;
const ROOM_EDITS_BODY_LIMIT = 2 * 1024 * 1024;
const SKIN_LIMIT = 250 * 1024;
const MAX_ROOM_EDITS = 100000;
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
  account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  world_id TEXT NOT NULL,
  world_data JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_played_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (account_id, world_id)
);
CREATE INDEX IF NOT EXISTS account_worlds_last_played_idx ON account_worlds(account_id, last_played_at DESC);
CREATE TABLE IF NOT EXISTS account_skins (
  account_id BIGINT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  png_data BYTEA NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS account_profiles (
  account_id BIGINT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  playtime_seconds BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS room_world_edits (
  room_code TEXT PRIMARY KEY,
  edits JSONB NOT NULL DEFAULT '[]'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS chat_reports (
  id BIGSERIAL PRIMARY KEY,
  reporter_account_id BIGINT REFERENCES accounts(id) ON DELETE SET NULL,
  reporter_name TEXT NOT NULL,
  target_account_id BIGINT REFERENCES accounts(id) ON DELETE SET NULL,
  target_name TEXT NOT NULL,
  room_code TEXT NOT NULL,
  reason TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'reviewed', 'dismissed')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS chat_reports_status_created_idx ON chat_reports(status, created_at DESC);
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
function readJson(req, limit = BODY_LIMIT) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
      if (Buffer.byteLength(raw) > limit) {
        reject(Object.assign(new Error('Request is too large.'), { status: 413 }));
        req.destroy();
      }
    });
    req.on('end', () => {
      try { resolve(raw ? JSON.parse(raw) : {}); }
      catch { reject(Object.assign(new Error('Invalid JSON.'), { status: 400 })); }
    });
    req.on('error', reject);
  });
}
function rateAllowed(req, key, max = AUTH_RATE_LIMIT) {
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
  const id = key + ':' + ip;
  const now = Date.now();
  let entry = authRates.get(id);
  if (!entry || now - entry.start > AUTH_RATE_WINDOW) entry = { start: now, count: 0 };
  entry.count++;
  authRates.set(id, entry);
  return entry.count <= max;
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

async function requireAccount(req) {
  const account = await getAccountForToken(bearerToken(req));
  if (!account) throw Object.assign(new Error('Sign in again to continue.'), { status: 401 });
  return account;
}
function safeRoomCode(value) {
  return String(value || '').toLowerCase().replace(/[^a-z0-9_.-]/g, '').slice(0, 40);
}
function safeRoomTitle(value, fallback) {
  const title = String(value || '').replace(/[<>\u0000-\u001f]/g, '').trim().slice(0, 32);
  return title || fallback || 'Cave Game Server';
}
function worldMeta(world) {
  return {
    id: String(world.id), name: String(world.name || 'World').slice(0, 32),
    seed: String(world.seed == null ? '' : world.seed).slice(0, 40),
    mode: String(world.mode || 'survival'), roomCode: String(world.roomCode || '').slice(0, 40),
    created: Number(world.created) || Date.now(), last: Number(world.last) || Date.now(),
    thumb: typeof world.thumb === 'string' ? world.thumb.slice(0, 200000) : ''
  };
}
function validateWorldId(value) {
  const id = String(value || '');
  if (!/^[A-Za-z0-9_-]{3,80}$/.test(id)) throw Object.assign(new Error('Invalid world ID.'), { status: 400 });
  return id;
}
function validSkinDataUrl(value) {
  if (typeof value !== 'string') throw Object.assign(new Error('Choose a PNG skin first.'), { status: 400 });
  const m = /^data:image\/png;base64,([A-Za-z0-9+/]+={0,2})$/.exec(value);
  if (!m) throw Object.assign(new Error('Skin must be a PNG image.'), { status: 400 });
  const png = Buffer.from(m[1], 'base64');
  if (!png.length || png.length > SKIN_LIMIT) throw Object.assign(new Error('Skin PNG must be 250 KB or smaller.'), { status: 413 });
  const signature = Buffer.from([137,80,78,71,13,10,26,10]);
  if (png.length < 24 || !png.subarray(0, 8).equals(signature) || png.toString('ascii', 12, 16) !== 'IHDR') {
    throw Object.assign(new Error('That file is not a valid PNG.'), { status: 400 });
  }
  if (png.readUInt32BE(16) !== 64 || png.readUInt32BE(20) !== 64) {
    throw Object.assign(new Error('Skin PNG must be exactly 64 × 64 pixels.'), { status: 400 });
  }
  return png;
}
function roomPublicSummary(r) {
  return {
    room: r.name, title: r.title, players: r.clients.size, maxPlayers: MAX_PLAYERS,
    host: r.hostName || 'Player', createdAt: r.createdAt || Date.now()
  };
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
    if (req.method === 'GET' && path === '/api/servers') {
      if (!rateAllowed(req, 'server-list', 180)) return sendJson(res, 429, { ok: false, error: 'Please wait before refreshing the server browser again.' });
      const list = [...rooms.values()].filter(r => r.public && r.clients.size > 0 && r.clients.size < MAX_PLAYERS + 1)
        .map(roomPublicSummary).sort((a, b) => b.players - a.players || a.title.localeCompare(b.title));
      return sendJson(res, 200, { ok: true, servers: list, maxPlayers: MAX_PLAYERS });
    }

    if (req.method === 'GET' && path === '/api/worlds') {
      const account = await requireAccount(req);
      const result = await pool.query(
        `SELECT world_data, created_at, last_played_at FROM account_worlds
          WHERE account_id = $1 ORDER BY last_played_at DESC LIMIT 100`, [account.id]
      );
      const worlds = result.rows.map(row => {
        const data = row.world_data || {};
        return worldMeta({ ...data, created: data.created || new Date(row.created_at).getTime(), last: data.last || new Date(row.last_played_at).getTime() });
      });
      return sendJson(res, 200, { ok: true, worlds });
    }
    const worldMatch = /^\/api\/worlds\/([^/]+)$/.exec(path);
    if (worldMatch) {
      const account = await requireAccount(req);
      let worldId;
      try { worldId = validateWorldId(decodeURIComponent(worldMatch[1])); }
      catch (err) { throw err; }
      if (req.method === 'GET') {
        const result = await pool.query('SELECT world_data FROM account_worlds WHERE account_id = $1 AND world_id = $2 LIMIT 1', [account.id, worldId]);
        if (!result.rowCount) return sendJson(res, 404, { ok: false, error: 'World not found on this account.' });
        await pool.query('UPDATE account_worlds SET last_played_at = NOW() WHERE account_id = $1 AND world_id = $2', [account.id, worldId]);
        return sendJson(res, 200, { ok: true, world: result.rows[0].world_data });
      }
      if (req.method === 'PUT') {
        const body = await readJson(req, WORLD_BODY_LIMIT);
        const world = body && body.world;
        if (!world || typeof world !== 'object' || Array.isArray(world)) throw Object.assign(new Error('World data is missing.'), { status: 400 });
        if (String(world.id || '') !== worldId) throw Object.assign(new Error('World ID does not match the URL.'), { status: 400 });
        if (!['survival', 'creative', 'hardcore'].includes(String(world.mode || 'survival'))) throw Object.assign(new Error('Invalid world mode.'), { status: 400 });
        const json = JSON.stringify(world);
        if (Buffer.byteLength(json) > WORLD_BODY_LIMIT - 1024) throw Object.assign(new Error('World save is too large (8 MB maximum).'), { status: 413 });
        const now = new Date();
        await pool.query(
          `INSERT INTO account_worlds (account_id, world_id, world_data, created_at, last_played_at)
           VALUES ($1, $2, $3::jsonb, $4, $5)
           ON CONFLICT (account_id, world_id) DO UPDATE
             SET world_data = EXCLUDED.world_data, last_played_at = EXCLUDED.last_played_at`,
          [account.id, worldId, json, new Date(Number(world.created) || now.getTime()), now]
        );
        return sendJson(res, 200, { ok: true, world: worldMeta({ ...world, last: now.getTime() }) });
      }
      if (req.method === 'DELETE') {
        const result = await pool.query('DELETE FROM account_worlds WHERE account_id = $1 AND world_id = $2', [account.id, worldId]);
        return sendJson(res, 200, { ok: true, deleted: result.rowCount > 0 });
      }
      return sendJson(res, 405, { ok: false, error: 'Method not allowed.' });
    }

    if (req.method === 'PUT' && path === '/api/me/skin') {
      const account = await requireAccount(req);
      const body = await readJson(req, SKIN_LIMIT * 2);
      const png = validSkinDataUrl(body && body.dataUrl);
      await pool.query(
        `INSERT INTO account_skins (account_id, png_data, updated_at) VALUES ($1, $2, NOW())
         ON CONFLICT (account_id) DO UPDATE SET png_data = EXCLUDED.png_data, updated_at = NOW()`,
        [account.id, png]
      );
      return sendJson(res, 200, { ok: true, message: 'Skin synced to your Cave Game account.' });
    }
    if (req.method === 'DELETE' && path === '/api/me/skin') {
      const account = await requireAccount(req);
      await pool.query('DELETE FROM account_skins WHERE account_id = $1', [account.id]);
      return sendJson(res, 200, { ok: true, message: 'Cloud skin removed.' });
    }
    const skinMatch = /^\/api\/skins\/([1-9][0-9]{0,17})$/.exec(path);
    if (req.method === 'GET' && skinMatch) {
      const result = await pool.query('SELECT png_data, updated_at FROM account_skins WHERE account_id = $1 LIMIT 1', [skinMatch[1]]);
      if (!result.rowCount) return sendJson(res, 404, { ok: false, error: 'No cloud skin found.' });
      return sendJson(res, 200, { ok: true, dataUrl: 'data:image/png;base64,' + Buffer.from(result.rows[0].png_data).toString('base64'), updatedAt: result.rows[0].updated_at });
    }

    const profileMatch = /^\/api\/profiles\/([A-Za-z0-9_.-]{3,16})$/.exec(path);
    if (req.method === 'GET' && profileMatch) {
      const usernameNorm = profileMatch[1].toLowerCase();
      const result = await pool.query(
        `SELECT a.id, a.username, a.role, a.created_at,
                COALESCE(p.playtime_seconds, 0)::bigint AS playtime_seconds,
                (s.account_id IS NOT NULL) AS has_skin,
                (SELECT COUNT(*) FROM account_worlds w WHERE w.account_id = a.id)::int AS world_count
           FROM accounts a LEFT JOIN account_profiles p ON p.account_id = a.id
           LEFT JOIN account_skins s ON s.account_id = a.id
          WHERE a.username_norm = $1 LIMIT 1`, [usernameNorm]
      );
      if (!result.rowCount) return sendJson(res, 404, { ok: false, error: 'Player profile not found.' });
      const p = result.rows[0];
      return sendJson(res, 200, { ok: true, profile: {
        accountId: String(p.id), username: p.username, role: p.role, joinedAt: p.created_at,
        playtimeSeconds: Number(p.playtime_seconds) || 0, worldCount: p.world_count,
        hasSkin: !!p.has_skin
      }});
    }
    if (req.method === 'POST' && path === '/api/profile/playtime') {
      const account = await requireAccount(req);
      const body = await readJson(req);
      const seconds = Number(body && body.seconds);
      if (!Number.isInteger(seconds) || seconds < 1 || seconds > 120) throw Object.assign(new Error('Playtime update must be between 1 and 120 seconds.'), { status: 400 });
      const result = await pool.query(
        `INSERT INTO account_profiles (account_id, playtime_seconds, updated_at) VALUES ($1, $2, NOW())
         ON CONFLICT (account_id) DO UPDATE SET playtime_seconds = account_profiles.playtime_seconds + EXCLUDED.playtime_seconds, updated_at = NOW()
         RETURNING playtime_seconds`, [account.id, seconds]
      );
      return sendJson(res, 200, { ok: true, playtimeSeconds: Number(result.rows[0].playtime_seconds) || 0 });
    }

    if (path === '/api/room-world' && req.method === 'GET') {
      const code = safeRoomCode(new URL(req.url, 'http://localhost').searchParams.get('room'));
      if (!code) return sendJson(res, 400, { ok: false, error: 'Invalid room code.' });
      const result = await pool.query('SELECT edits FROM room_world_edits WHERE room_code = $1 LIMIT 1', [code]);
      return sendJson(res, 200, { ok: true, edits: result.rowCount ? result.rows[0].edits : [] });
    }
    if (path === '/api/room-world' && req.method === 'POST') {
      if (!rateAllowed(req, 'room-world-write', 180)) return sendJson(res, 429, { ok: false, error: 'Too many world edit uploads. Try again shortly.' });
      const body = await readJson(req, ROOM_EDITS_BODY_LIMIT);
      const code = safeRoomCode(body && body.room);
      if (!code || !Array.isArray(body.edits)) throw Object.assign(new Error('Invalid room edit batch.'), { status: 400 });
      const incoming = [];
      for (const q of body.edits.slice(0, 3000)) {
        if (!Array.isArray(q) || q.length < 4) continue;
        const x = Number(q[0]), y = Number(q[1]), z = Number(q[2]), v = Number(q[3]);
        if (![x, y, z, v].every(Number.isFinite) || !Number.isInteger(x) || !Number.isInteger(y) || !Number.isInteger(z) || !Number.isInteger(v)) continue;
        if (Math.abs(x) > 30000000 || y < 0 || y > 255 || Math.abs(z) > 30000000 || v < 0 || v > 65535) continue;
        incoming.push([x, y, z, v]);
      }
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [code]);
        const prior = await client.query('SELECT edits FROM room_world_edits WHERE room_code = $1 FOR UPDATE', [code]);
        const map = new Map();
        for (const q of (prior.rows[0] && prior.rows[0].edits || [])) if (Array.isArray(q) && q.length >= 4) map.set(q[0] + ',' + q[1] + ',' + q[2], q);
        for (const q of incoming) map.set(q[0] + ',' + q[1] + ',' + q[2], q);
        const edits = Array.from(map.values()).slice(-MAX_ROOM_EDITS);
        await client.query(
          `INSERT INTO room_world_edits (room_code, edits, updated_at) VALUES ($1, $2::jsonb, NOW())
           ON CONFLICT (room_code) DO UPDATE SET edits = EXCLUDED.edits, updated_at = NOW()`, [code, JSON.stringify(edits)]
        );
        await client.query('COMMIT');
      } catch (err) {
        try { await client.query('ROLLBACK'); } catch {}
        throw err;
      } finally { client.release(); }
      return sendJson(res, 200, { ok: true, saved: incoming.length });
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

      if (path === '/api/owner/reports') {
        const result = await pool.query(
          `SELECT id, reporter_name, target_name, room_code, reason, status, created_at
             FROM chat_reports ORDER BY created_at DESC LIMIT 100`
        );
        return sendJson(res, 200, { ok: true, reports: result.rows });
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

const wss = new WebSocketServer({ server, maxPayload: 32 * 1024, perMessageDeflate: { threshold: 512 } });
function room(name, meta) {
  let r = rooms.get(name);
  if (!r) {
    r = {
      name, clients: new Map(), edits: new Map(), signs: new Map(), clock: null,
      public: !!(meta && meta.public), title: safeRoomTitle(meta && meta.title, name),
      createdAt: Date.now(), hostId: null, hostName: ''
    };
    rooms.set(name, r);
  }
  return r;
}
const send = (ws, o) => { if (ws.readyState === 1) ws.send(JSON.stringify(o)); };
const num = (v, lo, hi) => (Number.isFinite(+v) ? Math.min(hi, Math.max(lo, +v)) : 0);
function hostRoom(r) {
  if (!r) return;
  const first = r.clients.values().next().value;
  r.hostId = first ? first.id : null;
  r.hostName = first ? first.name : '';
  for (const c of r.clients.values()) send(c, { t: 'host', you: c.id === r.hostId, hostId: r.hostId });
}
function uniqueGuestName(r, raw) {
  let base = String(raw || 'Guest').replace(/[^A-Za-z0-9_.-]/g, '').slice(0, 10) || 'Guest';
  let candidate = 'Guest-' + base, n = 2;
  const used = () => [...r.clients.values()].some(c => c.name.toLowerCase() === candidate.toLowerCase());
  while (used() && n < 100) { candidate = 'Guest-' + base.slice(0, 7) + n; n++; }
  return candidate.slice(0, 16);
}
function joinRoomSocket(ws, message, account) {
  const name = safeRoomCode(message.room) || 'main';
  let r = rooms.get(name);
  const first = !r || r.clients.size === 0;
  if (!r) r = room(name, { public: !!message.public, title: message.title });
  if (r.clients.size >= MAX_PLAYERS) { ws.close(1013, 'room full'); return false; }
  if (account) ws.name = account.username;
  else ws.name = uniqueGuestName(r, message.name);
  ws.account = account || null;
  ws.role = account ? account.role : 'guest';
  ws.room = r; ws.roomName = name; ws.id = 'p' + (nextId++); ws.joinedAt = Date.now();
  if (first) {
    r.public = !!message.public;
    r.title = safeRoomTitle(message.title, name);
    r.createdAt = Date.now();
    r.hostId = ws.id; r.hostName = ws.name;
  }
  r.clients.set(ws.id, ws);
  clearTimeout(ws.authTimer);
  send(ws, { t: 'w', id: ws.id, n: r.clients.size, name: ws.name, role: ws.role,
    host: r.hostId === ws.id, guest: !account, public: r.public, title: r.title,
    account: account ? { username: account.username, role: account.role } : null });
  if (r.clock) send(ws, { ...r.clock, t: 'room', hostId: r.hostId });
  if (r.signs.size) send(ws, { t: 'signs', l: [...r.signs.values()] });
  const peers = [];
  for (const c of r.clients.values()) {
    if (c !== ws && c.state) peers.push([c.id, c.state]);
  }
  for (let i = 0; i < peers.length; i += 100) send(ws, { t: 'p', l: peers.slice(i, i + 100) });
  const allEdits = [...r.edits.values()];
  for (let i = 0; i < allEdits.length; i += 400) send(ws, { t: 'e', l: allEdits.slice(i, i + 400) });
  if (r.clients.size === 1) hostRoom(r);
  return true;
}
function roomChat(r, packet, except) {
  for (const c of r.clients.values()) if (c !== except) send(c, packet);
}
function canAnnounce(ws) { return !!(ws.account && ['owner', 'admin', 'moderator'].includes(ws.account.role)); }
function validChatText(value, max = 200) {
  return String(value == null ? '' : value).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '').trim().slice(0, max);
}

wss.on('connection', (ws, req) => {
  ws.alive = true; ws.rate = 0; ws.room = null; ws.id = null; ws.state = null;
  ws.dirty = false; ws.needAll = false; ws.joining = false; ws.account = null; ws.role = 'guest';
  ws.chatAt = 0;
  ws.on('pong', () => { ws.alive = true; });
  ws.authTimer = setTimeout(() => { if (!ws.room && !ws.joining) ws.close(4001, 'authentication required'); }, 12000);
  ws.on('message', async (buf) => {
    if (++ws.rate > 100) return;
    let m; try { m = JSON.parse(buf); } catch { return; }
    if (!m || typeof m.t !== 'string') return;

    if (m.t === 'h') { // Account-authenticated join
      if (ws.room || ws.joining) return;
      ws.joining = true;
      try {
        const account = await getAccountForToken(m.token);
        if (ws.readyState !== 1) return;
        if (!account) {
          send(ws, { t: 'a', ok: false, message: 'Please sign in again before joining multiplayer.' });
          ws.close(4001, 'authentication required'); return;
        }
        joinRoomSocket(ws, m, account);
      } catch (err) {
        console.error('WebSocket authentication failed:', err.message);
        send(ws, { t: 'a', ok: false, message: 'Could not verify your account. Please try again.' });
        ws.close(1011, 'authentication check failed');
      } finally { ws.joining = false; }
      return;
    }
    if (m.t === 'g') { // Limited guest join: no account privileges or account storage
      if (ws.room || ws.joining) return;
      ws.joining = true;
      try {
        const raw = String(m.name || '').replace(/[^A-Za-z0-9_.-]/g, '').slice(0, 10);
        if (raw.length < 3) {
          send(ws, { t: 'a', ok: false, message: 'Guest names must be at least 3 characters.' });
          ws.close(4001, 'invalid guest name'); return;
        }
        const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
        if (!rateAllowed(req, 'guest-join', 200)) {
          send(ws, { t: 'a', ok: false, message: 'Too many guest connections from this network. Try again later.' });
          ws.close(1013, 'guest rate limit'); return;
        }
        if (ws.readyState === 1) joinRoomSocket(ws, m, null);
      } catch (err) {
        send(ws, { t: 'a', ok: false, message: 'Could not join as a guest.' });
        ws.close(1011, 'guest join failed');
      } finally { ws.joining = false; }
      return;
    }
    if (!ws.room) return;
    const r = ws.room;

    if (m.t === 's' && m.s) { // Player state; account ID is attached by the server, never trusted from client.
      const q = m.s;
      ws.state = {
        n: ws.name, x: num(q.x, -3e7, 3e7), y: num(q.y, -64, 512), z: num(q.z, -3e7, 3e7),
        yw: num(q.yw, -10, 10), pt: num(q.pt, -2, 2),
        sk: String(q.sk || 'steve').replace(/[^a-z]/g, '').slice(0, 12) || 'steve',
        hd: num(q.hd, 0, 65535) | 0, ar: String(q.ar || '').slice(0, 80),
        oh: num(q.oh, 0, 65535) | 0, bk: q.bk ? 1 : 0,
        dg: Array.isArray(q.dg) ? q.dg.slice(0, 5) : null,
        hp: num(q.hp, 0, 20), food: num(q.food, 0, 20), xpl: num(q.xpl, 0, 9999),
        uid: ws.account ? String(ws.account.id) : ''
      };
      ws.dirty = true;
    } else if (m.t === 'e' && Array.isArray(m.l)) { // Block edits
      const out = [];
      for (const q of m.l.slice(0, 200)) {
        if (!Array.isArray(q) || q.length < 4) continue;
        const x = q[0] | 0, y = q[1] | 0, z = q[2] | 0, v = q[3] | 0;
        if (y < 0 || y > 255 || v < 0 || v > 65535 || Math.abs(x) > 3e7 || Math.abs(z) > 3e7) continue;
        out.push([x, y, z, v]); r.edits.set(x + ',' + y + ',' + z, [x, y, z, v]);
      }
      if (r.edits.size > MAX_EDITS) r.edits.delete(r.edits.keys().next().value);
      if (out.length) for (const c of r.clients.values()) if (c !== ws) send(c, { t: 'e', l: out });
    } else if (m.t === 'c' && typeof m.m === 'string') { // Room chat
      const now = Date.now(); if (now - ws.chatAt < 350) return; ws.chatAt = now;
      const message = validChatText(m.m, 200); if (!message || message.startsWith('~#hit#~|')) return;
      roomChat(r, { t: 'c', n: ws.name, m: message }, ws);
    } else if (m.t === 'pm') { // Private message: only within the current room
      const pmNow = Date.now(); if (pmNow - ws.chatAt < 350) return; ws.chatAt = pmNow;
      const targetName = validChatText(m.to, 16).toLowerCase();
      const message = validChatText(m.m, 200);
      if (!targetName || !message) return;
      const target = [...r.clients.values()].find(c => c !== ws && c.name.toLowerCase() === targetName);
      if (!target) { send(ws, { t: 'notice', message: 'That player is not in this room.' }); return; }
      send(ws, { t: 'pm', from: ws.name, to: target.name, message, outgoing: true });
      send(target, { t: 'pm', from: ws.name, to: target.name, message, outgoing: false });
    } else if (m.t === 'announce') { // Moderators can announce to their current room
      const announceNow = Date.now(); if (announceNow - ws.chatAt < 350) return; ws.chatAt = announceNow;
      if (!canAnnounce(ws)) { send(ws, { t: 'notice', message: 'Moderator permission is required to announce.' }); return; }
      const message = validChatText(m.m, 200); if (!message) return;
      roomChat(r, { t: 'announce', n: ws.name, m: message });
    } else if (m.t === 'report') { // Reports are stored for server-owner review
      const reportNow = Date.now();
      if (reportNow - (ws.reportAt || 0) < 5000) { send(ws, { t: 'notice', message: 'Please wait a few seconds before sending another report.' }); return; }
      ws.reportAt = reportNow;
      const targetName = validChatText(m.to, 16);
      const reason = validChatText(m.reason, 240);
      if (!targetName || reason.length < 4) { send(ws, { t: 'notice', message: 'Usage: /report player reason (reason must be at least 4 characters).' }); return; }
      const target = [...r.clients.values()].find(c => c.name.toLowerCase() === targetName.toLowerCase());
      if (!target || target === ws) { send(ws, { t: 'notice', message: 'That player must be in your room to be reported.' }); return; }
      try {
        await pool.query(
          `INSERT INTO chat_reports (reporter_account_id, reporter_name, target_account_id, target_name, room_code, reason)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [ws.account ? ws.account.id : null, ws.name, target.account ? target.account.id : null, target.name, ws.roomName, reason]
        );
        send(ws, { t: 'notice', message: 'Report submitted to the Cave Game server owner.' });
      } catch (err) {
        console.error('Could not save chat report:', err.message);
        send(ws, { t: 'notice', message: 'The report could not be saved. Please try again later.' });
      }
    } else if (m.t === 'clock') { // First room player is authoritative for shared time/weather
      if (ws.id !== r.hostId) return;
      r.clock = {
        t: 'room', tod: num(m.tod, 0, 1), dayNum: num(m.dayNum, 0, 100000000) | 0,
        dayLength: num(m.dayLength, 60, 86400), weather: ['clear', 'cloudy', 'rain', 'thunder'].includes(m.weather) ? m.weather : 'clear',
        weatherLeft: num(m.weatherLeft, 0, 86400), rules: m.rules && typeof m.rules === 'object' ? m.rules : {},
        difficulty: m.difficulty === 'peaceful' ? 'peaceful' : 'normal', hostId: r.hostId
      };
      roomChat(r, r.clock, ws);
    } else if (m.t === 'mobs' && Array.isArray(m.l)) { // Host-authoritative mob snapshots
      if (ws.id !== r.hostId) return;
      const list = m.l.slice(0, 64).filter(v => v && typeof v.id === 'string' && v.id.length < 40 && Number.isFinite(+v.x) && Number.isFinite(+v.y) && Number.isFinite(+v.z)).map(v => ({
        id: v.id, type: v.type === 'animal' ? 'animal' : 'mob', kind: String(v.kind || 'zombie').slice(0, 24),
        x: num(v.x, -3e7, 3e7), y: num(v.y, -64, 512), z: num(v.z, -3e7, 3e7),
        yaw: num(v.yaw, -20, 20), hp: num(v.hp, 0, 100), dim: num(v.dim, 0, 2) | 0
      }));
      roomChat(r, { t: 'mobs', l: list }, ws);
    } else if (m.t === 'mh') { // Forward mob hit request to host only
      const host = [...r.clients.values()].find(c => c.id === r.hostId);
      if (host && host !== ws) send(host, { t: 'mh', id: String(m.id || '').slice(0, 40), damage: num(m.damage, 0, 25), x: num(m.x, -3e7, 3e7), z: num(m.z, -3e7, 3e7) });
    } else if (m.t === 'sign' && m.sign && typeof m.sign === 'object') {
      const v = m.sign;
      if (![v.x, v.y, v.z].every(Number.isFinite) || v.y < 0 || v.y > 255) return;
      const sign = { dim: num(v.dim, 0, 2) | 0, x: v.x | 0, y: v.y | 0, z: v.z | 0,
        lines: Array.isArray(v.lines) ? v.lines.slice(0, 4).map(t => validChatText(t, 15)) : ['', '', '', ''],
        wall: !!v.wall, hanging: !!v.hanging, rotation: num(v.rotation, 0, 15) | 0 };
      while (sign.lines.length < 4) sign.lines.push('');
      r.signs.set(sign.dim + ':' + sign.x + ',' + sign.y + ',' + sign.z, sign);
      roomChat(r, { t: 'sign', sign }, ws);
    }
  });
  ws.on('close', () => {
    clearTimeout(ws.authTimer);
    if (!ws.room) return;
    const r = ws.room, wasHost = r.hostId === ws.id;
    r.clients.delete(ws.id);
    for (const c of r.clients.values()) send(c, { t: 'l', id: ws.id });
    if (r.clients.size === 0) rooms.delete(ws.roomName);
    else if (wasHost) hostRoom(r);
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
