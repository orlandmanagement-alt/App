/**
 * worker.js (Single-file) — PART 1/2
 * Cloudflare Worker + D1 + KV
 *
 * Required bindings:
 *  - env.DB (D1)
 *  - env.KV (KV Namespace)
 *
 * Required secrets/vars:
 *  - HASH_PEPPER (secret)
 *  - SESSION_HMAC_KEY (secret)   // for session token signing
 *  - ALLOWED_ORIGINS (var)       // comma separated https origins
 *
 * Optional (for WhatsApp Twilio in PART 2):
 *  - TWILIO_ACCOUNT_SID (secret)
 *  - TWILIO_AUTH_TOKEN (secret)
 *  - TWILIO_WHATSAPP_FROM (secret) e.g. "whatsapp:+14155238886"
 *
 * Status codes (payload.status):
 * ok, invalid_input, unauthorized, forbidden, user_belum_terdaftar, password_invalid,
 * otp_invalid, otp_expired, otp_blocked, locked, rate_limited,
 * challenge_required, challenge_invalid, conflict, server_error
 */

export default {
  async fetch(req, env, ctx) {
    try {
      const url = new URL(req.url);

      // Preflight
      if (req.method === "OPTIONS") return corsPreflight(req);

      // Health is always allowed
      if (req.method === "GET" && url.pathname === "/health") {
        return json(req, env, 200, "ok", { ok: true, env: env.ENV_NAME || "unknown" });
      }

      // Origin allowlist for sensitive endpoints (skip if BREAKGLASS=true)
      if (String(env.BREAKGLASS || "false") !== "true") {
        const allow = parseOrigins(env);
        const p = url.pathname;
        const sensitive =
          p.startsWith("/admin/") ||
          p.startsWith("/auth/challenge/") ||
          p.startsWith("/incidents/") ||
          p.startsWith("/webhooks/");
        if (sensitive && !originOk(req, allow)) {
          return json(req, env, 403, "forbidden", null);
        }
      }

      // ROUTER
      // Auth
      if (req.method === "POST" && url.pathname === "/auth/login/password") return withCors(req, env, authLoginPassword(req, env));
      if (req.method === "POST" && url.pathname === "/auth/logout") return withCors(req, env, authLogout(req, env));
      if (req.method === "GET" && url.pathname === "/me") return withCors(req, env, me(req, env));

      // OTP / Step-up
      if (req.method === "POST" && url.pathname === "/auth/challenge/otp/request") return withCors(req, env, otpRequest(req, env));
      if (req.method === "POST" && url.pathname === "/auth/challenge/otp/verify") return withCors(req, env, otpVerify(req, env));

      // If nothing matched
      return json(req, env, 404, "invalid_input", { message: "Not found" });
    } catch (e) {
      return json(req, env, 500, "server_error", { message: String(e?.message || e) });
    }
  },

  // PART 2 will add scheduled() for tasks processor + cleanup cron
};

/* =========================
 * Response + CORS + Security
 * ========================= */

function cors(req) {
  const origin = req.headers.get("origin") || "*";
  // We still set ACAO=origin to satisfy browser; you can tighten if needed
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "authorization, content-type, x-challenge-token, x-request-id",
    "access-control-allow-methods": "GET,POST,PUT,DELETE,OPTIONS",
  };
}

function corsPreflight(req) {
  return new Response(null, { status: 204, headers: { ...cors(req), ...secHeaders() } });
}

function secHeaders() {
  return {
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "content-security-policy": "default-src 'none'",
  };
}

function json(req, env, httpCode, status, data) {
  return new Response(JSON.stringify({ status, data }, null, 0), {
    status: httpCode,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...secHeaders(),
      ...cors(req),
    },
  });
}

async function withCors(req, env, p) {
  const r = await p;
  // ensure response has cors+sec headers (if handler returned plain Response)
  if (r instanceof Response) return r;
  return json(req, env, 500, "server_error", { message: "handler_invalid_response" });
}

/* =========================
 * Helpers: time, parsing
 * ========================= */

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

async function readJson(req) {
  const ct = req.headers.get("content-type") || "";
  if (!ct.includes("application/json")) return null;
  return await req.json();
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function timingSafeEqual(a, b) {
  a = String(a || "");
  b = String(b || "");
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

/* =========================
 * Helpers: Origins
 * ========================= */

function parseOrigins(env) {
  return String(env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}
function originOk(req, allow) {
  const origin = req.headers.get("origin");
  if (!origin) return true; // curl / non-browser
  return allow.includes(origin);
}

/* =========================
 * Helpers: D1
 * ========================= */

async function one(r) {
  return (r && r.results && r.results[0]) ? r.results[0] : null;
}

async function d1Get(env, sql, binds = []) {
  const r = await env.DB.prepare(sql).bind(...binds).all();
  return await one(r);
}

async function d1All(env, sql, binds = []) {
  const r = await env.DB.prepare(sql).bind(...binds).all();
  return r.results || [];
}

/* =========================
 * Crypto: hashing, HMAC, PBKDF2
 * ========================= */

async function sha256Base64(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

async function hmacSignBase64(secret, msg) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

function b64urlEncode(s) {
  return s.replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
function b64urlDecode(s) {
  s = s.replaceAll("-", "+").replaceAll("_", "/");
  while (s.length % 4) s += "=";
  return s;
}

async function pbkdf2Hash(password, saltB64, iterations = 210_000) {
  const salt = Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0));
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    baseKey,
    256
  );
  const u8 = new Uint8Array(bits);
  return btoa(String.fromCharCode(...u8));
}

function randomB64(bytes = 16) {
  const u8 = crypto.getRandomValues(new Uint8Array(bytes));
  return btoa(String.fromCharCode(...u8));
}

/* =========================
 * Settings (system_settings)
 * ========================= */

async function getSettingStr(env, k, defVal) {
  const row = await d1Get(env, "SELECT v FROM system_settings WHERE k=? LIMIT 1", [k]);
  return row?.v != null ? String(row.v) : defVal;
}

/* =========================
 * Audit (no raw PII)
 * ========================= */

async function audit(env, { actor_user_id, action, target_type, target_id, meta }) {
  try {
    const id = crypto.randomUUID();
    const created_at = nowSec();
    const meta_json = meta ? JSON.stringify(meta) : null;
    await env.DB.prepare(
      "INSERT INTO audit_logs (id, actor_user_id, action, target_type, target_id, meta_json, created_at) VALUES (?,?,?,?,?,?,?)"
    )
      .bind(id, actor_user_id || null, action, target_type || null, target_id || null, meta_json, created_at)
      .run();
  } catch {
    // never block main flow on audit failure
  }
}

/* =========================
 * Rate limit + lockout
 * ========================= */

function getClientIp(req) {
  return (
    req.headers.get("cf-connecting-ip") ||
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    "0.0.0.0"
  );
}

async function ipHash(ip, pepper) {
  return await sha256Base64(`${ip}|${pepper}`);
}

async function rateLimitKeyInc(env, key, ttlSec) {
  const cur = Number((await env.KV.get(key)) || "0");
  const next = cur + 1;
  await env.KV.put(key, String(next), { expirationTtl: ttlSec });
  return next;
}

async function isLocked(env, idHash) {
  const v = await env.KV.get(`lock:${idHash}`);
  return !!v;
}
async function lockUser(env, idHash, ttlSec = 3600) {
  await env.KV.put(`lock:${idHash}`, "1", { expirationTtl: ttlSec });
}

/* =========================
 * RBAC helpers
 * ========================= */

function hasRole(roles, allowed) {
  const s = new Set((roles || []).map(String));
  return allowed.some((r) => s.has(r));
}

async function getRolesForUser(env, user_id) {
  // roles table assumed: roles(id,name). user_roles(user_id,role_id)
  const rows = await d1All(
    env,
    `SELECT r.name AS name
     FROM user_roles ur
     JOIN roles r ON r.id=ur.role_id
     WHERE ur.user_id=?`,
    [user_id]
  );
  return rows.map((x) => x.name);
}

/* =========================
 * Sessions: signed token + stored token_hash
 * ========================= */

function ipPrefix(ip) {
  if (!ip) return "unknown";
  if (ip.includes(".")) {
    const p = ip.split(".");
    if (p.length === 4) return `${p[0]}.${p[1]}.${p[2]}.0/24`;
  }
  if (ip.includes(":")) {
    const parts = ip.split(":").filter(Boolean);
    return parts.slice(0, 4).join(":") + "::/64";
  }
  return "unknown";
}

async function uaHash(env, req) {
  const ua = req.headers.get("user-agent") || "";
  return await sha256Base64(`${ua}|${env.HASH_PEPPER}`);
}
async function ipPrefixHash(env, req) {
  const pref = ipPrefix(getClientIp(req));
  return await sha256Base64(`${pref}|${env.HASH_PEPPER}`);
}

async function createSession(env, req, user_id, roles) {
  const now = nowSec();

  // expiry by role (admin shorter)
  let ttl = 8 * 3600; // default staff/admin 8h
  if (hasRole(roles, ["super_admin", "admin"])) ttl = 2 * 3600;
  if (hasRole(roles, ["client", "talent"])) ttl = 7 * 86400;

  const exp = now + ttl;
  const session_id = crypto.randomUUID();

  const payload = { v: 1, sid: session_id, uid: user_id, exp, roles };
  const payloadB64 = b64urlEncode(btoa(JSON.stringify(payload)));
  const sigB64 = b64urlEncode(await hmacSignBase64(env.SESSION_HMAC_KEY, payloadB64));
  const token = `${payloadB64}.${sigB64}`;

  const token_hash = await sha256Base64(`${token}|${env.HASH_PEPPER}`);
  const ua_h = await uaHash(env, req);
  const ip_h = await ipPrefixHash(env, req);

  // sessions table must have: id,user_id,token_hash,roles_json,expires_at,created_at,revoked_at,ua_hash,ip_prefix_hash,last_seen_at
  await env.DB.prepare(
    `INSERT INTO sessions (id,user_id,token_hash,roles_json,expires_at,created_at,revoked_at,ua_hash,ip_prefix_hash,last_seen_at)
     VALUES (?,?,?,?,?,?,?,?,?,?)`
  )
    .bind(session_id, user_id, token_hash, JSON.stringify(roles), exp, now, null, ua_h, ip_h, now)
    .run();

  return { token, session_id, exp };
}

async function revokeSessionByToken(env, token) {
  const token_hash = await sha256Base64(`${token}|${env.HASH_PEPPER}`);
  await env.DB.prepare("UPDATE sessions SET revoked_at=? WHERE token_hash=?").bind(nowSec(), token_hash).run();
}

async function requireAuth(env, req) {
  const auth = req.headers.get("authorization") || "";
  if (!auth.startsWith("Bearer ")) {
    return { ok: false, res: json(req, env, 401, "unauthorized", null) };
  }
  const token = auth.slice("Bearer ".length).trim();
  const parts = token.split(".");
  if (parts.length !== 2) return { ok: false, res: json(req, env, 401, "unauthorized", null) };

  const [payloadB64, sigB64] = parts;
  const expected = b64urlEncode(await hmacSignBase64(env.SESSION_HMAC_KEY, payloadB64));
  if (!timingSafeEqual(expected, sigB64)) {
    return { ok: false, res: json(req, env, 401, "unauthorized", null) };
  }

  let payload;
  try {
    payload = JSON.parse(atob(b64urlDecode(payloadB64)));
  } catch {
    return { ok: false, res: json(req, env, 401, "unauthorized", null) };
  }

  const now = nowSec();
  if (!payload?.exp || now > Number(payload.exp)) {
    return { ok: false, res: json(req, env, 401, "unauthorized", null) };
  }

  const token_hash = await sha256Base64(`${token}|${env.HASH_PEPPER}`);
  const row = await d1Get(env, `SELECT * FROM sessions WHERE token_hash=? LIMIT 1`, [token_hash]);
  if (!row) return { ok: false, res: json(req, env, 401, "unauthorized", null) };
  if (row.revoked_at) return { ok: false, res: json(req, env, 401, "unauthorized", null) };
  if (now > Number(row.expires_at || 0)) return { ok: false, res: json(req, env, 401, "unauthorized", null) };

  const roles = payload.roles || [];
  const isAdmin = hasRole(roles, ["admin", "super_admin"]);

  // Session binding check (admin requires anomaly step-up)
  const curUa = await uaHash(env, req);
  const curIp = await ipPrefixHash(env, req);
  if ((row.ua_hash && row.ua_hash !== curUa) || (row.ip_prefix_hash && row.ip_prefix_hash !== curIp)) {
    if (isAdmin) {
      await audit(env, { actor_user_id: payload.uid, action: "auth.session.anomaly", target_type: "session", target_id: row.id, meta: {} });
      return { ok: false, res: json(req, env, 403, "challenge_required", { action: "session_anomaly" }) };
    }
  }

  // Touch last_seen_at (best effort)
  try {
    await env.DB.prepare(`UPDATE sessions SET last_seen_at=? WHERE id=?`).bind(nowSec(), row.id).run();
  } catch {}

  return { ok: true, uid: payload.uid, roles, token };
}

/* =========================
 * Step-up challenge tokens (X-Challenge-Token)
 * Stored in KV only, short TTL
 * ========================= */

async function issueChallenge(env, user_id, action, ttlSec = 600) {
  const token = b64urlEncode(randomB64(18));
  const key = `ch:${user_id}:${action}:${token}`;
  await env.KV.put(key, "1", { expirationTtl: ttlSec });
  return token;
}

async function verifyChallengeToken(env, user_id, action, token) {
  if (!token) return false;
  const key = `ch:${user_id}:${action}:${token}`;
  const v = await env.KV.get(key);
  return !!v;
}

async function requireChallenge(env, req, user_id, action) {
  const t = req.headers.get("x-challenge-token") || "";
  const ok = await verifyChallengeToken(env, user_id, action, t);
  if (!ok) return { ok: false, res: json(req, env, 403, "challenge_required", { action }) };
  return { ok: true };
}

/* =========================
 * OTP (6 digits) hash only + attempts max 5
 * OTP plaintext stored in KV temporarily ONLY for async delivery
 * ========================= */

function genOtp6() {
  const n = crypto.getRandomValues(new Uint32Array(1))[0] % 1000000;
  return String(n).padStart(6, "0");
}

async function otpHash(env, otp, saltB64) {
  return await sha256Base64(`${otp}|${saltB64}|${env.HASH_PEPPER}`);
}

async function otpRequest(req, env) {
  // blocks
  const ipH = await ipHash(getClientIp(req), env.HASH_PEPPER);
  const rl = await rateLimitKeyInc(env, `rl:otp_req:${ipH}`, 60);
  if (rl > 30) return json(req, env, 429, "rate_limited", null);

  const body = await readJson(req);
  const action = String(body?.action || "").trim();
  const email = normalizeEmail(body?.email || "");

  if (!action) return json(req, env, 400, "invalid_input", null);

  // Determine user: for admin_login uses email; for session_anomaly requires session
  let user = null;
  if (action === "admin_login") {
    if (!email.includes("@")) return json(req, env, 400, "invalid_input", null);
    user = await d1Get(env, `SELECT id,email_norm,status FROM users WHERE email_norm=? LIMIT 1`, [email]);
    if (!user) return json(req, env, 403, "user_belum_terdaftar", null);
  } else {
    // requires auth
    const a = await requireAuth(env, req);
    if (!a.ok) return a.res;
    user = { id: a.uid };
  }

  const otp = genOtp6();
  const salt = randomB64(16);
  const h = await otpHash(env, otp, salt);
  const ref = crypto.randomUUID();

  // KV keys (10 min TTL)
  // otp:ref -> {hash,salt,exp,attempts}
  const exp = nowSec() + 600;

  await env.KV.put(`otp:${ref}`, JSON.stringify({ h, salt, exp, attempts: 0, action, uid: user.id }), { expirationTtl: 600 });

  // Plaintext delivery window (2–3 minutes). Delete after send.
  await env.KV.put(`otp_plain:${ref}`, otp, { expirationTtl: 180 });

  // Enqueue send_otp task will be in PART 2; for now we just say enqueued=false
  await audit(env, { actor_user_id: user.id, action: "otp.requested", target_type: "otp_ref", target_id: ref, meta: { action } });

  return json(req, env, 200, "ok", { otp_ref: ref, action, enqueued: false });
}

async function otpVerify(req, env) {
  const ipH = await ipHash(getClientIp(req), env.HASH_PEPPER);
  const rl = await rateLimitKeyInc(env, `rl:otp_ver:${ipH}`, 60);
  if (rl > 60) return json(req, env, 429, "rate_limited", null);

  const body = await readJson(req);
  const action = String(body?.action || "").trim();
  const otp = String(body?.otp || "").trim();
  const email = normalizeEmail(body?.email || "");
  const otp_ref = String(body?.otp_ref || "").trim(); // optional if you pass ref

  if (!action || !otp) return json(req, env, 400, "invalid_input", null);

  // locate otp record
  // If otp_ref provided, use it; else derive latest by email/action? (not implemented)
  if (!otp_ref) return json(req, env, 400, "invalid_input", { message: "otp_ref_required" });

  const recStr = await env.KV.get(`otp:${otp_ref}`);
  if (!recStr) return json(req, env, 400, "otp_expired", null);

  const rec = JSON.parse(recStr);
  const now = nowSec();
  if (now > Number(rec.exp || 0)) return json(req, env, 400, "otp_expired", null);

  if (Number(rec.attempts || 0) >= 5) return json(req, env, 400, "otp_blocked", null);

  const h = await otpHash(env, otp, rec.salt);
  if (h !== rec.h) {
    rec.attempts = Number(rec.attempts || 0) + 1;
    await env.KV.put(`otp:${otp_ref}`, JSON.stringify(rec), { expirationTtl: Math.max(1, rec.exp - now) });
    await audit(env, { actor_user_id: rec.uid || null, action: "otp.verify.fail", target_type: "otp_ref", target_id: otp_ref, meta: { action } });
    return json(req, env, 400, "otp_invalid", null);
  }

  // success: issue a challenge token OR session depending on action
  await env.KV.delete(`otp:${otp_ref}`);
  await env.KV.delete(`otp_plain:${otp_ref}`);
  await audit(env, { actor_user_id: rec.uid || null, action: "otp.verify.ok", target_type: "otp_ref", target_id: otp_ref, meta: { action } });

  if (action === "admin_login") {
    // For admin_login, issue session now
    if (!email.includes("@")) return json(req, env, 400, "invalid_input", null);
    const user = await d1Get(env, `SELECT id,status FROM users WHERE email_norm=? LIMIT 1`, [email]);
    if (!user) return json(req, env, 403, "user_belum_terdaftar", null);

    const roles = await getRolesForUser(env, user.id);
    const sess = await createSession(env, req, user.id, roles);
    return json(req, env, 200, "ok", { token: sess.token, exp: sess.exp });
  }

  // For other actions (rbac_write, incident_write, session_anomaly), issue challenge token
  // action string must match what endpoints require
  const uid = rec.uid;
  const token = await issueChallenge(env, uid, action, 600);
  return json(req, env, 200, "ok", { challenge_token: token, action });
}

/* =========================
 * Auth: Login / Logout / Me
 * ========================= */

async function authLoginPassword(req, env) {
  const body = await readJson(req);
  const email = normalizeEmail(body?.email || "");
  const password = String(body?.password || "");

  if (!email.includes("@") || password.length < 6) return json(req, env, 400, "invalid_input", null);
  if (!env.HASH_PEPPER || !env.SESSION_HMAC_KEY) return json(req, env, 500, "server_error", { message: "missing_secrets" });

  // rate limit by ip + identifier
  const ipH = await ipHash(getClientIp(req), env.HASH_PEPPER);
  const idH = await sha256Base64(`${email}|${env.HASH_PEPPER}`);
  const n = await rateLimitKeyInc(env, `rl:login:${ipH}:${idH}`, 60);
  if (n > 10) return json(req, env, 429, "rate_limited", null);

  // lockout
  if (await isLocked(env, idH)) return json(req, env, 403, "locked", null);

  // get user
  const user = await d1Get(env,
    `SELECT id,email_norm,password_salt,password_hash,password_iter,status
     FROM users WHERE email_norm=? LIMIT 1`,
    [email]
  );
  if (!user) return json(req, env, 403, "user_belum_terdaftar", null);
  if (String(user.status || "active") !== "active") return json(req, env, 403, "forbidden", null);

  // verify password PBKDF2
  const iter = Number(user.password_iter || 210000);
  const calc = await pbkdf2Hash(password, user.password_salt, iter);
  if (calc !== user.password_hash) {
    const fails = await rateLimitKeyInc(env, `fail:login:${idH}`, 3600);
    await audit(env, { actor_user_id: user.id, action: "auth.login.fail", target_type: "user", target_id: user.id, meta: {} });
    if (fails >= 5) await lockUser(env, idH, 3600);
    return json(req, env, 403, "password_invalid", null);
  }

  // success: admin must OTP (admin_login)
  const roles = await getRolesForUser(env, user.id);
  if (hasRole(roles, ["admin", "super_admin"])) {
    await audit(env, { actor_user_id: user.id, action: "auth.login.admin.stepup_required", target_type: "user", target_id: user.id, meta: {} });
    return json(req, env, 200, "challenge_required", { step: "otp_required", action: "admin_login" });
  }
  
  async function getUserTenantId(env, user_id){
  const r = await env.DB.prepare(`SELECT tenant_id FROM users WHERE id=? LIMIT 1`).bind(user_id).all();
  const row = (r.results && r.results[0]) ? r.results[0] : null;
  return row?.tenant_id || null;
}

function assertTenantAccessOrThrow(actorRoles, actorTenantId, targetTenantId){
  // super_admin bypass
  if (hasRole(actorRoles, ["super_admin"])) return true;
  // admin/staff must match tenant
  if (!actorTenantId || !targetTenantId) return false;
  return String(actorTenantId) === String(targetTenantId);
}

async function adminIncidentsList(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin","admin"])) return json(req, env, 403, "forbidden", null);

  const url = new URL(req.url);
  const q = String(url.searchParams.get("q")||"").trim();
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit")||"50")));

  let sql = `SELECT id,severity,type,summary,status,owner_user_id,created_at,updated_at FROM incidents`;
  const binds = [];
  if (q){
    sql += ` WHERE type LIKE ? OR summary LIKE ?`;
    binds.push(`%${q}%`, `%${q}%`);
  }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  const r = await env.DB.prepare(sql).bind(...binds).all();
  return json(req, env, 200, "ok", { incidents: r.results || [] });
}

async function adminIncidentsGet(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin","admin"])) return json(req, env, 403, "forbidden", null);

  const url = new URL(req.url);
  const id = String(url.searchParams.get("id")||"").trim();
  if(!id) return json(req, env, 400, "invalid_input", null);

  const r = await env.DB.prepare(
    `SELECT id,severity,type,summary,status,owner_user_id,details_json,created_at,updated_at
     FROM incidents WHERE id=? LIMIT 1`
  ).bind(id).all();

  const inc = (r.results && r.results[0]) ? r.results[0] : null;
  if(!inc) return json(req, env, 404, "invalid_input", { message:"not_found" });

  return json(req, env, 200, "ok", { incident: inc });
}

async function adminProjectsList(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin","admin","staff"])) return json(req, env, 403, "forbidden", null);

  const url = new URL(req.url);
  const tenantParam = String(url.searchParams.get("tenant_id")||"").trim();
  const actorTenantId = await getUserTenantId(env, a.uid);

  let tenant_id = tenantParam || actorTenantId;
  if (!hasRole(a.roles, ["super_admin"])) {
    // enforce tenant lock
    if (!tenant_id || tenant_id !== actorTenantId) return json(req, env, 403, "forbidden", null);
  }
  if (!tenant_id) return json(req, env, 400, "invalid_input", { message:"tenant_id_required" });

  const rows = await d1All(env, `
    SELECT id,tenant_id,name,status,created_at,updated_at
    FROM projects
    WHERE tenant_id=?
    ORDER BY created_at DESC
    LIMIT 200
  `, [tenant_id]);

  return json(req, env, 200, "ok", { projects: rows });
}

async function adminProjectsCreate(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin","admin","staff"])) return json(req, env, 403, "forbidden", null);
  const ch = await requireChallenge(env, req, a.uid, "rbac_write"); if(!ch.ok) return ch.res;

  const b = await readJson(req);
  const tenant_id = String(b?.tenant_id||"").trim();
  const name = String(b?.name||"").trim();
  if(!tenant_id || !name) return json(req, env, 400, "invalid_input", null);

  const actorTenantId = await getUserTenantId(env, a.uid);
  if (!hasRole(a.roles, ["super_admin"])) {
    if (!actorTenantId || actorTenantId !== tenant_id) return json(req, env, 403, "forbidden", null);
  }

  const id = crypto.randomUUID();
  const now = nowSec();
  await env.DB.prepare(
    `INSERT INTO projects (id,tenant_id,name,status,created_at,updated_at)
     VALUES (?,?,?,?,?,?)`
  ).bind(id, tenant_id, name, "active", now, now).run();

  await audit(env,{actor_user_id:a.uid, action:"project.create", target_type:"project", target_id:id, meta:{tenant_id}});
  return json(req, env, 200, "ok", { id });
}

async function adminProjectEventsList(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin","admin","staff"])) return json(req, env, 403, "forbidden", null);

  const url = new URL(req.url);
  const project_id = String(url.searchParams.get("project_id")||"").trim();
  const from = Number(url.searchParams.get("from")||"0");
  const to = Number(url.searchParams.get("to")||"0");
  if(!project_id) return json(req, env, 400, "invalid_input", null);

  const proj = await d1Get(env, `SELECT tenant_id FROM projects WHERE id=? LIMIT 1`, [project_id]);
  if(!proj) return json(req, env, 404, "invalid_input", { message:"project_not_found" });

  const actorTenantId = await getUserTenantId(env, a.uid);
  if (!hasRole(a.roles, ["super_admin"])) {
    if (!actorTenantId || actorTenantId !== proj.tenant_id) return json(req, env, 403, "forbidden", null);
  }

  let sql = `
    SELECT id,project_id,talent_user_id,title,notes,start_at,end_at,created_by_user_id,created_at
    FROM project_schedule_events
    WHERE project_id=?
  `;
  const binds = [project_id];
  if (from > 0) { sql += ` AND start_at >= ?`; binds.push(from); }
  if (to > 0) { sql += ` AND start_at <= ?`; binds.push(to); }
  sql += ` ORDER BY start_at ASC LIMIT 500`;

  const rows = await d1All(env, sql, binds);
  return json(req, env, 200, "ok", { events: rows });
}


async function adminProjectEventsCreate(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin","admin","staff"])) return json(req, env, 403, "forbidden", null);
  const ch = await requireChallenge(env, req, a.uid, "rbac_write"); if(!ch.ok) return ch.res;

  const b = await readJson(req);
  const project_id = String(b?.project_id||"").trim();
  const title = String(b?.title||"").trim();
  const talent_user_id = b?.talent_user_id ? String(b.talent_user_id).trim() : null;
  const start_at = Number(b?.start_at||0);
  const end_at = Number(b?.end_at||0);
  const notes = b?.notes ? String(b.notes).trim() : null;

  if(!project_id || !title || !start_at || !end_at || end_at <= start_at) {
    return json(req, env, 400, "invalid_input", null);
  }

  const proj = await d1Get(env, `SELECT tenant_id FROM projects WHERE id=? LIMIT 1`, [project_id]);
  if(!proj) return json(req, env, 404, "invalid_input", { message:"project_not_found" });

  const actorTenantId = await getUserTenantId(env, a.uid);
  if (!hasRole(a.roles, ["super_admin"])) {
    if (!actorTenantId || actorTenantId !== proj.tenant_id) return json(req, env, 403, "forbidden", null);
  }

  // Optional: ensure talent_user_id belongs to same tenant
  if (talent_user_id) {
    const tu = await d1Get(env, `SELECT tenant_id FROM users WHERE id=? LIMIT 1`, [talent_user_id]);
    if (tu && tu.tenant_id && tu.tenant_id !== proj.tenant_id && !hasRole(a.roles, ["super_admin"])) {
      return json(req, env, 403, "forbidden", null);
    }
  }

  const id = crypto.randomUUID();
  const now = nowSec();
  await env.DB.prepare(`
    INSERT INTO project_schedule_events (id,project_id,talent_user_id,title,notes,start_at,end_at,created_by_user_id,created_at)
    VALUES (?,?,?,?,?,?,?,?,?)
  `).bind(id, project_id, talent_user_id, title, notes, start_at, end_at, a.uid, now).run();

  await audit(env,{actor_user_id:a.uid, action:"project.event.create", target_type:"project_event", target_id:id, meta:{project_id}});
  return json(req, env, 200, "ok", { id });
}

async function talentSchedule(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["talent","super_admin"])) return json(req, env, 403, "forbidden", null);

  const url = new URL(req.url);
  const from = Number(url.searchParams.get("from")||"0");
  const to = Number(url.searchParams.get("to")||"0");

  let sql = `
    SELECT id,project_id,talent_user_id,title,notes,start_at,end_at,created_at
    FROM project_schedule_events
    WHERE talent_user_id=?
  `;
  const binds = [a.uid];
  if (from > 0) { sql += ` AND start_at >= ?`; binds.push(from); }
  if (to > 0) { sql += ` AND start_at <= ?`; binds.push(to); }
  sql += ` ORDER BY start_at ASC LIMIT 500`;

  const rows = await d1All(env, sql, binds);
  return json(req, env, 200, "ok", { events: rows });
}


  // non-admin: issue session
  const sess = await createSession(env, req, user.id, roles);
  await audit(env, { actor_user_id: user.id, action: "auth.login.ok", target_type: "session", target_id: sess.session_id, meta: {} });
  return json(req, env, 200, "ok", { token: sess.token, exp: sess.exp });
}

async function authLogout(req, env) {
  const a = await requireAuth(env, req);
  if (!a.ok) return a.res;
  await revokeSessionByToken(env, a.token);
  await audit(env, { actor_user_id: a.uid, action: "auth.logout", target_type: "session", target_id: "by_token", meta: {} });
  return json(req, env, 200, "ok", { logged_out: true });
}

async function me(req, env) {
  const a = await requireAuth(env, req);
  if (!a.ok) return a.res;

  // Basic user info (avoid PII)
  const u = await d1Get(env, `SELECT id,display_name,status FROM users WHERE id=? LIMIT 1`, [a.uid]);
  return json(req, env, 200, "ok", { id: u?.id, display_name: u?.display_name, roles: a.roles, status: u?.status });
}

/* =========================
 * worker.js — PART 2/2
 * Paste this BELOW PART 1/2 in the same file.
 * Adds Admin APIs, Tasks/DLQ, Backups, WhatsApp Twilio outbound+inbound.
 * ========================= */

/* ---------- ROUTER ADDITIONS ----------
 * Add these routes inside fetch router (after the auth routes).
 * If you already have a router section, insert these checks there.
 *
 * NOTE: In PART 1, fetch() currently only routes /health and auth endpoints.
 * You must ADD the following in fetch(req, env, ctx) router:
 *
 *  // Admin RBAC + Audit
 *  if (req.method==="GET"  && url.pathname==="/admin/roles") return withCors(req, env, adminRolesList(req, env));
 *  if (req.method==="GET"  && url.pathname==="/admin/menus") return withCors(req, env, adminMenusList(req, env));
 *  if (req.method==="POST" && url.pathname==="/admin/menus/upsert") return withCors(req, env, adminMenusUpsert(req, env));
 *  if (req.method==="POST" && url.pathname==="/admin/role-menus/set") return withCors(req, env, adminRoleMenusSet(req, env));
 *  if (req.method==="GET"  && url.pathname==="/admin/audit") return withCors(req, env, adminAuditList(req, env));
 *
 *  // Security dashboard
 *  if (req.method==="GET"  && url.pathname==="/admin/security/summary") return withCors(req, env, adminSecuritySummary(req, env));
 *  if (req.method==="GET"  && url.pathname==="/admin/security/incidents") return withCors(req, env, adminSecurityIncidents(req, env));
 *
 *  // IP blocks
 *  if (req.method==="GET"  && url.pathname==="/admin/ipblocks") return withCors(req, env, adminIpBlocksList(req, env));
 *  if (req.method==="POST" && url.pathname==="/admin/ipblocks/block") return withCors(req, env, adminIpBlocksBlock(req, env));
 *  if (req.method==="POST" && url.pathname==="/admin/ipblocks/unblock") return withCors(req, env, adminIpBlocksUnblock(req, env));
 *  if (req.method==="POST" && url.pathname==="/admin/ipblocks/unblock_by_hash") return withCors(req, env, adminIpBlocksUnblockByHash(req, env));
 *  if (req.method==="GET"  && url.pathname==="/admin/ipblocks/check") return withCors(req, env, adminIpBlocksCheck(req, env));
 *
 *  // Tasks + DLQ
 *  if (req.method==="POST" && url.pathname==="/admin/tasks/enqueue") return withCors(req, env, adminTasksEnqueue(req, env));
 *  if (req.method==="GET"  && url.pathname==="/admin/tasks") return withCors(req, env, adminTasksList(req, env));
 *  if (req.method==="GET"  && url.pathname==="/admin/dlq") return withCors(req, env, adminDlqList(req, env));
 *  if (req.method==="POST" && url.pathname==="/admin/dlq/retry") return withCors(req, env, adminDlqRetry(req, env));
 *
 *  // Maintenance
 *  if (req.method==="GET"  && url.pathname==="/admin/maintenance/smoke") return withCors(req, env, adminMaintenanceSmoke(req, env));
 *  if (req.method==="POST" && url.pathname==="/admin/maintenance/migrate_missing") return withCors(req, env, adminMaintenanceMigrateMissing(req, env));
 *  if (req.method==="POST" && url.pathname==="/admin/maintenance/cleanup") return withCors(req, env, adminMaintenanceCleanup(req, env));
 *
 *  // Backups
 *  if (req.method==="POST" && url.pathname==="/admin/backup/create") return withCors(req, env, adminBackupCreate(req, env));
 *  if (req.method==="GET"  && url.pathname==="/admin/backup/list") return withCors(req, env, adminBackupList(req, env));
 *  if (req.method==="GET"  && url.pathname==="/admin/backup/download") return withCors(req, env, adminBackupDownload(req, env));
 *  if (req.method==="GET"  && url.pathname==="/admin/backup/create_download") return withCors(req, env, adminBackupCreateDownload(req, env));
 *  if (req.method==="POST" && url.pathname==="/admin/backup/purge") return withCors(req, env, adminBackupPurge(req, env));
 *  if (req.method==="GET"  && url.pathname==="/admin/backup/verify") return withCors(req, env, adminBackupVerify(req, env));
 *  if (req.method==="GET"  && url.pathname==="/admin/backup/check") return withCors(req, env, adminBackupCheck(req, env));
 *
 *  // Users + WA
 *  if (req.method==="GET"  && url.pathname==="/admin/users") return withCors(req, env, adminUsersList(req, env));
 *  if (req.method==="POST" && url.pathname==="/admin/users/phone/upsert") return withCors(req, env, adminUserPhoneUpsert(req, env));
 *  if (req.method==="POST" && url.pathname==="/admin/wa/token/set") return withCors(req, env, adminWaTokenSet(req, env));
 *  if (req.method==="GET"  && url.pathname==="/admin/wa/token/status") return withCors(req, env, adminWaTokenStatus(req, env));
 *
 *  // Incident notify now
 *  if (req.method==="POST" && url.pathname==="/admin/incidents/notify_now") return withCors(req, env, incidentNotifyNow(req, env));
 *
 *  // Twilio inbound webhook
 *  if (req.method==="POST" && url.pathname==="/webhooks/twilio/whatsapp") return twilioWhatsAppWebhook(req, env);
 */
 
 
 // ===== Incidents (real list + detail) =====
if (req.method==="GET"  && url.pathname==="/admin/incidents") return withCors(req, env, adminIncidentsList(req, env));
if (req.method==="GET"  && url.pathname==="/admin/incidents/get") return withCors(req, env, adminIncidentsGet(req, env));

// ===== Tenants (Stage 8) =====
if (req.method==="GET"  && url.pathname==="/admin/tenants") return withCors(req, env, adminTenantsList(req, env));
if (req.method==="POST" && url.pathname==="/admin/tenants/create") return withCors(req, env, adminTenantsCreate(req, env));

// ===== Projects + events (Stage 9) =====
if (req.method==="GET"  && url.pathname==="/admin/projects") return withCors(req, env, adminProjectsList(req, env));
if (req.method==="POST" && url.pathname==="/admin/projects/create") return withCors(req, env, adminProjectsCreate(req, env));
if (req.method==="GET"  && url.pathname==="/admin/projects/events") return withCors(req, env, adminProjectEventsList(req, env));
if (req.method==="POST" && url.pathname==="/admin/projects/events/create") return withCors(req, env, adminProjectEventsCreate(req, env));

// ===== Talent schedule (Stage 9) =====
if (req.method==="GET"  && url.pathname==="/talent/schedule") return withCors(req, env, talentSchedule(req, env));

/* =========================
 * RBAC: roles, menus, role_menus
 * ========================= */



async function adminRolesList(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(req, env, 403, "forbidden", null);
  const rows = await d1All(env, `SELECT id,name,created_at FROM roles ORDER BY name ASC`, []);
  return json(req, env, 200, "ok", { roles: rows });
}

async function adminMenusList(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(req, env, 403, "forbidden", null);
  const menus = await d1All(env, `SELECT * FROM menus ORDER BY sort_order ASC, created_at ASC`, []);
  const role_menus = await d1All(env, `SELECT * FROM role_menus ORDER BY role_id, menu_id`, []);
  return json(req, env, 200, "ok", { menus, role_menus });
}

async function adminMenusUpsert(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(req, env, 403, "forbidden", null);
  const ch = await requireChallenge(env, req, a.uid, "rbac_write"); if(!ch.ok) return ch.res;

  const b = await readJson(req);
  const id = (b?.id && String(b.id).trim()) ? String(b.id).trim() : crypto.randomUUID();
  const code = String(b?.code||"").trim();
  const label = String(b?.label||"").trim();
  const path = String(b?.path||"").trim();
  const parent_id = b?.parent_id ? String(b.parent_id).trim() : null;
  const sort_order = Number(b?.sort_order||0);
  if(!code || !label || !path) return json(req, env, 400, "invalid_input", null);

  await env.DB.prepare(`
    INSERT INTO menus (id,code,label,path,parent_id,sort_order,created_at)
    VALUES (?,?,?,?,?,?,?)
    ON CONFLICT(id) DO UPDATE SET
      code=excluded.code, label=excluded.label, path=excluded.path,
      parent_id=excluded.parent_id, sort_order=excluded.sort_order
  `).bind(id, code, label, path, parent_id, sort_order, nowSec()).run();

  await audit(env,{actor_user_id:a.uid, action:"rbac.menu.upsert", target_type:"menu", target_id:id, meta:{code,path}});
  return json(req, env, 200, "ok", { id });
}

async function adminRoleMenusSet(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(req, env, 403, "forbidden", null);
  const ch = await requireChallenge(env, req, a.uid, "rbac_write"); if(!ch.ok) return ch.res;

  const b = await readJson(req);
  const role_id = String(b?.role_id||"").trim();
  const menu_ids = Array.isArray(b?.menu_ids) ? b.menu_ids.map(x=>String(x).trim()).filter(Boolean) : [];
  if(!role_id) return json(req, env, 400, "invalid_input", null);

  await env.DB.prepare(`DELETE FROM role_menus WHERE role_id=?`).bind(role_id).run();
  for (const mid of menu_ids){
    await env.DB.prepare(`INSERT INTO role_menus (role_id,menu_id,created_at) VALUES (?,?,?)`)
      .bind(role_id, mid, nowSec()).run();
  }
  await audit(env,{actor_user_id:a.uid, action:"rbac.role_menus.set", target_type:"role", target_id:role_id, meta:{count:menu_ids.length}});
  return json(req, env, 200, "ok", { updated: true });
}

/* =========================
 * Audit Viewer
 * ========================= */

async function adminAuditList(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin","admin"])) return json(req, env, 403, "forbidden", null);

  const url = new URL(req.url);
  const q = String(url.searchParams.get("q")||"").trim();
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit")||"50")));
  const since = Number(url.searchParams.get("since")||"0");

  let sql = `SELECT id,actor_user_id,action,target_type,target_id,created_at FROM audit_logs`;
  const wh = [];
  const binds = [];
  if (since>0){ wh.push("created_at>=?"); binds.push(since); }
  if (q){ wh.push("action LIKE ?"); binds.push(`%${q}%`); }
  if (wh.length) sql += " WHERE " + wh.join(" AND ");
  sql += " ORDER BY created_at DESC LIMIT ?"; binds.push(limit);

  const r = await env.DB.prepare(sql).bind(...binds).all();
  return json(req, env, 200, "ok", { rows: r.results || [] });
}

/* =========================
 * Security Dashboard APIs
 * Requires: hourly_metrics(day_key, hour_epoch, password_fail, otp_verify_fail, session_anomaly)
 * and incidents(type LIKE 'alert_%' ...).
 * ========================= */

async function adminSecuritySummary(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin","admin"])) return json(req, env, 403, "forbidden", null);

  const url = new URL(req.url);
  const days = Math.min(90, Math.max(1, Number(url.searchParams.get("days")||"7")));
  const since = nowSec() - days*86400;

  const series = await d1All(env, `
    SELECT day_key,
           SUM(password_fail) AS password_fail,
           SUM(otp_verify_fail) AS otp_verify_fail,
           SUM(session_anomaly) AS session_anomaly
    FROM hourly_metrics
    WHERE hour_epoch >= ?
    GROUP BY day_key
    ORDER BY day_key ASC
  `, [since]);

  const incidents_by_severity = await d1All(env, `
    SELECT severity, COUNT(*) AS cnt
    FROM incidents
    WHERE created_at >= ? AND type LIKE 'alert_%'
    GROUP BY severity
  `, [since]);

  const blocks = await d1Get(env, `
    SELECT COUNT(*) AS cnt
    FROM ip_blocks
    WHERE revoked_at IS NULL AND expires_at > ?
  `, [nowSec()]);

  return json(req, env, 200, "ok", {
    days,
    series,
    incidents_by_severity,
    active_ip_blocks: Number(blocks?.cnt || 0),
  });
}

async function adminSecurityIncidents(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin","admin"])) return json(req, env, 403, "forbidden", null);

  const url = new URL(req.url);
  const limit = Math.min(50, Math.max(1, Number(url.searchParams.get("limit")||"10")));

  const incs = await d1All(env, `
    SELECT id,severity,type,summary,status,created_at
    FROM incidents
    WHERE type LIKE 'alert_%' OR type LIKE 'sec_%'
    ORDER BY created_at DESC
    LIMIT ?
  `, [limit]);

  return json(req, env, 200, "ok", { incidents: incs });
}

/* =========================
 * IP Blocks
 * Requires: ip_blocks table + KV key ipblock:<ip_hash>
 * ========================= */

async function adminIpBlocksList(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(req, env, 403, "forbidden", null);

  const now = nowSec();
  const blocks = await d1All(env, `
    SELECT id, ip_hash, reason, expires_at, revoked_at, created_at, created_by_user_id
    FROM ip_blocks
    WHERE revoked_at IS NULL AND expires_at > ?
    ORDER BY created_at DESC
    LIMIT 200
  `, [now]);

  return json(req, env, 200, "ok", { blocks });
}

async function adminIpBlocksBlock(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(req, env, 403, "forbidden", null);
  const ch = await requireChallenge(env, req, a.uid, "rbac_write"); if(!ch.ok) return ch.res;

  const b = await readJson(req);
  const ip_hash = String(b?.ip_hash||"").trim();
  const ttl_sec = Math.min(7*86400, Math.max(60, Number(b?.ttl_sec||3600)));
  const reason = String(b?.reason||"manual_block").trim();
  if(!ip_hash) return json(req, env, 400, "invalid_input", null);

  await env.KV.put(`ipblock:${ip_hash}`, reason, { expirationTtl: ttl_sec });

  const id = crypto.randomUUID();
  const now = nowSec();
  const expires_at = now + ttl_sec;
  await env.DB.prepare(
    `INSERT INTO ip_blocks (id,ip_hash,reason,expires_at,created_at,created_by_user_id)
     VALUES (?,?,?,?,?,?)`
  ).bind(id, ip_hash, reason, expires_at, now, a.uid).run();

  await audit(env,{actor_user_id:a.uid, action:"ipblock.block", target_type:"ip_block", target_id:id, meta:{ttl_sec}});
  return json(req, env, 200, "ok", { blocked:true, id, expires_at });
}

async function adminIpBlocksUnblock(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(req, env, 403, "forbidden", null);
  const ch = await requireChallenge(env, req, a.uid, "rbac_write"); if(!ch.ok) return ch.res;

  const b = await readJson(req);
  const id = String(b?.id||"").trim();
  if(!id) return json(req, env, 400, "invalid_input", null);

  const row = await d1Get(env, `SELECT ip_hash FROM ip_blocks WHERE id=? LIMIT 1`, [id]);
  if(!row) return json(req, env, 400, "invalid_input", { message:"not_found" });

  await env.KV.delete(`ipblock:${row.ip_hash}`);
  await env.DB.prepare(`UPDATE ip_blocks SET revoked_at=? WHERE id=?`).bind(nowSec(), id).run();

  await audit(env,{actor_user_id:a.uid, action:"ipblock.unblock", target_type:"ip_block", target_id:id, meta:{}});
  return json(req, env, 200, "ok", { unblocked:true });
}

async function adminIpBlocksUnblockByHash(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(req, env, 403, "forbidden", null);
  const ch = await requireChallenge(env, req, a.uid, "rbac_write"); if(!ch.ok) return ch.res;

  const b = await readJson(req);
  const ip_hash = String(b?.ip_hash||"").trim();
  if(!ip_hash) return json(req, env, 400, "invalid_input", null);

  await env.KV.delete(`ipblock:${ip_hash}`);

  const now = nowSec();
  await env.DB.prepare(`
    UPDATE ip_blocks SET revoked_at=?
    WHERE id IN (
      SELECT id FROM ip_blocks
      WHERE ip_hash=? AND revoked_at IS NULL AND expires_at > ?
      ORDER BY created_at DESC LIMIT 1
    )
  `).bind(now, ip_hash, now).run();

  await audit(env,{actor_user_id:a.uid, action:"ipblock.unblock_by_hash", target_type:"ip_hash", target_id:ip_hash, meta:{}});
  return json(req, env, 200, "ok", { unblocked:true });
}

async function adminIpBlocksCheck(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin","admin"])) return json(req, env, 403, "forbidden", null);

  const url = new URL(req.url);
  const ip_hash = String(url.searchParams.get("ip_hash")||"").trim();
  if(!ip_hash) return json(req, env, 400, "invalid_input", null);

  const v = await env.KV.get(`ipblock:${ip_hash}`);
  return json(req, env, 200, "ok", { blocked: !!v, reason: v || null });
}

/* =========================
 * Tasks + DLQ + Cron processor
 * Requires: tasks, dlq tables. Cron schedule should run every minute.
 * ========================= */

function validTaskType(t){
  return ["send_otp","notify_incident","cleanup","backup","custom"].includes(t);
}
function validTaskStatus(s){
  return ["queued","processing","done","failed","dlq"].includes(s);
}

async function enqueueTask(env, type, payload, delay_sec=0){
  const id = crypto.randomUUID();
  const now = nowSec();
  await env.DB.prepare(
    `INSERT INTO tasks (id,type,payload_json,status,attempts,next_run_at,created_at,updated_at)
     VALUES (?,?,?,'queued',0,?,?,?)`
  ).bind(id, type, JSON.stringify(payload||{}), now + delay_sec, now, now).run();
  return id;
}

async function adminTasksEnqueue(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin","admin"])) return json(req, env, 403, "forbidden", null);
  const ch = await requireChallenge(env, req, a.uid, "rbac_write"); if(!ch.ok) return ch.res;

  const b = await readJson(req);
  const type = String(b?.type||"").trim();
  const payload = b?.payload ?? {};
  const delay_sec = Math.min(86400, Math.max(0, Number(b?.delay_sec||0)));
  if(!validTaskType(type)) return json(req, env, 400, "invalid_input", null);

  const id = await enqueueTask(env, type, payload, delay_sec);
  await audit(env,{actor_user_id:a.uid, action:"tasks.enqueue", target_type:"task", target_id:id, meta:{type, delay_sec}});
  return json(req, env, 200, "ok", { id, type });
}

async function adminTasksList(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin","admin"])) return json(req, env, 403, "forbidden", null);

  const url = new URL(req.url);
  const status = String(url.searchParams.get("status")||"").trim();
  const type = String(url.searchParams.get("type")||"").trim();
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit")||"50")));

  let sql = `SELECT id,type,status,attempts,next_run_at,last_error,created_at,updated_at FROM tasks`;
  const wh = [];
  const binds = [];
  if(status){
    if(!validTaskStatus(status)) return json(req, env, 400, "invalid_input", null);
    wh.push("status=?"); binds.push(status);
  }
  if(type){ wh.push("type=?"); binds.push(type); }
  if(wh.length) sql += " WHERE " + wh.join(" AND ");
  sql += " ORDER BY created_at DESC LIMIT ?"; binds.push(limit);

  const r = await env.DB.prepare(sql).bind(...binds).all();
  return json(req, env, 200, "ok", { tasks: r.results||[] });
}

async function adminDlqList(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin","admin"])) return json(req, env, 403, "forbidden", null);

  const url = new URL(req.url);
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit")||"50")));
  const r = await env.DB.prepare(`SELECT id,task_id,type,error,created_at FROM dlq ORDER BY created_at DESC LIMIT ?`)
    .bind(limit).all();
  return json(req, env, 200, "ok", { dlq: r.results||[] });
}

async function adminDlqRetry(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(req, env, 403, "forbidden", null);
  const ch = await requireChallenge(env, req, a.uid, "rbac_write"); if(!ch.ok) return ch.res;

  const b = await readJson(req);
  const id = String(b?.id||"").trim();
  if(!id) return json(req, env, 400, "invalid_input", null);

  const row = await d1Get(env, `SELECT * FROM dlq WHERE id=? LIMIT 1`, [id]);
  if(!row) return json(req, env, 404, "invalid_input", { message:"not_found" });

  const newId = await enqueueTask(env, row.type, JSON.parse(row.payload_json||"{}"), 0);
  await env.DB.prepare(`DELETE FROM dlq WHERE id=?`).bind(id).run();

  await audit(env,{actor_user_id:a.uid, action:"dlq.retry", target_type:"dlq", target_id:id, meta:{new_task_id:newId}});
  return json(req, env, 200, "ok", { retried:true, new_task_id:newId });
}

async function dispatchTask(env, type, payload){
  if (type === "cleanup") { await runCleanup(env); return; }
  if (type === "send_otp") { await taskSendOtp(env, payload); return; }
  if (type === "notify_incident") { await taskNotifyIncident(env, payload); return; }
  if (type === "backup") { /* optional hook */ return; }
  if (type === "custom") { return; }
  throw new Error("unknown_task_type");
}

async function processTasks(env, limit=10){
  const now = nowSec();
  const r = await env.DB.prepare(
    `SELECT id,type,payload_json,attempts,next_run_at
     FROM tasks
     WHERE status='queued' AND next_run_at<=?
     ORDER BY next_run_at ASC
     LIMIT ?`
  ).bind(now, limit).all();

  for (const t of (r.results||[])){
    const start = nowSec();
    try {
      await env.DB.prepare(`UPDATE tasks SET status='processing', updated_at=? WHERE id=?`).bind(start, t.id).run();
      const payload = JSON.parse(t.payload_json || "{}");
      await dispatchTask(env, t.type, payload);
      await env.DB.prepare(`UPDATE tasks SET status='done', updated_at=? WHERE id=?`).bind(nowSec(), t.id).run();
    } catch(e){
      const attempts = Number(t.attempts||0) + 1;
      const err = String(e).slice(0,500);
      const backoff = Math.min(3600, (2 ** attempts) * 30);
      const nextRun = nowSec() + backoff;

      if (attempts >= 5){
        await env.DB.prepare(
          `INSERT INTO dlq (id,task_id,type,payload_json,error,created_at) VALUES (?,?,?,?,?,?)`
        ).bind(crypto.randomUUID(), t.id, t.type, t.payload_json, err, nowSec()).run();

        await env.DB.prepare(
          `UPDATE tasks SET status='dlq', attempts=?, last_error=?, updated_at=? WHERE id=?`
        ).bind(attempts, err, nowSec(), t.id).run();
      } else {
        await env.DB.prepare(
          `UPDATE tasks SET status='queued', attempts=?, last_error=?, next_run_at=?, updated_at=? WHERE id=?`
        ).bind(attempts, err, nextRun, nowSec(), t.id).run();
      }
    }
  }
}

/* =========================
 * Maintenance: cleanup + smoke + migrate_missing
 * ========================= */

async function runCleanup(env){
  const now = nowSec();

  // Default retentions (can be made settings-driven)
  await env.DB.prepare(`DELETE FROM tasks WHERE status='done' AND updated_at < ?`).bind(now - 30*86400).run();
  await env.DB.prepare(`DELETE FROM dlq WHERE created_at < ?`).bind(now - 90*86400).run();
  await env.DB.prepare(`DELETE FROM ip_activity WHERE window_start < ?`).bind(now - 7*86400).run();
  await env.DB.prepare(
    `DELETE FROM ip_blocks WHERE created_at < ? AND (revoked_at IS NOT NULL OR expires_at < ?)`
  ).bind(now - 90*86400, now).run();
  await env.DB.prepare(
    `DELETE FROM invites WHERE created_at < ? AND (used_at IS NOT NULL OR expires_at < ?)`
  ).bind(now - 90*86400, now).run();

  // purge old backups in R2 if enabled
  try { await purgeOldBackups(env); } catch {}

  return { ok:true };
}

async function adminMaintenanceCleanup(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(req, env, 403, "forbidden", null);
  const ch = await requireChallenge(env, req, a.uid, "rbac_write"); if(!ch.ok) return ch.res;

  const res = await runCleanup(env);
  await audit(env,{actor_user_id:a.uid, action:"maintenance.cleanup.run", target_type:"system", target_id:"cleanup", meta:{}});
  return json(req, env, 200, "ok", { result: res });
}

async function adminMaintenanceSmoke(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(req, env, 403, "forbidden", null);
  const ch = await requireChallenge(env, req, a.uid, "rbac_write"); if(!ch.ok) return ch.res;

  const results = [];
  const now = nowSec();
  const pass = (name,data)=>results.push({name, ok:true, data});
  const fail = (name,e)=>results.push({name, ok:false, error:String(e)});

  try { pass("env.ALLOWED_ORIGINS", !!(env.ALLOWED_ORIGINS && String(env.ALLOWED_ORIGINS).includes("http"))); } catch(e){ fail("env.ALLOWED_ORIGINS", e); }
  try { pass("env.HASH_PEPPER", !!env.HASH_PEPPER); } catch(e){ fail("env.HASH_PEPPER", e); }
  try { pass("env.SESSION_HMAC_KEY", !!env.SESSION_HMAC_KEY); } catch(e){ fail("env.SESSION_HMAC_KEY", e); }

  try { await env.KV.put("smoke:ping", String(now), { expirationTtl: 60 }); const v=await env.KV.get("smoke:ping"); pass("kv.read_write", v===String(now)); } catch(e){ fail("kv.read_write", e); }
  try { const r=await env.DB.prepare("SELECT 1 AS ok").all(); pass("d1.select_1", r.results?.[0]?.ok===1); } catch(e){ fail("d1.select_1", e); }

  async function tableExists(t){
    const r = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=? LIMIT 1").bind(t).all();
    return !!(r.results && r.results.length);
  }
  const tables = ["users","sessions","roles","user_roles","system_settings","audit_logs","invites","ip_blocks","ip_activity","tasks","dlq","backups","incidents","hourly_metrics","user_contacts","wa_command_tokens"];
  for (const t of tables){
    try { pass(`table.${t}`, await tableExists(t)); } catch(e){ fail(`table.${t}`, e); }
  }

  const okAll = results.every(x => x.ok && x.data !== false);
  await audit(env,{actor_user_id:a.uid, action:"maintenance.smoke.run", target_type:"system", target_id:"smoke", meta:{okAll}});
  return json(req, env, 200, "ok", { okAll, results });
}

async function adminMaintenanceMigrateMissing(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(req, env, 403, "forbidden", null);
  const ch = await requireChallenge(env, req, a.uid, "rbac_write"); if(!ch.ok) return ch.res;

  const applied = [], skipped = [], errors = [];

  async function tableExists(t){
    const r = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=? LIMIT 1").bind(t).all();
    return !!(r.results && r.results.length);
  }
  async function hasColumn(table, col){
    const r = await env.DB.prepare(`PRAGMA table_info(${table})`).all();
    return (r.results || []).some(x => x.name === col);
  }
  async function run(sql, tag){
    try { await env.DB.exec(sql); applied.push(tag); } catch(e){ errors.push({tag, error:String(e)}); }
  }

  // Minimal tables (safe create)
  if (!(await tableExists("user_contacts"))) {
    await run(`
      CREATE TABLE IF NOT EXISTS user_contacts (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        channel TEXT NOT NULL,
        identifier_hash TEXT NOT NULL,
        verified_at INTEGER,
        created_at INTEGER NOT NULL
      );
      CREATE UNIQUE INDEX IF NOT EXISTS uq_user_contacts_channel_hash ON user_contacts(channel, identifier_hash);
      CREATE INDEX IF NOT EXISTS idx_user_contacts_hash ON user_contacts(channel, identifier_hash);
    `, "table.user_contacts");
  } else skipped.push("table.user_contacts");

  if (!(await tableExists("wa_command_tokens"))) {
    await run(`
      CREATE TABLE IF NOT EXISTS wa_command_tokens (
        user_id TEXT PRIMARY KEY,
        token_hash TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      );
    `, "table.wa_command_tokens");
  } else skipped.push("table.wa_command_tokens");

  // Settings defaults
  await run(`
    INSERT OR IGNORE INTO system_settings (k,v,is_secret,updated_at) VALUES
    ('wa.provider','stub',0,strftime('%s','now')),
    ('app.base_url','',0,strftime('%s','now')),
    ('backup.r2.enabled','true',0,strftime('%s','now')),
    ('backup.retention_days','30',0,strftime('%s','now'));
  `, "settings.defaults");

  const okAll = errors.length === 0;
  await audit(env,{actor_user_id:a.uid, action:"maintenance.migrate_missing", target_type:"system", target_id:"migrations", meta:{okAll, appliedCount:applied.length, errorCount:errors.length}});
  return json(req, env, 200, "ok", { okAll, applied, skipped, errors });
}

/* =========================
 * Backups (R2 optional)
 * Requires: backups table + optional env.R2 bucket binding + optional BACKUP_ENC_KEY
 * ========================= */

function maskEmail(e){
  const s = String(e||"");
  const at = s.indexOf("@");
  if (at <= 1) return "***";
  return s.slice(0,1) + "***" + s.slice(at);
}
function maskPhone(p){
  const s = String(p||"");
  if (s.length < 6) return "***";
  return s.slice(0,2) + "****" + s.slice(-2);
}
async function sha256Hex(str){
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join("");
}
async function sha256HexBytes(u8){
  const buf = await crypto.subtle.digest("SHA-256", u8);
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join("");
}
function b64(u8){ let s=""; for (const c of u8) s+=String.fromCharCode(c); return btoa(s); }
function u8FromB64(s){ const bin=atob(String(s||"")); const u8=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++)u8[i]=bin.charCodeAt(i); return u8; }

async function aesKeyFromSecret(secret){
  const raw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  return crypto.subtle.importKey("raw", raw, { name:"AES-GCM" }, false, ["encrypt","decrypt"]);
}
async function encryptIfNeeded(env, plaintext){
  if (!env.BACKUP_ENC_KEY) return { enc:false, bytes: new TextEncoder().encode(plaintext), wrapper:null };
  const key = await aesKeyFromSecret(env.BACKUP_ENC_KEY);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, key, new TextEncoder().encode(plaintext));
  const data_b64 = b64(new Uint8Array(ct));
  const iv_b64 = b64(iv);
  const sha = await sha256Hex(plaintext);
  const wrapper = JSON.stringify({ enc:true, meta:{ alg:"AES-GCM", iv_b64 }, data_b64, sha256: sha });
  return { enc:true, bytes: new TextEncoder().encode(wrapper), wrapper: JSON.parse(wrapper), sha256: sha };
}
async function decryptIfPossible(env, wrapper){
  if (!wrapper?.enc) return { ok:false, message:"not_encrypted" };
  if (!env.BACKUP_ENC_KEY) return { ok:false, message:"missing_BACKUP_ENC_KEY" };
  try{
    const key = await aesKeyFromSecret(env.BACKUP_ENC_KEY);
    const iv = u8FromB64(wrapper.meta?.iv_b64||"");
    const ct = u8FromB64(wrapper.data_b64||"");
    const pt = await crypto.subtle.decrypt({ name:"AES-GCM", iv }, key, ct);
    return { ok:true, plaintext: new TextDecoder().decode(new Uint8Array(pt)) };
  }catch(e){ return { ok:false, message:String(e) }; }
}

async function adminBackupCreate(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(req, env, 403, "forbidden", null);
  const ch = await requireChallenge(env, req, a.uid, "rbac_write"); if(!ch.ok) return ch.res;

  const b = await readJson(req);
  const mode = String(b?.mode||"redacted").trim();        // redacted|full
  const destination = String(b?.destination||"download").trim(); // download|r2
  if(!["redacted","full"].includes(mode)) return json(req, env, 400, "invalid_input", null);
  if(!["download","r2"].includes(destination)) return json(req, env, 400, "invalid_input", null);
  if(destination==="r2" && !env.R2) return json(req, env, 400, "invalid_input", { message:"R2_not_bound" });

  const allowFull = (await getSettingStr(env,"backup.allow_full","false")) === "true";
  if(mode==="full" && !allowFull) return json(req, env, 403, "forbidden", null);

  const id = crypto.randomUUID();
  const now = nowSec();

  try{
    const users = await d1All(env, `SELECT id,email_norm,phone_e164,display_name,status,created_at,updated_at FROM users`, []);
    const users_out = (mode==="redacted")
      ? users.map(u=>({id:u.id,email_masked:maskEmail(u.email_norm),phone_masked:maskPhone(u.phone_e164),display_name:u.display_name,status:u.status,created_at:u.created_at,updated_at:u.updated_at}))
      : users;

    const roles = await d1All(env, `SELECT id,name,created_at FROM roles`, []);
    const user_roles = await d1All(env, `SELECT user_id,role_id,created_at FROM user_roles`, []);
    const menus = await d1All(env, `SELECT id,code,label,path,parent_id,sort_order,created_at FROM menus`, []);
    const role_menus = await d1All(env, `SELECT role_id,menu_id,created_at FROM role_menus`, []);
    const system_settings = await d1All(env, `SELECT k,v,is_secret,updated_at FROM system_settings WHERE is_secret=0`, []);
    const incidents = await d1All(env, `SELECT id,severity,type,summary,status,created_at,updated_at FROM incidents ORDER BY created_at DESC LIMIT 5000`, []);
    const audit_logs = await d1All(env, `SELECT id,actor_user_id,action,target_type,target_id,created_at FROM audit_logs ORDER BY created_at DESC LIMIT 10000`, []);

    const payloadObj = { kind:"d1_backup", version:1, created_at:now, mode, tables:{ users:users_out, roles, user_roles, menus, role_menus, system_settings, incidents, audit_logs } };
    const plaintext = JSON.stringify(payloadObj);

    const enc = await encryptIfNeeded(env, plaintext);
    const bytes = enc.bytes;
    const size_bytes = bytes.length;

    const sha = enc.enc ? enc.sha256 : await sha256Hex(plaintext);
    let r2_key = null;

    if(destination==="r2"){
      r2_key = `backups/${id}.json${enc.enc ? ".enc" : ""}`;
      await env.R2.put(r2_key, bytes, { httpMetadata:{ contentType:"application/json" } });
    }

    await env.DB.prepare(
      `INSERT INTO backups (id,mode,destination,status,r2_key,size_bytes,sha256,created_by_user_id,created_at)
       VALUES (?,?,?,?,?,?,?,?,?)`
    ).bind(id, mode, destination, "created", r2_key, size_bytes, sha, a.uid, now).run();

    await audit(env,{actor_user_id:a.uid, action:"backup.create", target_type:"backup", target_id:id, meta:{mode,destination}});

    if(destination==="download"){
      const filename = `backup_${id}.json${enc.enc ? ".enc" : ""}`;
      return new Response(bytes, { status:200, headers:{ "content-type":"application/json; charset=utf-8", "content-disposition":`attachment; filename="${filename}"`, ...secHeaders(), ...cors(req) }});
    }
    return json(req, env, 200, "ok", { id, mode, destination, r2_key, size_bytes, sha256: sha });
  }catch(e){
    await env.DB.prepare(`INSERT INTO backups (id,mode,destination,status,created_by_user_id,created_at) VALUES (?,?,?,?,?,?)`)
      .bind(id, mode, destination, "failed", a.uid, now).run();
    return json(req, env, 500, "server_error", { message:String(e) });
  }
}

async function adminBackupList(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(req, env, 403, "forbidden", null);

  const rows = await d1All(env, `
    SELECT id,mode,destination,status,r2_key,size_bytes,sha256,created_by_user_id,created_at
    FROM backups ORDER BY created_at DESC LIMIT 50
  `, []);
  return json(req, env, 200, "ok", { backups: rows });
}

async function adminBackupDownload(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(req, env, 403, "forbidden", null);
  const ch = await requireChallenge(env, req, a.uid, "rbac_write"); if(!ch.ok) return ch.res;

  const url = new URL(req.url);
  const id = String(url.searchParams.get("id")||"").trim();
  if(!id) return json(req, env, 400, "invalid_input", null);

  const b = await d1Get(env, `SELECT * FROM backups WHERE id=? LIMIT 1`, [id]);
  if(!b) return json(req, env, 404, "invalid_input", { message:"not_found" });

  if(b.destination !== "r2") return json(req, env, 400, "invalid_input", { message:"not_r2_backup" });
  if(!env.R2) return json(req, env, 500, "server_error", { message:"R2_not_bound" });

  const obj = await env.R2.get(b.r2_key);
  if(!obj) return json(req, env, 404, "invalid_input", { message:"r2_missing" });

  const filename = `backup_${id}.json`;
  return new Response(await obj.arrayBuffer(), { status:200, headers:{ "content-type":"application/json; charset=utf-8", "content-disposition":`attachment; filename="${filename}"`, ...secHeaders(), ...cors(req) }});
}

// GET create_download with challenge token in query (for window.open)
async function adminBackupCreateDownload(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(req, env, 403, "forbidden", null);

  const url = new URL(req.url);
  const mode = String(url.searchParams.get("mode")||"redacted").trim();
  const challenge_token = String(url.searchParams.get("challenge_token")||"").trim();
  if(!["redacted","full"].includes(mode)) return json(req, env, 400, "invalid_input", null);

  const allowFull = (await getSettingStr(env,"backup.allow_full","false")) === "true";
  if(mode==="full" && !allowFull) return json(req, env, 403, "forbidden", null);

  const okCh = await verifyChallengeToken(env, a.uid, "rbac_write", challenge_token);
  if(!okCh) return json(req, env, 403, "challenge_invalid", null);

  // call create logic by emulating destination=download
  const fakeReq = new Request(req.url, { method:"POST", headers:req.headers, body: JSON.stringify({ mode, destination:"download" })});
  return await adminBackupCreate(fakeReq, env);
}

async function purgeOldBackups(env){
  if(!env.R2) return { ok:false, message:"R2_not_bound" };
  const enabled = (await getSettingStr(env,"backup.r2.enabled","true")) === "true";
  if(!enabled) return { ok:false, message:"disabled" };
  const days = Math.min(365, Math.max(1, Number(await getSettingStr(env,"backup.retention_days","30"))));
  const now = nowSec();
  const cutoff = now - days*86400;

  const rows = await d1All(env, `
    SELECT id, r2_key FROM backups
    WHERE destination='r2' AND status='created' AND created_at < ?
    LIMIT 200
  `, [cutoff]);

  let deleted=0, errors=0;
  for (const b of rows){
    try{
      if(b.r2_key) await env.R2.delete(b.r2_key);
      await env.DB.prepare(`UPDATE backups SET status='deleted' WHERE id=?`).bind(b.id).run();
      deleted++;
    }catch{ errors++; }
  }
  return { ok:true, retention_days:days, scanned:rows.length, deleted, errors };
}

async function adminBackupPurge(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(req, env, 403, "forbidden", null);
  const ch = await requireChallenge(env, req, a.uid, "rbac_write"); if(!ch.ok) return ch.res;

  const res = await purgeOldBackups(env);
  await audit(env,{actor_user_id:a.uid, action:"backup.purge", target_type:"system", target_id:"backup_purge", meta:res});
  return json(req, env, 200, "ok", res);
}

async function adminBackupVerify(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(req, env, 403, "forbidden", null);
  const ch = await requireChallenge(env, req, a.uid, "rbac_write"); if(!ch.ok) return ch.res;
  if(!env.R2) return json(req, env, 500, "server_error", { message:"R2_not_bound" });

  const url = new URL(req.url);
  const id = String(url.searchParams.get("id")||"").trim();
  if(!id) return json(req, env, 400, "invalid_input", null);

  const b = await d1Get(env, `SELECT * FROM backups WHERE id=? LIMIT 1`, [id]);
  if(!b || b.destination!=="r2" || !b.r2_key) return json(req, env, 400, "invalid_input", { message:"not_r2_backup" });

  const obj = await env.R2.get(b.r2_key);
  if(!obj) return json(req, env, 404, "invalid_input", { message:"r2_object_missing" });

  const buf = new Uint8Array(await obj.arrayBuffer());
  const text = new TextDecoder().decode(buf);

  let parsed;
  try { parsed = JSON.parse(text); } catch { return json(req, env, 200, "ok", { id, valid:false, reason:"json_parse_failed" }); }

  if(parsed?.enc === true){
    const wrapperOk = !!(parsed.meta?.iv_b64 && parsed.data_b64 && parsed.sha256);
    const dec = await decryptIfPossible(env, parsed);
    if(dec.ok){
      const ptHash = await sha256Hex(dec.plaintext);
      const match = (ptHash === String(parsed.sha256));
      return json(req, env, 200, "ok", { id, valid: match, kind:"encrypted", wrapper_ok: wrapperOk, sha256_match: match });
    }
    return json(req, env, 200, "ok", { id, valid: wrapperOk, kind:"encrypted", wrapper_ok: wrapperOk, sha256_match: null, note: dec.message });
  }

  const calc = await sha256Hex(text);
  const match = (calc === String(b.sha256||""));
  const schemaOk = parsed?.kind === "d1_backup" && parsed?.version === 1 && parsed?.tables;
  return json(req, env, 200, "ok", { id, valid: match && schemaOk, kind:"plain", sha256_match: match, schema_ok: schemaOk, expected_sha256: b.sha256, calculated_sha256: calc });
}

async function adminBackupCheck(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(req, env, 403, "forbidden", null);
  const ch = await requireChallenge(env, req, a.uid, "rbac_write"); if(!ch.ok) return ch.res;
  if(!env.R2) return json(req, env, 500, "server_error", { message:"R2_not_bound" });

  const url = new URL(req.url);
  const id = String(url.searchParams.get("id")||"").trim();
  if(!id) return json(req, env, 400, "invalid_input", null);

  const b = await d1Get(env, `SELECT * FROM backups WHERE id=? LIMIT 1`, [id]);
  if(!b || b.destination!=="r2" || !b.r2_key) return json(req, env, 400, "invalid_input", null);

  const obj = await env.R2.get(b.r2_key);
  if(!obj) return json(req, env, 404, "invalid_input", null);

  let parsed;
  try { parsed = JSON.parse(await obj.text()); } catch { return json(req, env, 200, "ok", { id, ok:false, reason:"json_parse_failed" }); }
  if(parsed?.enc === true){
    const dec = await decryptIfPossible(env, parsed);
    if(!dec.ok) return json(req, env, 200, "ok", { id, ok:false, reason:"cannot_decrypt", note: dec.message });
    try { parsed = JSON.parse(dec.plaintext); } catch { return json(req, env, 200, "ok", { id, ok:false, reason:"decrypted_json_parse_failed" }); }
  }

  const requiredTables = ["users","roles","user_roles","system_settings"];
  const missing = requiredTables.filter(t => !parsed?.tables?.[t]);
  const counts = {};
  for (const [k,v] of Object.entries(parsed?.tables||{})) counts[k] = Array.isArray(v) ? v.length : 0;

  const okAll = missing.length===0 && parsed?.kind==="d1_backup" && parsed?.version===1;
  return json(req, env, 200, "ok", { id, ok: okAll, kind: parsed?.kind, version: parsed?.version, mode: parsed?.mode, missing_tables: missing, counts });
}

/* =========================
 * Users + WhatsApp mapping + WA command token
 * Requires: users table has email_norm, phone_e164, display_name, status
 * user_contacts table, wa_command_tokens table
 * ========================= */

async function adminUsersList(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin","admin"])) return json(req, env, 403, "forbidden", null);

  const url = new URL(req.url);
  const q = String(url.searchParams.get("q")||"").trim().toLowerCase();
  const limit = Math.min(100, Math.max(1, Number(url.searchParams.get("limit")||"25")));

  let sql = `SELECT id,display_name,email_norm,phone_e164,status,updated_at FROM users`;
  const binds = [];
  if(q){
    sql += ` WHERE email_norm LIKE ? OR display_name LIKE ?`;
    binds.push(`%${q}%`,`%${q}%`);
  }
  sql += ` ORDER BY updated_at DESC LIMIT ?`;
  binds.push(limit);

  const r = await env.DB.prepare(sql).bind(...binds).all();
  const rows = (r.results||[]).map(u=>({
    id:u.id,
    display_name:u.display_name,
    email_masked: maskEmail(u.email_norm||""),
    phone: u.phone_e164 ? maskPhone(u.phone_e164) : null,
    status:u.status,
    phone_e164_present: !!u.phone_e164
  }));
  return json(req, env, 200, "ok", { users: rows });
}

async function adminUserPhoneUpsert(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(req, env, 403, "forbidden", null);
  const ch = await requireChallenge(env, req, a.uid, "rbac_write"); if(!ch.ok) return ch.res;

  const b = await readJson(req);
  const user_id = String(b?.user_id||"").trim();
  const phone_e164 = String(b?.phone_e164||"").trim();
  if(!user_id || !phone_e164.startsWith("+")) return json(req, env, 400, "invalid_input", null);

  await env.DB.prepare(`UPDATE users SET phone_e164=?, updated_at=? WHERE id=?`).bind(phone_e164, nowSec(), user_id).run();

  // upsert user_contacts (whatsapp)
  const h = await sha256Base64(`${phone_e164}|${env.HASH_PEPPER}`);
  const id = crypto.randomUUID();
  const now = nowSec();
  await env.DB.prepare(
    `INSERT INTO user_contacts (id,user_id,channel,identifier_hash,verified_at,created_at)
     VALUES (?,?,?,?,?,?)
     ON CONFLICT(channel,identifier_hash) DO UPDATE SET user_id=excluded.user_id, verified_at=excluded.verified_at`
  ).bind(id, user_id, "whatsapp", h, now, now).run();

  await audit(env,{actor_user_id:a.uid, action:"user.phone.upsert", target_type:"user", target_id:user_id, meta:{phone_hash:h}});
  return json(req, env, 200, "ok", { updated:true });
}

async function adminWaTokenSet(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(req, env, 403, "forbidden", null);
  const ch = await requireChallenge(env, req, a.uid, "rbac_write"); if(!ch.ok) return ch.res;

  const b = await readJson(req);
  const user_id = String(b?.user_id||"").trim();
  const token_plain = String(b?.token_plain||"").trim();
  if(!user_id || token_plain.length < 6) return json(req, env, 400, "invalid_input", null);

  const h = await sha256Base64(`${token_plain}|${env.HASH_PEPPER}`);
  await env.DB.prepare(`
    INSERT INTO wa_command_tokens (user_id,token_hash,updated_at)
    VALUES (?,?,?)
    ON CONFLICT(user_id) DO UPDATE SET token_hash=excluded.token_hash, updated_at=excluded.updated_at
  `).bind(user_id, h, nowSec()).run();

  await audit(env,{actor_user_id:a.uid, action:"wa.token.set", target_type:"user", target_id:user_id, meta:{}});
  return json(req, env, 200, "ok", { updated:true });
}

async function adminWaTokenStatus(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin","admin"])) return json(req, env, 403, "forbidden", null);

  const url = new URL(req.url);
  const user_id = String(url.searchParams.get("user_id")||"").trim();
  if(!user_id) return json(req, env, 400, "invalid_input", null);

  const row = await d1Get(env, `SELECT updated_at FROM wa_command_tokens WHERE user_id=? LIMIT 1`, [user_id]);
  return json(req, env, 200, "ok", { has_token: !!row, updated_at: row?.updated_at || null });
}

/* =========================
 * Twilio WhatsApp outbound (provider)
 * Requires: system_settings wa.provider=stub|twilio
 * Twilio secrets: TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_WHATSAPP_FROM
 * ========================= */

async function sendWhatsApp(env, { to, message }){
  const provider = await getSettingStr(env, "wa.provider", "stub");

  if (provider === "stub") {
    const toHash = await sha256Base64(`${to}|${env.HASH_PEPPER}`);
    await audit(env, { actor_user_id: null, action: "wa.stub.sent", target_type: "wa_to_hash", target_id: toHash, meta: { len: message.length } });
    return;
  }

  if (provider === "twilio") {
    if (!env.TWILIO_ACCOUNT_SID || !env.TWILIO_AUTH_TOKEN || !env.TWILIO_WHATSAPP_FROM) throw new Error("twilio_missing_secrets");

    const from = String(env.TWILIO_WHATSAPP_FROM);
    const toWa = to.startsWith("whatsapp:") ? to : `whatsapp:${to}`;
    const url = `https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(env.TWILIO_ACCOUNT_SID)}/Messages.json`;
    const body = new URLSearchParams({ From: from, To: toWa, Body: message });
    const auth = btoa(`${env.TWILIO_ACCOUNT_SID}:${env.TWILIO_AUTH_TOKEN}`);

    const resp = await fetch(url, { method:"POST", headers:{ "authorization":`Basic ${auth}`, "content-type":"application/x-www-form-urlencoded;charset=UTF-8" }, body });
    if (!resp.ok) {
      const toHash = await sha256Base64(`${to}|${env.HASH_PEPPER}`);
      await audit(env, { actor_user_id: null, action: "wa.twilio.fail", target_type: "wa_to_hash", target_id: toHash, meta: { status: resp.status } });
      throw new Error(`twilio_send_failed_${resp.status}`);
    }

    const toHash = await sha256Base64(`${to}|${env.HASH_PEPPER}`);
    await audit(env, { actor_user_id: null, action: "wa.twilio.sent", target_type: "wa_to_hash", target_id: toHash, meta: { ok: true } });
    return;
  }

  throw new Error("wa_provider_not_supported");
}

function fmtSeverityEmoji(sev){
  const s = String(sev||"").toLowerCase();
  if (s==="critical") return "🛑";
  if (s==="high") return "⚠️";
  if (s==="medium") return "🔶";
  return "ℹ️";
}
function sanitizeOneLine(s, max=180){
  const t = String(s||"").replace(/\s+/g," ").trim();
  return t.length > max ? t.slice(0,max-1)+"…" : t;
}
async function buildIncidentLink(env, incident_id){
  const base = await getSettingStr(env, "app.base_url", "");
  if(!base) return "";
  return `${base}#/incident?id=${encodeURIComponent(incident_id)}`;
}

/* =========================
 * Task: send_otp / notify_incident
 * NOTE: OTP plaintext for delivery is stored at otp_plain:<otp_ref> TTL 180 sec (from PART 1).
 * ========================= */

async function taskSendOtp(env, payload){
  const user_id = String(payload?.user_id||"").trim();
  const action = String(payload?.action||"").trim();
  const otp_ref = String(payload?.otp_ref||"").trim();
  if(!user_id || !otp_ref) throw new Error("invalid_payload");

  const u = await d1Get(env, `SELECT phone_e164 FROM users WHERE id=? LIMIT 1`, [user_id]);
  if(!u?.phone_e164) throw new Error("missing_phone");

  const otp_plain = await env.KV.get(`otp_plain:${otp_ref}`);
  if(!otp_plain) throw new Error("otp_plain_missing_or_expired");

  const msg = `Kode OTP (${action}): ${otp_plain}\nBerlaku 10 menit.`;
  await sendWhatsApp(env, { to: String(u.phone_e164), message: msg });

  await env.KV.delete(`otp_plain:${otp_ref}`);
  await audit(env, { actor_user_id: user_id, action: "otp.sent", target_type: "otp_ref", target_id: otp_ref, meta: { action } });
}

// routing stubs; replace with your oncall routing tables if you already have them.
async function resolveGroupForType(env, incidentType){
  // If you have oncall_routing_rules table, implement here.
  // Minimal: return null (fallback to super_admin).
  return null;
}
async function getOncallUserForGroup(env, group_id){
  return null;
}

async function taskNotifyIncident(env, payload){
  const incident_id = String(payload?.incident_id||"").trim();
  if(!incident_id) throw new Error("invalid_payload");

  const inc = await d1Get(env, `SELECT id,severity,type,summary,status,created_at,owner_user_id FROM incidents WHERE id=? LIMIT 1`, [incident_id]);
  if(!inc) throw new Error("incident_not_found");
  if(String(inc.status||"").toLowerCase()==="closed") return;

  let group_id = null;
  try { group_id = await resolveGroupForType(env, inc.type); } catch {}
  let oncall_uid = null;
  if(group_id){ try { oncall_uid = await getOncallUserForGroup(env, group_id); } catch {} }

  let recips = [];
  if(oncall_uid){
    const u = await d1Get(env, `SELECT id,phone_e164 FROM users WHERE id=? LIMIT 1`, [oncall_uid]);
    if(u?.phone_e164) recips = [u];
  }
  if(!recips.length){
    recips = await d1All(env, `
      SELECT u.id,u.phone_e164
      FROM users u
      JOIN user_roles ur ON ur.user_id=u.id
      JOIN roles r ON r.id=ur.role_id
      WHERE r.name='super_admin' AND u.status='active' AND u.phone_e164 IS NOT NULL
      LIMIT 5
    `, []);
  }
  if(!recips.length){
    await audit(env,{actor_user_id:null, action:"incident.notify.skip", target_type:"incident", target_id:incident_id, meta:{reason:"no_recipients"}});
    return;
  }

  const emoji = fmtSeverityEmoji(inc.severity);
  const title = `${emoji} INCIDENT ${String(inc.severity||"").toUpperCase()} • ${inc.type}`;
  const summary = sanitizeOneLine(inc.summary||"", 220);
  const link = await buildIncidentLink(env, inc.id);
  let msg = `${title}\n${summary}\nStatus: ${inc.status}\nID: ${inc.id}`;
  if(link) msg += `\n\nOpen: ${link}`;

  for(const r of recips){
    if(!r.phone_e164) continue;
    await sendWhatsApp(env, { to: r.phone_e164, message: msg });
  }

  const recipHashes = [];
  for(const r of recips) recipHashes.push(await sha256Base64(`${r.phone_e164}|${env.HASH_PEPPER}`));
  await audit(env,{actor_user_id:null, action:"incident.notify.sent", target_type:"incident", target_id:incident_id, meta:{group_id, oncall_user_id:oncall_uid, recip_count:recips.length, recip_hashes:recipHashes.slice(0,5)}});
}

async function incidentNotifyNow(req, env){
  const a = await requireAuth(env, req); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin","admin"])) return json(req, env, 403, "forbidden", null);
  const ch = await requireChallenge(env, req, a.uid, "incident_write"); if(!ch.ok) return ch.res;

  const b = await readJson(req);
  const incident_id = String(b?.incident_id||"").trim();
  if(!incident_id) return json(req, env, 400, "invalid_input", null);

  const task_id = await enqueueTask(env, "notify_incident", { incident_id }, 0);
  await audit(env,{actor_user_id:a.uid, action:"incident.notify.enqueued", target_type:"task", target_id:task_id, meta:{incident_id}});
  return json(req, env, 200, "ok", { enqueued:true, task_id });
}

/* =========================
 * Twilio inbound webhook (WhatsApp commands)
 * Verify signature + sender mapping + token per user + rate limit
 * Requires: user_contacts, wa_command_tokens
 * ========================= */

async function twilioValidateSignature(env, req, formParams){
  const sig = req.headers.get("X-Twilio-Signature") || "";
  if(!sig || !env.TWILIO_AUTH_TOKEN) return false;

  const url = new URL(req.url);
  const fullUrl = url.origin + url.pathname;

  const keys = Array.from(formParams.keys()).sort();
  let data = fullUrl;
  for(const k of keys) data += k + formParams.get(k);

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.TWILIO_AUTH_TOKEN),
    { name:"HMAC", hash:"SHA-1" },
    false,
    ["sign"]
  );
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  const b64sig = btoa(String.fromCharCode(...new Uint8Array(mac)));
  return timingSafeEqual(b64sig, sig);
}

async function userIdByWhatsAppFrom(env, from){
  const e164 = String(from||"").replace(/^whatsapp:/,"").trim();
  if(!e164.startsWith("+")) return null;
  const h = await sha256Base64(`${e164}|${env.HASH_PEPPER}`);
  const row = await d1Get(env, `SELECT user_id FROM user_contacts WHERE channel='whatsapp' AND identifier_hash=? LIMIT 1`, [h]);
  return row?.user_id || null;
}

function escapeXml(s){
  return String(s||"")
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;")
    .replaceAll('"',"&quot;")
    .replaceAll("'","&apos;");
}
function twiml(message){
  const xml = `<?xml version="1.0" encoding="UTF-8"?><Response><Message>${escapeXml(message)}</Message></Response>`;
  return new Response(xml, { status:200, headers:{ "content-type":"application/xml; charset=utf-8" }});
}

async function twilioWhatsAppWebhook(req, env){
  const ct = req.headers.get("content-type") || "";
  if(!ct.includes("application/x-www-form-urlencoded")) return new Response("bad_request", { status:400 });

  const bodyText = await req.text();
  const params = new URLSearchParams(bodyText);

  const okSig = await twilioValidateSignature(env, req, params);
  if(!okSig) return new Response("unauthorized", { status:401 });

  const from = params.get("From") || "";
  const text = (params.get("Body") || "").trim();

  // rate limit per sender hash
  const e164 = String(from).replace(/^whatsapp:/,"").trim();
  const senderHash = await sha256Base64(`${e164}|${env.HASH_PEPPER}`);
  const n = await rateLimitKeyInc(env, `wa:rl:${senderHash}`, 300); // 5 min
  if(n > 30) return twiml("Rate limited. Try later.");

  const uid = await userIdByWhatsAppFrom(env, from);
  if(!uid) return twiml("Sorry, your number is not registered.");

  const roles = await getRolesForUser(env, uid);
  if(!hasRole(roles, ["super_admin","admin","staff"])) return twiml("Sorry, not authorized.");

  const parts = text.split(/\s+/).filter(Boolean);
  const cmd = (parts[0] || "").toUpperCase();

  if(cmd === "HELP" || !cmd){
    return twiml("Commands:\nSTATUS <id>\nACK <id> <token>\nASSIGN <id> <token>\nCLOSE <id> <token>");
  }

  const incident_id = parts[1] || "";
  if(!incident_id) return twiml("Missing incident id. Use: STATUS <id>");

  const inc = await d1Get(env, `SELECT id,status,severity,type,summary,owner_user_id FROM incidents WHERE id=? LIMIT 1`, [incident_id]);
  if(!inc) return twiml("Incident not found.");

  if(cmd === "STATUS"){
    return twiml(`Status: ${inc.status}\n${inc.severity} • ${inc.type}\n${sanitizeOneLine(inc.summary, 180)}`);
  }

  const writeCmd = (cmd === "ACK" || cmd === "ASSIGN" || cmd === "CLOSE");
  if(!writeCmd) return twiml("Commands:\nSTATUS <id>\nACK <id> <token>\nASSIGN <id> <token>\nCLOSE <id> <token>");

  const token = parts[2] || "";
  if(!token) return twiml("Token required. Example: ACK <incident_id> <token>");

  const tr = await d1Get(env, `SELECT token_hash FROM wa_command_tokens WHERE user_id=? LIMIT 1`, [uid]);
  if(!tr?.token_hash) return twiml("No token set. Ask admin.");
  const got = await sha256Base64(`${token}|${env.HASH_PEPPER}`);
  if(got !== tr.token_hash){
    await audit(env,{actor_user_id:uid, action:"wa.cmd.token_invalid", target_type:"incident", target_id:incident_id, meta:{cmd}});
    return twiml("Token invalid.");
  }

  const now = nowSec();

  if(cmd === "ASSIGN"){
    await env.DB.prepare(`UPDATE incidents SET owner_user_id=?, status='ack', updated_at=? WHERE id=?`)
      .bind(uid, now, incident_id).run();
    await audit(env,{actor_user_id:uid, action:"incident.assign.via_wa", target_type:"incident", target_id:incident_id, meta:{}});
    return twiml(`ASSIGN OK: ${incident_id}`);
  }

  if(cmd === "ACK"){
    await env.DB.prepare(`UPDATE incidents SET status='ack', owner_user_id=COALESCE(owner_user_id, ?), updated_at=? WHERE id=?`)
      .bind(uid, now, incident_id).run();
    await audit(env,{actor_user_id:uid, action:"incident.ack.via_wa", target_type:"incident", target_id:incident_id, meta:{}});
    return twiml(`ACK OK: ${incident_id}`);
  }

  if(cmd === "CLOSE"){
    await env.DB.prepare(`UPDATE incidents SET status='closed', updated_at=? WHERE id=?`)
      .bind(now, incident_id).run();
    await audit(env,{actor_user_id:uid, action:"incident.close.via_wa", target_type:"incident", target_id:incident_id, meta:{}});
    return twiml(`CLOSE OK: ${incident_id}`);
  }

  return twiml("OK");
}

/* =========================
 * Scheduled handler (cron)
 * You must MERGE this into export default in PART 1.
 * Example:
 * export default { fetch, scheduled }
 * ========================= */

// Add this function into export default in PART 1:
// async scheduled(event, env, ctx){ ctx.waitUntil(processTasks(env, 10)); }

/* =========================
 * IMPORTANT: OTP enqueue integration
 * In PART 1, otpRequest() returns {enqueued:false}. Update otpRequest() to enqueue send_otp like this:
 *
 * const task_id = await enqueueTask(env, "send_otp", { user_id: user.id, action, otp_ref: ref }, 0);
 * return json(req, env, 200, "ok", { otp_ref: ref, action, enqueued:true, task_id });
 *
 * That way OTP is delivered by cron with retry+DLQ.
 * ========================= */