// App/functions/_lib.js

export function json(code, status, data, extraHeaders = {}) {
  return new Response(JSON.stringify({ status, data }), {
    status: code,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders,
    },
  });
}

export async function readJson(request) {
  const ct = request.headers.get("content-type") || "";
  if (ct.includes("application/json")) return await request.json().catch(() => null);
  const t = await request.text().catch(() => "");
  if (!t) return null;
  try { return JSON.parse(t); } catch { return null; }
}

export function normEmail(email) {
  return String(email || "").trim().toLowerCase();
}

export function timingSafeEqual(a, b) {
  a = String(a || "");
  b = String(b || "");
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

export function hasRole(roles, allowed) {
  const s = new Set((roles || []).map(String));
  return allowed.some((r) => s.has(r));
}

export function readCookie(request, name) {
  const c = request.headers.get("cookie") || "";
  const m = c.match(new RegExp("(^|;\\s*)" + name + "=([^;]+)"));
  return m ? decodeURIComponent(m[2]) : "";
}

export function cookie(name, value, opt = {}) {
  const maxAge = opt.maxAge ?? 3600;
  const sameSite = opt.sameSite ?? "Lax";
  const path = opt.path ?? "/";
  return `${name}=${encodeURIComponent(value)}; Path=${path}; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=${maxAge}`;
}

export function randomB64(bytes = 16) {
  const u8 = crypto.getRandomValues(new Uint8Array(bytes));
  return btoa(String.fromCharCode(...u8));
}

export async function sha256Base64(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

/**
 * PBKDF2 SHA-256 with iteration clamp (Pages limit)
 * - Cloudflare Pages PBKDF2 sering gagal kalau iter > 100000
 */
export async function pbkdf2Hash(password, saltB64, iterations) {
  const iterReq = Number(iterations || 100000);
  const iter = Math.min(100000, Math.max(10000, iterReq));

  const salt = Uint8Array.from(atob(String(saltB64 || "")), (c) => c.charCodeAt(0));
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(String(password || "")),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: iter },
    baseKey,
    256
  );
  return btoa(String.fromCharCode(...new Uint8Array(bits)));
}

export async function getRolesForUser(env, userId) {
  const r = await env.DB.prepare(
    `SELECT r.name AS name
     FROM user_roles ur
     JOIN roles r ON r.id=ur.role_id
     WHERE ur.user_id=?`
  ).bind(userId).all();
  return (r.results || []).map((x) => x.name);
}

/**
 * Session in KV: sess:<sid> = { uid, roles, exp, ua_hash, ip_prefix_hash }
 */
export async function createSession(env, userId, roles, bind = null) {
  const sid = crypto.randomUUID();

  const ttlAdmin = Number(env.SESSION_TTL_SEC_ADMIN || 7200);
  const ttlStaff = Number(env.SESSION_TTL_SEC_STAFF || 28800);
  const ttl = hasRole(roles, ["super_admin", "admin"]) ? ttlAdmin : ttlStaff;

  const exp = Math.floor(Date.now() / 1000) + ttl;

  const payload = {
    uid: userId,
    roles,
    exp,
    ua_hash: bind?.ua_hash || null,
    ip_prefix_hash: bind?.ip_prefix_hash || null,
  };

  await env.KV.put(`sess:${sid}`, JSON.stringify(payload), { expirationTtl: ttl });
  return { sid, ttl, exp };
}

export async function getSession(env, sid) {
  if (!sid) return null;
  const raw = await env.KV.get(`sess:${sid}`);
  if (!raw) return null;

  let sess;
  try { sess = JSON.parse(raw); } catch { return null; }

  const now = Math.floor(Date.now() / 1000);
  if (now > Number(sess?.exp || 0)) return null;

  return sess;
}

/** Best-effort audit */
export async function audit(env, { actor_user_id, action, target_type, target_id, meta }) {
  try {
    const id = crypto.randomUUID();
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare(
      `INSERT INTO audit_logs (id,actor_user_id,action,target_type,target_id,meta_json,created_at)
       VALUES (?,?,?,?,?,?,?)`
    ).bind(
      id,
      actor_user_id || null,
      String(action),
      target_type || null,
      target_id || null,
      meta ? JSON.stringify(meta) : null,
      now
    ).run();
  } catch {}
}

/** KV rate limit counter */
export async function rateLimitKV(env, key, limit, ttlSec) {
  if (!env.KV) return { ok: true, n: 0 };
  const cur = Number((await env.KV.get(key)) || "0");
  const next = cur + 1;
  await env.KV.put(key, String(next), { expirationTtl: ttlSec });
  return { ok: next <= limit, n: next };
}
