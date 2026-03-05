// App/functions/_lib.js — FULL (latest)
// Cloudflare Pages Functions helpers (D1 + KV + R2)
// Notes:
// - PBKDF2 iteration is clamped to max 100000 to avoid runtime limit errors.
// - Session is stored in KV as opaque sid cookie (HttpOnly).

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
  if (ct.includes("application/json")) {
    return await request.json().catch(() => null);
  }
  // allow empty body
  const t = await request.text().catch(() => "");
  if (!t) return null;
  try {
    return JSON.parse(t);
  } catch {
    return null;
  }
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
  // Secure + HttpOnly for auth cookies
  return `${name}=${encodeURIComponent(value)}; Path=${path}; HttpOnly; Secure; SameSite=${sameSite}; Max-Age=${maxAge}`;
}

export function timingSafeEqual(a, b) {
  a = String(a || "");
  b = String(b || "");
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

export function normEmail(email) {
  return String(email || "").trim().toLowerCase();
}

export function requireEnv(env, keys) {
  const missing = [];
  for (const k of keys) if (!env?.[k]) missing.push(k);
  return missing;
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
 * PBKDF2 (SHA-256) with iteration clamp.
 * Some Workers runtimes reject iterations > 100000.
 */
export async function pbkdf2Hash(password, saltB64, iterations) {
  const iterReq = Number(iterations || 100000);

  // Clamp iterations to avoid runtime limit
  const iter = Math.min(100000, Math.max(10000, iterReq));

  const salt = Uint8Array.from(atob(String(saltB64 || "")), (c) => c.charCodeAt(0));
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(String(password || "")),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  // derive 256-bit key
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: iter },
    baseKey,
    256
  );
  return btoa(String.fromCharCode(...new Uint8Array(bits)));
}

export function hasRole(roles, allowed) {
  const s = new Set((roles || []).map(String));
  return allowed.some((r) => s.has(r));
}

export async function getRolesForUser(env, userId) {
  const r = await env.DB.prepare(
    `SELECT r.name AS name
     FROM user_roles ur
     JOIN roles r ON r.id=ur.role_id
     WHERE ur.user_id=?`
  )
    .bind(userId)
    .all();
  return (r.results || []).map((x) => x.name);
}

/**
 * Session stored in KV: sess:<sid> = {uid, roles, exp}
 * TTL depends on role.
 */
export async function createSession(env, userId, roles) {
  const sid = crypto.randomUUID();

  // TTLs (seconds)
  const ttlAdmin = Number(env.SESSION_TTL_SEC_ADMIN || 7200); // 2h
  const ttlStaff = Number(env.SESSION_TTL_SEC_STAFF || 28800); // 8h
  const ttl = hasRole(roles, ["super_admin", "admin"]) ? ttlAdmin : ttlStaff;

  const exp = Math.floor(Date.now() / 1000) + ttl;

  await env.KV.put(`sess:${sid}`, JSON.stringify({ uid: userId, roles, exp }), {
    expirationTtl: ttl,
  });

  return { sid, ttl, exp };
}

export async function getSession(env, sid) {
  if (!sid) return null;
  const raw = await env.KV.get(`sess:${sid}`);
  if (!raw) return null;

  let sess;
  try {
    sess = JSON.parse(raw);
  } catch {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  if (now > Number(sess?.exp || 0)) return null;
  return sess;
}
