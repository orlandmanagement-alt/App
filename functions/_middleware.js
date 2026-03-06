// App/functions/_middleware.js — FULLPACK
import { json, readCookie, getSession, sha256Base64, getUserSessionVersion, audit } from "./_lib.js";

function nowMs(){ return Date.now(); }
function getClientIp(req) {
  return (
    req.headers.get("cf-connecting-ip") ||
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    "0.0.0.0"
  );
}
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
async function ipHash(env, ip) { return await sha256Base64(`${ip}|${env.HASH_PEPPER}`); }
async function ipPrefixHash(env, ip) { return await sha256Base64(`${ipPrefix(ip)}|${env.HASH_PEPPER}`); }
async function uaHash(env, ua) { return await sha256Base64(`${String(ua || "")}|${env.HASH_PEPPER}`); }

// PUBLIC endpoints (no login)
const PUBLIC = new Set([
  "/api/health",
  "/api/setup/status",
  "/api/setup/bootstrap",
  "/api/login",
  "/api/password/reset/request",
  "/api/password/reset/confirm",
  "/api/password/reset/validate",
  "/api/invites/accept",
]);

export async function onRequest(context) {
  const start = nowMs();
  const { request, env, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  if (!path.startsWith("/api/")) return next();

  if (!env.DB) return json(500, "server_error", { message: "missing_binding_DB" });
  if (!env.KV) return json(500, "server_error", { message: "missing_binding_KV" });
  if (!env.HASH_PEPPER) return json(500, "server_error", { message: "missing_HASH_PEPPER" });

  const ip = getClientIp(request);
  const ip_h = await ipHash(env, ip);

  // IP block check (skip public)
  if (!PUBLIC.has(path)) {
    const reason = await env.KV.get(`ipblock:${ip_h}`);
    if (reason) return json(403, "forbidden", { message: "ip_blocked", reason });
  }

  // Allow public
  if (PUBLIC.has(path)) {
    const res = await next();
    await logReqBestEffort({ env, request, path, start, sessionUid: null, ip_h, res });
    return res;
  }

  // Require session
  const sid = readCookie(request, "sid");
  const sess = await getSession(env, sid);
  if (!sess) {
    const res = json(401, "unauthorized", null);
    await logReqBestEffort({ env, request, path, start, sessionUid: null, ip_h, res });
    return res;
  }

  // Session version check (force logout)
  const dbSv = await getUserSessionVersion(env, sess.uid);
  const tokenSv = Number(sess?.sv || 1);
  if (dbSv !== tokenSv) {
    await env.KV.delete(`sess:${sid}`);
    const res = json(401, "unauthorized", { message: "session_revoked_relogin" });
    await logReqBestEffort({ env, request, path, start, sessionUid: sess.uid, ip_h, res });
    return res;
  }

  // Admin binding check
  const roles = sess.roles || [];
  const isAdmin = roles.includes("super_admin") || roles.includes("admin");
  if (isAdmin && sess.ua_hash && sess.ip_prefix_hash) {
    const curUaH = await uaHash(env, request.headers.get("user-agent") || "");
    const curPrefH = await ipPrefixHash(env, ip);
    if (curUaH !== sess.ua_hash || curPrefH !== sess.ip_prefix_hash) {
      await env.KV.delete(`sess:${sid}`);
      const res = json(403, "forbidden", { message: "session_anomaly_relogin" });
      await logReqBestEffort({ env, request, path, start, sessionUid: sess.uid, ip_h, res });
      return res;
    }
  }

  context.data.session = { uid: sess.uid, roles: sess.roles, exp: sess.exp, sid };
  const res = await next();
  await logReqBestEffort({ env, request, path, start, sessionUid: sess.uid, ip_h, res });
  return res;
}

async function logReqBestEffort({ env, request, path, start, sessionUid, ip_h, res }) {
  try {
    const duration_ms = Math.max(0, nowMs() - start);
    const ua_h = await uaHash(env, request.headers.get("user-agent") || "");
    await audit(env, {
      actor_user_id: sessionUid || null,
      action: "http.request",
      target_type: "route",
      target_id: path,
      meta: { method: request.method },
      ip_hash: ip_h,
      ua_hash: ua_h,
      route: path,
      http_status: res.status,
      duration_ms,
    });
  } catch {}
}
