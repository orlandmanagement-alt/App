// App/functions/_middleware.js
import { json, readCookie, getSession, sha256Base64 } from "./_lib.js";

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
async function ipHash(env, ip) {
  return await sha256Base64(`${ip}|${env.HASH_PEPPER}`);
}
async function ipPrefixHash(env, ip) {
  return await sha256Base64(`${ipPrefix(ip)}|${env.HASH_PEPPER}`);
}
async function uaHash(env, ua) {
  return await sha256Base64(`${String(ua || "")}|${env.HASH_PEPPER}`);
}

// Public endpoints (no login)
const PUBLIC = new Set([
  "/api/setup/status",
  "/api/setup/bootstrap",
  "/api/login",
]);

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  if (!path.startsWith("/api/")) return next();
  if (!env.DB) return json(500, "server_error", { message: "missing_binding_DB" });
  if (!env.KV) return json(500, "server_error", { message: "missing_binding_KV" });
  if (!env.HASH_PEPPER) return json(500, "server_error", { message: "missing_HASH_PEPPER" });

  // 1) IP block check (skip public)
  if (!PUBLIC.has(path)) {
    const ip = getClientIp(request);
    const h = await ipHash(env, ip);
    const reason = await env.KV.get(`ipblock:${h}`);
    if (reason) return json(403, "forbidden", { message: "ip_blocked", reason });
  }

  // 2) allow public endpoints
  if (PUBLIC.has(path)) return next();

  // 3) require session
  const sid = readCookie(request, "sid");
  const sess = await getSession(env, sid);
  if (!sess) return json(401, "unauthorized", null);

  // 4) session binding check for admin/super_admin
  const roles = sess.roles || [];
  const isAdmin = roles.includes("super_admin") || roles.includes("admin");

  if (isAdmin && sess.ua_hash && sess.ip_prefix_hash) {
    const ua = request.headers.get("user-agent") || "";
    const ip = getClientIp(request);

    const curUaH = await uaHash(env, ua);
    const curPrefH = await ipPrefixHash(env, ip);

    if (curUaH !== sess.ua_hash || curPrefH !== sess.ip_prefix_hash) {
      // revoke KV session
      await env.KV.delete(`sess:${sid}`);
      return json(403, "forbidden", { message: "session_anomaly_relogin" });
    }
  }

  context.data.session = { uid: sess.uid, roles: sess.roles, exp: sess.exp, sid };
  return next();
}
