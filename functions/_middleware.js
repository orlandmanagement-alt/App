// App/functions/_middleware.js
import { json, readCookie, getSession, sha256Base64 } from "./_lib.js";

function getClientIp(req){
  return req.headers.get("cf-connecting-ip")
    || req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    || "0.0.0.0";
}
async function ipHash(env, ip){
  return await sha256Base64(`${ip}|${env.HASH_PEPPER}`);
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

  // Only protect /api/*
  if (!path.startsWith("/api/")) return next();

  // 1) IP block check (skip for PUBLIC)
  if (!PUBLIC.has(path)) {
    if (!env.KV) return json(500, "server_error", { message: "missing_KV_binding" });
    if (!env.HASH_PEPPER) return json(500, "server_error", { message: "missing_HASH_PEPPER" });

    const ip = getClientIp(request);
    const h = await ipHash(env, ip);
    const reason = await env.KV.get(`ipblock:${h}`);
    if (reason) return json(403, "forbidden", { message: "ip_blocked", reason });
  }

  // 2) Public endpoints
  if (PUBLIC.has(path)) return next();

  // 3) Require session
  const sid = readCookie(request, "sid");
  const sess = await getSession(env, sid);
  if (!sess) return json(401, "unauthorized", null);

  // Attach session to context for handlers
  context.data.session = { uid: sess.uid, roles: sess.roles, exp: sess.exp };
  return next();
}
