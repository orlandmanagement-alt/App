import { json, readCookie, getSession } from "./_lib.js";

const PUBLIC = new Set([
  "/api/setup/status",
  "/api/setup/bootstrap",
  "/api/login",
]);

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  // hanya guard /api/*
  if (!path.startsWith("/api/")) return next();

  if (PUBLIC.has(path)) return next();

  const sid = readCookie(request, "sid");
  const sess = await getSession(env, sid);

  if (!sess) return json(401, "unauthorized", null);

  context.data.session = sess;
  return next();
}
