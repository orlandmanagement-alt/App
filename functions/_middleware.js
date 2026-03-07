import { audit, requireAuth } from "./_lib.js";

export async function onRequest(ctx) {
  const { request, env } = ctx;
  const url = new URL(request.url);

  // Only audit API routes
  if (!url.pathname.startsWith("/api/")) {
    return await ctx.next();
  }

  // Best-effort actor (no hard fail)
  let actor_user_id = null;
  try {
    const a = await requireAuth(env, request);
    if (a.ok) actor_user_id = a.uid;
  } catch {}

  const res = await ctx.next();

  // Write audit log (best effort)
  try {
    await audit(env, {
      actor_user_id,
      action: "http.request",
      route: `${request.method} ${url.pathname}`,
      http_status: res.status,
      meta: {}
    });
  } catch {}

  // Security headers for API
  const h = new Headers(res.headers);
  h.set("cache-control","no-store");
  h.set("x-content-type-options","nosniff");
  return new Response(res.body, { status: res.status, headers: h });
}
