// App/functions/api/ip-blocks/check.js
// GET /api/ip-blocks/check?ip_hash=...

import { json, hasRole } from "../../_lib.js";

export async function onRequestGet({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin", "admin"])) return json(403, "forbidden", null);

  const url = new URL(request.url);
  const ip_hash = String(url.searchParams.get("ip_hash") || "").trim();
  if (!ip_hash) return json(400, "invalid_input", { message: "ip_hash_required" });

  const v = await env.KV.get(`ipblock:${ip_hash}`);
  return json(200, "ok", { blocked: !!v, reason: v || null });
}
