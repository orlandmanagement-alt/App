// App/functions/api/ip-blocks/by-user.js
// GET /api/ip-blocks/by-user?user_id=...

import { json, hasRole } from "../../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }

export async function onRequestGet({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin", "admin"])) return json(403, "forbidden", null);

  const url = new URL(request.url);
  const user_id = String(url.searchParams.get("user_id") || "").trim();
  if (!user_id) return json(400, "invalid_input", { message: "user_id_required" });

  const u = await env.DB.prepare(
    "SELECT id,email_norm,display_name,last_ip_hash,last_login_at,status FROM users WHERE id=? LIMIT 1"
  ).bind(user_id).first();

  if (!u) return json(404, "invalid_input", { message: "user_not_found" });
  if (!u.last_ip_hash) return json(200, "ok", { user: u, blocks: [] });

  const now = nowSec();
  const r = await env.DB.prepare(`
    SELECT id,ip_hash,reason,expires_at,revoked_at,created_at,created_by_user_id
    FROM ip_blocks
    WHERE ip_hash=? AND revoked_at IS NULL AND expires_at > ?
    ORDER BY created_at DESC
    LIMIT 50
  `).bind(u.last_ip_hash, now).all();

  return json(200, "ok", { user: u, blocks: r.results || [] });
}
