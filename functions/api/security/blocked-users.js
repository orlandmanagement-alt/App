// App/functions/api/security/blocked-users.js
import { json, hasRole } from "../../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }

export async function onRequestGet({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin"])) return json(403, "forbidden", null);

  const url = new URL(request.url);
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit") || "100")));
  const now = nowSec();

  const r = await env.DB.prepare(`
    SELECT
      b.id AS block_id,
      b.ip_hash,
      b.reason,
      b.expires_at,
      b.created_at,
      u.id AS user_id,
      u.email_norm,
      u.display_name,
      u.status,
      u.last_login_at
    FROM ip_blocks b
    LEFT JOIN users u ON u.last_ip_hash = b.ip_hash
    WHERE b.revoked_at IS NULL AND b.expires_at > ?
    ORDER BY b.created_at DESC
    LIMIT ?
  `).bind(now, limit).all();

  return json(200, "ok", { rows: r.results || [] });
}
