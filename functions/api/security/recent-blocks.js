// App/functions/api/security/recent-blocks.js
// GET /api/security/recent-blocks?limit=50
// super_admin/admin read

import { json, hasRole } from "../../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }

export async function onRequestGet({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin","admin"])) return json(403,"forbidden",null);

  const url = new URL(request.url);
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit") || "50")));

  const now = nowSec();

  const r = await env.DB.prepare(`
    SELECT id,ip_hash,reason,expires_at,revoked_at,created_at,created_by_user_id
    FROM ip_blocks
    WHERE revoked_at IS NULL AND expires_at > ?
    ORDER BY created_at DESC
    LIMIT ?
  `).bind(now, limit).all();

  const blocks = r.results || [];

  // attach user by last_ip_hash
  const out = [];
  for (const b of blocks) {
    const u = await env.DB.prepare(`
      SELECT id,email_norm,display_name,last_login_at,status
      FROM users
      WHERE last_ip_hash=?
      ORDER BY last_login_at DESC
      LIMIT 1
    `).bind(b.ip_hash).first();

    out.push({
      ...b,
      user: u ? {
        id: u.id,
        email_norm: u.email_norm,
        display_name: u.display_name,
        last_login_at: u.last_login_at,
        status: u.status
      } : null
    });
  }

  return json(200,"ok",{ blocks: out });
}
