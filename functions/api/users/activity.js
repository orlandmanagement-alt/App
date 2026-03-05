import { json, hasRole } from "../../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }

export async function onRequestGet({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin", "admin"])) return json(403, "forbidden", null);

  const url = new URL(request.url);
  const q = String(url.searchParams.get("q") || "").trim().toLowerCase();
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit") || "50")));
  const now = nowSec();

  let sql = `SELECT id,email_norm,display_name,status,last_login_at,last_ip_hash,session_version,updated_at FROM users`;
  const binds = [];
  if (q) {
    sql += " WHERE email_norm LIKE ? OR display_name LIKE ?";
    binds.push(`%${q}%`, `%${q}%`);
  }
  sql += " ORDER BY last_login_at DESC NULLS LAST, updated_at DESC LIMIT ?";
  binds.push(limit);

  const r = await env.DB.prepare(sql).bind(...binds).all();
  const rows = r.results || [];

  const out = [];
  for (const u of rows) {
    // roles
    const rr = await env.DB.prepare(`
      SELECT r.name AS name
      FROM user_roles ur JOIN roles r ON r.id=ur.role_id
      WHERE ur.user_id=?
    `).bind(u.id).all();
    const roles = (rr.results || []).map(x => x.name);

    // only admin/staff/super_admin
    const adminish = roles.some(x => ["super_admin","admin","staff"].includes(x));
    if (!adminish) continue;

    // blocked?
    let blocked = false;
    let reason = null;
    if (u.last_ip_hash) {
      const b = await env.DB.prepare(`
        SELECT reason,expires_at
        FROM ip_blocks
        WHERE ip_hash=? AND revoked_at IS NULL AND expires_at > ?
        ORDER BY created_at DESC LIMIT 1
      `).bind(u.last_ip_hash, now).first();
      if (b) { blocked = true; reason = b.reason; }
    }

    out.push({
      id: u.id,
      email_norm: u.email_norm,
      display_name: u.display_name,
      status: u.status,
      roles,
      last_login_at: u.last_login_at || null,
      last_ip_hash: u.last_ip_hash || null,
      blocked,
      block_reason: reason,
      session_version: u.session_version,
    });
  }

  return json(200, "ok", { users: out });
}
