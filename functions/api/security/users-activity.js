// App/functions/api/security/users-activity.js
// GET /api/security/users-activity?minutes=60&limit=20
// super_admin/admin read

import { json, hasRole } from "../../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }

async function topByKind(env, kind, since, limit){
  // aggregate ip_activity per ip_hash for a kind
  const r = await env.DB.prepare(`
    SELECT ip_hash, SUM(cnt) AS total, MAX(updated_at) AS last_seen_at
    FROM ip_activity
    WHERE kind=? AND window_start >= ?
    GROUP BY ip_hash
    ORDER BY total DESC
    LIMIT ?
  `).bind(kind, since, limit).all();

  const rows = r.results || [];
  if (!rows.length) return [];

  // Join to user by last_ip_hash (best effort)
  const out = [];
  for (const x of rows) {
    const u = await env.DB.prepare(`
      SELECT id,email_norm,display_name,last_login_at,status
      FROM users
      WHERE last_ip_hash=? 
      ORDER BY last_login_at DESC
      LIMIT 1
    `).bind(x.ip_hash).first();

    out.push({
      ip_hash: x.ip_hash,
      total: Number(x.total || 0),
      last_seen_at: Number(x.last_seen_at || 0),
      user: u ? {
        id: u.id,
        email_norm: u.email_norm,
        display_name: u.display_name,
        last_login_at: u.last_login_at,
        status: u.status
      } : null
    });
  }
  return out;
}

export async function onRequestGet({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin","admin"])) return json(403,"forbidden",null);

  const url = new URL(request.url);
  const minutes = Math.min(7*24*60, Math.max(5, Number(url.searchParams.get("minutes") || "60")));
  const limit = Math.min(50, Math.max(5, Number(url.searchParams.get("limit") || "20")));

  const since = nowSec() - minutes*60;

  const top_password_fail = await topByKind(env, "password_fail", since, limit);
  const top_otp_verify_fail = await topByKind(env, "otp_verify_fail", since, limit);
  const top_session_anomaly = await topByKind(env, "session_anomaly", since, limit);

  return json(200,"ok",{
    window_minutes: minutes,
    top_password_fail,
    top_otp_verify_fail,
    top_session_anomaly
  });
}
