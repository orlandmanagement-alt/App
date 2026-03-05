// App/functions/api/security/overview.js
// GET /api/security/overview?days=7&minutes=60&limit=20
//
// Returns:
// - summary: { days, active_ip_blocks, series[], incidents_by_severity[] }
// - activity: { window_minutes, top_password_fail[], top_otp_verify_fail[], top_session_anomaly[] }
// - recent_blocks: { blocks[] }
//
// Access: super_admin/admin

import { json, hasRole } from "../../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }

async function topByKind(env, kind, since, limit){
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

  // Attach best-effort user by last_ip_hash
  const out = [];
  for (const x of rows){
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
        status: u.status,
      } : null
    });
  }
  return out;
}

export async function onRequestGet({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin","admin"])) return json(403,"forbidden",null);

  const url = new URL(request.url);
  const days = Math.min(90, Math.max(1, Number(url.searchParams.get("days") || "7")));
  const minutes = Math.min(7*24*60, Math.max(5, Number(url.searchParams.get("minutes") || "60")));
  const limit = Math.min(50, Math.max(5, Number(url.searchParams.get("limit") || "20")));

  const now = nowSec();
  const sinceDays = now - days*86400;
  const sinceMin = now - minutes*60;

  // ---- summary series (hourly_metrics schema: day_key, hour_epoch)
  const series = await env.DB.prepare(`
    SELECT
      day_key,
      SUM(COALESCE(password_fail,0)) AS password_fail,
      SUM(COALESCE(otp_verify_fail,0)) AS otp_verify_fail,
      SUM(COALESCE(session_anomaly,0)) AS session_anomaly
    FROM hourly_metrics
    WHERE hour_epoch >= ?
    GROUP BY day_key
    ORDER BY day_key ASC
  `).bind(sinceDays).all();

  const blocksCnt = await env.DB.prepare(`
    SELECT COUNT(*) AS cnt
    FROM ip_blocks
    WHERE revoked_at IS NULL AND expires_at > ?
  `).bind(now).first();

  const incSev = await env.DB.prepare(`
    SELECT severity, COUNT(*) AS cnt
    FROM incidents
    WHERE created_at >= ? AND (type LIKE 'alert_%' OR type LIKE 'sec_%')
    GROUP BY severity
  `).bind(sinceDays).all();

  // ---- recent active blocks + attach user
  const rb = await env.DB.prepare(`
    SELECT id,ip_hash,reason,expires_at,revoked_at,created_at,created_by_user_id
    FROM ip_blocks
    WHERE revoked_at IS NULL AND expires_at > ?
    ORDER BY created_at DESC
    LIMIT ?
  `).bind(now, Math.min(200, limit)).all();

  const blocks = [];
  for (const b of (rb.results || [])){
    const u = await env.DB.prepare(`
      SELECT id,email_norm,display_name,last_login_at,status
      FROM users
      WHERE last_ip_hash=?
      ORDER BY last_login_at DESC
      LIMIT 1
    `).bind(b.ip_hash).first();

    blocks.push({
      ...b,
      user: u ? {
        id: u.id,
        email_norm: u.email_norm,
        display_name: u.display_name,
        last_login_at: u.last_login_at,
        status: u.status,
      } : null
    });
  }

  // ---- activity tops
  const top_password_fail = await topByKind(env, "password_fail", sinceMin, limit);
  const top_otp_verify_fail = await topByKind(env, "otp_verify_fail", sinceMin, limit);
  const top_session_anomaly = await topByKind(env, "session_anomaly", sinceMin, limit);

  return json(200,"ok",{
    summary: {
      days,
      active_ip_blocks: Number(blocksCnt?.cnt || 0),
      series: series.results || [],
      incidents_by_severity: incSev.results || [],
    },
    activity: {
      window_minutes: minutes,
      top_password_fail,
      top_otp_verify_fail,
      top_session_anomaly,
    },
    recent_blocks: { blocks }
  });
}
