import { json, hasRole } from "../../_lib.js";

function nowSec() { return Math.floor(Date.now() / 1000); }

export async function onRequestGet({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin", "admin"])) return json(403, "forbidden", null);

  const url = new URL(request.url);
  const days = Math.min(90, Math.max(1, Number(url.searchParams.get("days") || "7")));
  const since = nowSec() - days * 86400;

  // daily series from hourly_metrics (table kamu pakai PK "hour")
  // asumsi hour string bentuk "YYYY-MM-DD HH" atau sejenis, tapi kita aman: pakai updated_at sebagai filter
  // jika hour format kamu beda, kita tinggal adjust query
  const series = await env.DB.prepare(`
    SELECT
      substr(hour, 1, 10) AS day_key,
      SUM(COALESCE(password_fail,0)) AS password_fail,
      SUM(COALESCE(otp_verify_fail,0)) AS otp_verify_fail,
      SUM(COALESCE(rate_limited,0)) AS rate_limited,
      SUM(COALESCE(lockouts,0)) AS lockouts,
      SUM(COALESCE(session_anomaly,0)) AS session_anomaly
    FROM hourly_metrics
    WHERE updated_at >= ?
    GROUP BY day_key
    ORDER BY day_key ASC
  `).bind(since).all();

  // active ip blocks count
  const blocks = await env.DB.prepare(`
    SELECT COUNT(*) AS cnt
    FROM ip_blocks
    WHERE revoked_at IS NULL AND expires_at > ?
  `).bind(nowSec()).first();

  // recent security incidents count (optional)
  const inc = await env.DB.prepare(`
    SELECT severity, COUNT(*) AS cnt
    FROM incidents
    WHERE created_at >= ? AND (type LIKE 'alert_%' OR type LIKE 'sec_%')
    GROUP BY severity
  `).bind(since).all();

  return json(200, "ok", {
    days,
    active_ip_blocks: Number(blocks?.cnt || 0),
    series: series.results || [],
    incidents_by_severity: inc.results || [],
  });
}
