// App/functions/api/security/summary.js
import { json, hasRole } from "../../_lib.js";

function nowSec() { return Math.floor(Date.now() / 1000); }

export async function onRequestGet({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin", "admin"])) return json(403, "forbidden", null);

  const url = new URL(request.url);
  const days = Math.min(90, Math.max(1, Number(url.searchParams.get("days") || "7")));
  const since = nowSec() - days * 86400;

  // ✅ hourly_metrics schema baru: (day_key, hour_epoch, password_fail, otp_verify_fail, session_anomaly, updated_at)
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
  `).bind(since).all();

  const blocks = await env.DB.prepare(`
    SELECT COUNT(*) AS cnt
    FROM ip_blocks
    WHERE revoked_at IS NULL AND expires_at > ?
  `).bind(nowSec()).first();

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
