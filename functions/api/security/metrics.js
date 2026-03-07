import { json, requireAuth, hasRole, nowSec } from "../../_lib.js";
import { tableCols, has } from "./_cols.js";

export async function onRequestGet({ request, env }){
  const a = await requireAuth(env, request); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin","admin"])) return json(403,"forbidden",null);

  const url = new URL(request.url);
  const days = Math.min(90, Math.max(1, Number(url.searchParams.get("days")||"7")));
  const since = nowSec() - days*86400;

  const cols = await tableCols(env, "hourly_metrics");

  // Build safe select parts
  const pw = has(cols,"password_fail") ? "SUM(password_fail) AS password_fail" : "0 AS password_fail";
  const otp = has(cols,"otp_verify_fail") ? "SUM(otp_verify_fail) AS otp_verify_fail" : "0 AS otp_verify_fail";
  const anom = has(cols,"session_anomaly") ? "SUM(session_anomaly) AS session_anomaly" : "0 AS session_anomaly";
  const rate = has(cols,"rate_limited") ? "SUM(rate_limited) AS rate_limited" : "0 AS rate_limited";

  // We prefer day_key/hour_epoch schema (your D1 already has it)
  const hasDayKey = has(cols,"day_key");
  const hasHourEpoch = has(cols,"hour_epoch");

  if(!hasDayKey || !hasHourEpoch){
    // fallback: return empty but still ok (so UI doesn't crash)
    const blocks = await env.DB.prepare(
      `SELECT COUNT(*) AS c FROM ip_blocks WHERE revoked_at IS NULL AND expires_at > ?`
    ).bind(nowSec()).first();

    return json(200,"ok",{ days, series: [], active_ip_blocks: Number(blocks?.c||0), note:"hourly_metrics schema missing day_key/hour_epoch" });
  }

  const r = await env.DB.prepare(`
    SELECT day_key,
           ${pw},
           ${otp},
           ${anom},
           ${rate}
    FROM hourly_metrics
    WHERE hour_epoch >= ?
    GROUP BY day_key
    ORDER BY day_key ASC
  `).bind(since).all();

  const blocks = await env.DB.prepare(
    `SELECT COUNT(*) AS c FROM ip_blocks WHERE revoked_at IS NULL AND expires_at > ?`
  ).bind(nowSec()).first();

  return json(200,"ok",{
    days,
    series: r.results || [],
    active_ip_blocks: Number(blocks?.c || 0)
  });
}
