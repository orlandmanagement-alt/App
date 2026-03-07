import { json, requireAuth, hasRole, nowSec } from "../../_lib.js";
import { tableCols, has } from "./_cols.js";

export async function onRequestGet({ request, env }){
  const a = await requireAuth(env, request); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin","admin"])) return json(403,"forbidden",null);

  const url = new URL(request.url);
  const days = Math.min(30, Math.max(1, Number(url.searchParams.get("days")||"7")));
  const since = nowSec() - days*86400;

  const cols = await tableCols(env, "hourly_metrics");

  const hasHourEpoch = has(cols,"hour_epoch");
  if(!hasHourEpoch){
    return json(200,"ok",{ rows: [], note:"hourly_metrics schema missing hour_epoch" });
  }

  const pw = has(cols,"password_fail") ? "password_fail" : "0 AS password_fail";
  const otp = has(cols,"otp_verify_fail") ? "otp_verify_fail" : "0 AS otp_verify_fail";
  const anom = has(cols,"session_anomaly") ? "session_anomaly" : "0 AS session_anomaly";

  const r = await env.DB.prepare(`
    SELECT hour_epoch,
           ${pw},
           ${otp},
           ${anom}
    FROM hourly_metrics
    WHERE hour_epoch >= ?
    ORDER BY hour_epoch ASC
    LIMIT 2000
  `).bind(since).all();

  return json(200,"ok",{ rows: r.results || [] });
}
