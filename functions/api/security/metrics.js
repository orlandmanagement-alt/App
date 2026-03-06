import { json, hasRole } from "../../_lib.js";
function nowSec(){ return Math.floor(Date.now()/1000); }
export async function onRequestGet({ env, data, request }){
  const sess=data.session;
  if(!hasRole(sess.roles, ["super_admin","admin"])) return json(403,"forbidden",null);
  const url=new URL(request.url);
  const days=Math.min(90, Math.max(1, Number(url.searchParams.get("days")||"7")));
  const since=nowSec() - days*86400;
  const r=await env.DB.prepare(`
    SELECT day_key,
      SUM(password_fail) AS password_fail,
      SUM(rate_limited) AS rate_limited,
      SUM(lockouts) AS lockouts,
      SUM(session_anomaly) AS session_anomaly
    FROM hourly_metrics
    WHERE hour_epoch >= ?
    GROUP BY day_key
    ORDER BY day_key ASC
  `).bind(since).all();
  const blocks=await env.DB.prepare(`SELECT COUNT(*) AS cnt FROM ip_blocks WHERE revoked_at IS NULL AND expires_at > ?`).bind(nowSec()).first();
  return json(200,"ok",{ days, series:r.results||[], active_ip_blocks:Number(blocks?.cnt||0) });
}
