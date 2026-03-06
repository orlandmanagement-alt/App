import { json, hasRole } from "../../_lib.js";
function nowSec(){ return Math.floor(Date.now()/1000); }
export async function onRequestGet({ env, data, request }){
  const sess=data.session;
  if(!hasRole(sess.roles, ["super_admin","admin"])) return json(403,"forbidden",null);
  const url=new URL(request.url);
  const days=Math.min(90, Math.max(1, Number(url.searchParams.get("days")||"7")));
  const since=nowSec() - days*86400;
  const r=await env.DB.prepare(`
    SELECT id,day_key,hour_epoch,password_fail,otp_verify_fail,session_anomaly,created_at,updated_at
    FROM hourly_metrics
    WHERE hour_epoch >= ?
    ORDER BY hour_epoch ASC
    LIMIT 5000
  `).bind(since).all();
  return json(200,"ok",{ days, rows:r.results||[] });
}
