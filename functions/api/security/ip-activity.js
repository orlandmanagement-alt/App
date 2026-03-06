import { json, hasRole } from "../../_lib.js";
function nowSec(){ return Math.floor(Date.now()/1000); }
export async function onRequestGet({ env, data, request }){
  const sess=data.session;
  if(!hasRole(sess.roles, ["super_admin","admin"])) return json(403,"forbidden",null);
  const url=new URL(request.url);
  const kind=String(url.searchParams.get("kind")||"password_fail").trim();
  const minutes=Math.min(7*24*60, Math.max(5, Number(url.searchParams.get("minutes")||"60")));
  const limit=Math.min(200, Math.max(5, Number(url.searchParams.get("limit")||"20")));
  const since=nowSec() - minutes*60;
  const r=await env.DB.prepare(`
    SELECT ip_hash, SUM(cnt) AS total, MAX(updated_at) AS last_seen_at
    FROM ip_activity
    WHERE kind=? AND window_start >= ?
    GROUP BY ip_hash
    ORDER BY total DESC
    LIMIT ?
  `).bind(kind, since, limit).all();
  return json(200,"ok",{ kind, window_minutes: minutes, rows:r.results||[] });
}
