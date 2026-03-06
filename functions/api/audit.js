import { json, hasRole } from "../_lib.js";
export async function onRequestGet({ env, data, request }){
  const sess=data.session;
  if(!hasRole(sess.roles, ["super_admin","admin"])) return json(403,"forbidden",null);
  const url=new URL(request.url);
  const q=String(url.searchParams.get("q")||"").trim();
  const limit=Math.min(200, Math.max(1, Number(url.searchParams.get("limit")||"50")));
  const since=Number(url.searchParams.get("since")||"0");

  let sql="SELECT id,actor_user_id,action,target_type,target_id,meta_json,created_at,ip_hash,ua_hash,route,http_status,duration_ms FROM audit_logs";
  const wh=[]; const binds=[];
  if(since>0){ wh.push("created_at>=?"); binds.push(since); }
  if(q){ wh.push("action LIKE ?"); binds.push(`%${q}%`); }
  if(wh.length) sql += " WHERE " + wh.join(" AND ");
  sql += " ORDER BY created_at DESC LIMIT ?"; binds.push(limit);

  const r=await env.DB.prepare(sql).bind(...binds).all();
  return json(200,"ok",{ rows:r.results||[] });
}
