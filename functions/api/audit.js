import { json, requireAuth } from "../_lib.js";

export async function onRequestGet({ request, env }) {
  const a = await requireAuth(env, request);
  if(!a.ok) return a.res;

  const url = new URL(request.url);
  const q = String(url.searchParams.get("q")||"").trim();
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit")||"80")));

  let sql = `SELECT actor_user_id, action, meta_json, created_at FROM audit_logs`;
  const wh = [];
  const binds = [];
  if(q){ wh.push("action LIKE ?"); binds.push(`%${q}%`); }
  if(wh.length) sql += " WHERE " + wh.join(" AND ");
  sql += " ORDER BY created_at DESC LIMIT ?"; binds.push(limit);

  const r = await env.DB.prepare(sql).bind(...binds).all();
  const rows = (r.results||[]).map(x=>{
    let meta={};
    try{ meta = JSON.parse(x.meta_json||"{}"); }catch{}
    return {
      actor_user_id: x.actor_user_id || null,
      action: x.action,
      route: meta.route || null,
      http_status: meta.http_status || null,
      created_at: x.created_at
    };
  });

  return json(200,"ok",{ rows });
}
