// App/functions/api/dlq.js
// GET /api/dlq?limit=
// super_admin/admin read

import { json, hasRole } from "../_lib.js";

function canRead(sess){ return hasRole(sess.roles, ["super_admin","admin"]); }

export async function onRequestGet({ env, data, request }){
  const sess = data.session;
  if(!canRead(sess)) return json(403,"forbidden",null);

  const url = new URL(request.url);
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit")||"50")));

  const r = await env.DB.prepare(`
    SELECT id,task_id,type,error,created_at
    FROM dlq
    ORDER BY created_at DESC
    LIMIT ?
  `).bind(limit).all();

  return json(200,"ok",{ dlq: r.results || [] });
}
