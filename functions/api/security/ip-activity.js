import { json, requireAuth, hasRole, nowSec } from "../../_lib.js";

export async function onRequestGet({ request, env }){
  const a = await requireAuth(env, request); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin","admin"])) return json(403,"forbidden",null);

  const url = new URL(request.url);
  const kind = String(url.searchParams.get("kind")||"password_fail").trim();
  const minutes = Math.min(24*60, Math.max(5, Number(url.searchParams.get("minutes")||"240")));
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit")||"20")));

  const since = nowSec() - minutes*60;

  // ip_activity schema: ip_hash, kind, cnt, window_start, updated_at
  const r = await env.DB.prepare(`
    SELECT ip_hash,
           SUM(cnt) AS total,
           MAX(updated_at) AS last_seen_at
    FROM ip_activity
    WHERE kind=? AND window_start >= ?
    GROUP BY ip_hash
    ORDER BY total DESC
    LIMIT ?
  `).bind(kind, since, limit).all();

  return json(200,"ok",{ rows: r.results || [], kind, minutes });
}
