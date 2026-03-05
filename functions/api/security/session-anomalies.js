import { json, hasRole } from "../../_lib.js";

export async function onRequestGet({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin", "admin"])) return json(403, "forbidden", null);

  const url = new URL(request.url);
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit") || "50")));

  const r = await env.DB.prepare(`
    SELECT id, actor_user_id, action, target_type, target_id, created_at
    FROM audit_logs
    WHERE action LIKE 'session.anomaly%'
    ORDER BY created_at DESC
    LIMIT ?
  `).bind(limit).all();

  return json(200, "ok", { rows: r.results || [] });
}
