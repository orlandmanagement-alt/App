import { json, readJson, requireAuth, hasRole, nowSec } from "../../_lib.js";

/**
 * POST /api/role-menus/set
 * Body: { role_id, menu_ids: [] }
 * Super Admin only
 */
export async function onRequestPost({ request, env }) {
  const a = await requireAuth(env, request);
  if (!a.ok) return a.res;
  if (!hasRole(a.roles, ["super_admin"])) return json(403, "forbidden", null);

  const b = await readJson(request);
  const role_id = String(b?.role_id || "").trim();
  const menu_ids = Array.isArray(b?.menu_ids) ? b.menu_ids.map(x => String(x).trim()).filter(Boolean) : [];

  if (!role_id) return json(400, "invalid_input", { message: "role_id_required" });

  const now = nowSec();

  await env.DB.prepare(`DELETE FROM role_menus WHERE role_id=?`).bind(role_id).run();

  for (const mid of menu_ids) {
    await env.DB.prepare(
      `INSERT INTO role_menus (role_id, menu_id, created_at) VALUES (?,?,?)`
    ).bind(role_id, mid, now).run();
  }

  return json(200, "ok", { updated: true, count: menu_ids.length });
}
