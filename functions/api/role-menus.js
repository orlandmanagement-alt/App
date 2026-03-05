// App/functions/api/role-menus.js
// /api/role-menus
// GET  : role menus by role_id
// POST : replace role menus (super_admin only)

import { json, readJson, hasRole } from "../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }
function canRead(sess){ return hasRole(sess.roles, ["super_admin","admin","staff"]); }
function onlySuperAdmin(sess){ return hasRole(sess.roles, ["super_admin"]); }

export async function onRequestGet({ env, data, request }) {
  const sess = data.session;
  if(!canRead(sess)) return json(403, "forbidden", null);

  const url = new URL(request.url);
  const role_id = String(url.searchParams.get("role_id")||"").trim();
  if(!role_id) return json(400, "invalid_input", { message:"role_id_required" });

  const rows = await env.DB.prepare(
    "SELECT role_id,menu_id,created_at FROM role_menus WHERE role_id=? ORDER BY menu_id"
  ).bind(role_id).all();

  return json(200, "ok", { role_id, menu_ids: (rows.results||[]).map(x=>x.menu_id) });
}

export async function onRequestPost({ env, data, request }) {
  const sess = data.session;
  if(!onlySuperAdmin(sess)) return json(403, "forbidden", null);

  const b = await readJson(request);
  const role_id = String(b?.role_id||"").trim();
  const menu_ids = Array.isArray(b?.menu_ids) ? b.menu_ids.map(x=>String(x).trim()).filter(Boolean) : [];

  if(!role_id) return json(400, "invalid_input", { message:"role_id_required" });

  // Validate role exists
  const role = await env.DB.prepare("SELECT id FROM roles WHERE id=? LIMIT 1").bind(role_id).first();
  if(!role) return json(400, "invalid_input", { message:"role_not_found" });

  // Validate menus exist (optional strict)
  if(menu_ids.length){
    const placeholders = menu_ids.map(()=>"?").join(",");
    const found = await env.DB.prepare(`SELECT id FROM menus WHERE id IN (${placeholders})`).bind(...menu_ids).all();
    const foundSet = new Set((found.results||[]).map(x=>x.id));
    const missing = menu_ids.filter(id => !foundSet.has(id));
    if(missing.length) return json(400, "invalid_input", { message:"menu_not_found", missing });
  }

  await env.DB.prepare("DELETE FROM role_menus WHERE role_id=?").bind(role_id).run();
  const now = nowSec();
  for(const mid of menu_ids){
    await env.DB.prepare("INSERT INTO role_menus (role_id,menu_id,created_at) VALUES (?,?,?)")
      .bind(role_id, mid, now).run();
  }

  return json(200, "ok", { updated:true, role_id, count: menu_ids.length });
}
