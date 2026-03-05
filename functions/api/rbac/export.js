import { json, hasRole } from "../../_lib.js";

export async function onRequestGet({ env, data }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin"])) return json(403, "forbidden", null);

  const roles = await env.DB.prepare(`SELECT id,name,created_at FROM roles ORDER BY name ASC`).all();
  const menus = await env.DB.prepare(`SELECT id,code,label,path,parent_id,sort_order,icon,created_at FROM menus ORDER BY sort_order ASC`).all();
  const role_menus = await env.DB.prepare(`SELECT role_id,menu_id,created_at FROM role_menus ORDER BY role_id,menu_id`).all();

  return json(200, "ok", {
    exported_at: Math.floor(Date.now()/1000),
    roles: roles.results||[],
    menus: menus.results||[],
    role_menus: role_menus.results||[],
  });
}
