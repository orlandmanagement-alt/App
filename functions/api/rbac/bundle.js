import { json, requireAuth, hasRole, menusHasIcon } from "../../_lib.js";

export async function onRequestGet({ request, env }){
  const a = await requireAuth(env, request); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin","admin"])) return json(403,"forbidden",null);

  const roles = (await env.DB.prepare(`SELECT id,name,created_at FROM roles ORDER BY name ASC`).all()).results || [];

  const hasIcon = await menusHasIcon(env);
  const iconCol = hasIcon ? ", icon" : "";
  const menus = (await env.DB.prepare(`
    SELECT id,code,label,path,parent_id,sort_order${iconCol},created_at
    FROM menus ORDER BY sort_order ASC, created_at ASC
  `).all()).results || [];

  const role_menus = (await env.DB.prepare(`SELECT role_id,menu_id,created_at FROM role_menus ORDER BY role_id, menu_id`).all()).results || [];

  return json(200,"ok",{ roles, menus, role_menus });
}
