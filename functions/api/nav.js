import { json, requireAuth, hasRole, menusHasIcon } from "../_lib.js";

export async function onRequestGet({ request, env }) {
  const a = await requireAuth(env, request);
  if(!a.ok) return a.res;

  // super_admin sees all menus, others see role_menus
  const iconCol = (await menusHasIcon(env)) ? ", m.icon AS icon" : "";

  let rows = [];
  if(hasRole(a.roles, ["super_admin"])){
    const r = await env.DB.prepare(
      `SELECT m.id,m.code,m.label,m.path,m.parent_id,m.sort_order${iconCol},m.created_at
       FROM menus m
       ORDER BY m.sort_order ASC, m.created_at ASC`
    ).all();
    rows = r.results || [];
  } else {
    const r = await env.DB.prepare(
      `SELECT DISTINCT m.id,m.code,m.label,m.path,m.parent_id,m.sort_order${iconCol},m.created_at
       FROM menus m
       JOIN role_menus rm ON rm.menu_id=m.id
       JOIN user_roles ur ON ur.role_id=rm.role_id
       WHERE ur.user_id=?
       ORDER BY m.sort_order ASC, m.created_at ASC`
    ).bind(a.uid).all();
    rows = r.results || [];
  }

  // Build tree by parent_id
  const map = new Map();
  rows.forEach(m=>map.set(m.id, { ...m, children: [] }));
  const roots = [];
  rows.forEach(m=>{
    const node = map.get(m.id);
    if(m.parent_id && map.has(m.parent_id)) map.get(m.parent_id).children.push(node);
    else roots.push(node);
  });

  return json(200, "ok", { tree: roots, menus: rows });
}
