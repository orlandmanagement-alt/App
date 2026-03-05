import { json, hasRole } from "../../_lib.js";

function sortMenus(arr){
  return arr.sort((a,b)=>{
    const sa=Number(a.sort_order||0), sb=Number(b.sort_order||0);
    if (sa!==sb) return sa-sb;
    return Number(a.created_at||0) - Number(b.created_at||0);
  });
}

export async function onRequestGet({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin", "admin"])) return json(403, "forbidden", null);

  const url = new URL(request.url);
  const role = String(url.searchParams.get("role") || "").trim();
  const user_id = String(url.searchParams.get("user_id") || "").trim();

  let roles = [];
  if (role) {
    roles = [role];
  } else if (user_id) {
    const rr = await env.DB.prepare(`
      SELECT r.name AS name
      FROM user_roles ur JOIN roles r ON r.id=ur.role_id
      WHERE ur.user_id=?
    `).bind(user_id).all();
    roles = (rr.results || []).map(x => x.name);
  } else {
    return json(400, "invalid_input", { message: "role or user_id required" });
  }

  // super_admin sees all
  if (roles.includes("super_admin")) {
    const r = await env.DB.prepare(`
      SELECT id,code,label,path,parent_id,sort_order,icon,created_at
      FROM menus ORDER BY sort_order ASC, created_at ASC
    `).all();
    return json(200, "ok", { roles, menus: r.results || [] });
  }

  const r = await env.DB.prepare(`
    SELECT DISTINCT m.id,m.code,m.label,m.path,m.parent_id,m.sort_order,m.icon,m.created_at
    FROM menus m
    JOIN role_menus rm ON rm.menu_id=m.id
    JOIN roles ro ON ro.id=rm.role_id
    WHERE ro.name IN (${roles.map(()=>"?").join(",")})
    ORDER BY m.sort_order ASC, m.created_at ASC
  `).bind(...roles).all();

  let menus = r.results || [];
  const have = new Set(menus.map(m=>m.id));
  const missingParents = Array.from(new Set(menus.map(m=>m.parent_id).filter(Boolean))).filter(pid=>!have.has(pid));
  if (missingParents.length){
    const p = await env.DB.prepare(`
      SELECT id,code,label,path,parent_id,sort_order,icon,created_at
      FROM menus
      WHERE id IN (${missingParents.map(()=>"?").join(",")})
    `).bind(...missingParents).all();
    for (const x of (p.results||[])) if(!have.has(x.id)) menus.push(x);
  }
  menus = sortMenus(menus);

  return json(200, "ok", { roles, menus });
}
