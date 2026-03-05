// App/functions/api/nav-tree.js
import { json } from "../_lib.js";

// Reuse /api/nav result, but build nested tree
function buildTree(menus) {
  const byId = new Map();
  for (const m of menus) byId.set(m.id, { ...m, children: [] });

  const roots = [];
  for (const m of byId.values()) {
    if (m.parent_id && byId.has(m.parent_id)) byId.get(m.parent_id).children.push(m);
    else roots.push(m);
  }

  // sort children
  function sortNode(n){
    n.children.sort((a,b)=>{
      const sa=Number(a.sort_order||0), sb=Number(b.sort_order||0);
      if (sa!==sb) return sa-sb;
      return Number(a.created_at||0) - Number(b.created_at||0);
    });
    n.children.forEach(sortNode);
  }
  roots.sort((a,b)=>{
    const sa=Number(a.sort_order||0), sb=Number(b.sort_order||0);
    if (sa!==sb) return sa-sb;
    return Number(a.created_at||0) - Number(b.created_at||0);
  });
  roots.forEach(sortNode);

  return roots;
}

export async function onRequestGet({ env, data }) {
  // call same logic as /api/nav by re-querying (simple & reliable)
  const roles = data.session.roles || [];

  let menus = [];
  if (roles.includes("super_admin")) {
    const r = await env.DB.prepare(`
      SELECT id,code,label,path,parent_id,sort_order,icon,created_at
      FROM menus
      ORDER BY sort_order ASC, created_at ASC
    `).all();
    menus = r.results || [];
  } else {
    const r = await env.DB.prepare(`
      SELECT DISTINCT
        m.id,m.code,m.label,m.path,m.parent_id,m.sort_order,m.icon,m.created_at
      FROM menus m
      JOIN role_menus rm ON rm.menu_id = m.id
      JOIN roles ro ON ro.id = rm.role_id
      WHERE ro.name IN (${roles.map(() => "?").join(",")})
      ORDER BY m.sort_order ASC, m.created_at ASC
    `).bind(...roles).all();
    menus = r.results || [];
  }

  // ensure parents included
  const have = new Set(menus.map(m=>m.id));
  const missingParents = Array.from(new Set(menus.map(m=>m.parent_id).filter(Boolean))).filter(pid=>!have.has(pid));
  if (missingParents.length) {
    const p = await env.DB.prepare(`
      SELECT id,code,label,path,parent_id,sort_order,icon,created_at
      FROM menus
      WHERE id IN (${missingParents.map(()=>"?").join(",")})
    `).bind(...missingParents).all();
    for (const x of (p.results||[])) if (!have.has(x.id)) menus.push(x);
  }

  return json(200, "ok", { tree: buildTree(menus) });
}
