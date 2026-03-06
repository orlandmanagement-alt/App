import { json } from "../_lib.js";
function buildTree(menus) {
  const byId = new Map();
  for (const m of menus) byId.set(m.id, { ...m, children: [] });
  const roots = [];
  for (const m of byId.values()) {
    if (m.parent_id && byId.has(m.parent_id)) byId.get(m.parent_id).children.push(m);
    else roots.push(m);
  }
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
export async function onRequestGet({ env }) {
  const r = await env.DB.prepare(`SELECT id,code,label,path,parent_id,sort_order,icon,created_at FROM menus ORDER BY sort_order ASC, created_at ASC`).all();
  return json(200, "ok", { tree: buildTree(r.results||[]) });
}
