import { json, requireAuth, hasRole, menusHasIcon, nowSec } from "../../_lib.js";

export async function onRequestPost({ request, env }){
  const a = await requireAuth(env, request); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(403,"forbidden",null);

  const now = nowSec();
  const hasIcon = await menusHasIcon(env);

  const seeds = [
    {id:"menu_dashboard", code:"dashboard", label:"Dashboard", path:"/dashboard", sort_order:10, icon:"fa-solid fa-gauge"},
    {id:"menu_users", code:"users", label:"Users", path:"/users", sort_order:20, icon:"fa-solid fa-users"},
    {id:"menu_roles", code:"roles", label:"Roles", path:"/roles", sort_order:25, icon:"fa-solid fa-user-tag"},
    {id:"menu_menus", code:"menus", label:"Menus", path:"/menus", sort_order:30, icon:"fa-solid fa-list"},
    {id:"menu_rbac", code:"rbac", label:"RBAC Manager", path:"/rbac", sort_order:60, icon:"fa-solid fa-user-shield"},
    {id:"menu_security", code:"security", label:"Security Dashboard", path:"/security", sort_order:70, icon:"fa-solid fa-shield-halved"},
    {id:"menu_ipblocks", code:"ipblocks", label:"IP Blocks", path:"/ipblocks", sort_order:83, icon:"fa-solid fa-ban"},
    {id:"menu_audit", code:"audit", label:"Audit Logs", path:"/audit", sort_order:90, icon:"fa-solid fa-clipboard-list"},
    {id:"menu_ops", code:"ops", label:"Ops Dashboard", path:"/ops", sort_order:95, icon:"fa-solid fa-screwdriver-wrench"},
  ];

  for(const m of seeds){
    if(hasIcon){
      await env.DB.prepare(`
        INSERT INTO menus (id,code,label,path,parent_id,sort_order,icon,created_at)
        VALUES (?,?,?,?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET
          code=excluded.code,label=excluded.label,path=excluded.path,parent_id=excluded.parent_id,sort_order=excluded.sort_order,icon=excluded.icon
      `).bind(m.id, m.code, m.label, m.path, null, m.sort_order, m.icon, now).run();
    }else{
      await env.DB.prepare(`
        INSERT INTO menus (id,code,label,path,parent_id,sort_order,created_at)
        VALUES (?,?,?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET
          code=excluded.code,label=excluded.label,path=excluded.path,parent_id=excluded.parent_id,sort_order=excluded.sort_order
      `).bind(m.id, m.code, m.label, m.path, null, m.sort_order, now).run();
    }
  }

  return json(200,"ok",{ seeded:true, count: seeds.length });
}
