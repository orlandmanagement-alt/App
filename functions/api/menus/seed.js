import { json, hasRole, audit } from "../../../_lib.js";
function nowSec(){ return Math.floor(Date.now()/1000); }

const DEFAULT_MENUS = [
  { id:"menu_dashboard", code:"dashboard", label:"Dashboard", path:"/dashboard", sort_order:10, icon:"fa-solid fa-gauge" },
  { id:"menu_users", code:"users", label:"Users", path:"/users", sort_order:20, icon:"fa-solid fa-users" },
  { id:"menu_roles", code:"roles", label:"Roles", path:"/roles", sort_order:25, icon:"fa-solid fa-id-badge" },
  { id:"menu_menus", code:"menus", label:"Menus", path:"/menus", sort_order:26, icon:"fa-solid fa-sitemap" },
  { id:"menu_rbac", code:"rbac", label:"RBAC", path:"/rbac", sort_order:30, icon:"fa-solid fa-user-shield" },
  { id:"menu_security", code:"security", label:"Security", path:"/security", sort_order:60, icon:"fa-solid fa-shield-halved" },
  { id:"menu_ipblocks", code:"ipblocks", label:"IP Blocks", path:"/ipblocks", sort_order:70, icon:"fa-solid fa-ban" },
  { id:"menu_audit", code:"audit", label:"Audit Logs", path:"/audit", sort_order:80, icon:"fa-solid fa-clipboard-list" },
  { id:"menu_ops", code:"ops", label:"Ops", path:"/ops", sort_order:90, icon:"fa-solid fa-screwdriver-wrench" },
];

export async function onRequestPost({ env, data }){
  const sess=data.session;
  if(!hasRole(sess.roles, ["super_admin"])) return json(403,"forbidden",null);
  const now=nowSec();
  let upserted=0;
  for (const m of DEFAULT_MENUS){
    await env.DB.prepare(`
      INSERT INTO menus (id,code,label,path,parent_id,sort_order,icon,created_at)
      VALUES (?,?,?,?,NULL,?,?,?)
      ON CONFLICT(id) DO UPDATE SET
        code=excluded.code,label=excluded.label,path=excluded.path,sort_order=excluded.sort_order,icon=excluded.icon
    `).bind(m.id,m.code,m.label,m.path,m.sort_order,m.icon,now).run();
    upserted++;
  }
  await audit(env,{actor_user_id:sess.uid, action:"menus.seed", target_type:"system", target_id:"menus", meta:{upserted}});
  return json(200,"ok",{ seeded:true, upserted });
}
