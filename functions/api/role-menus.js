// App/functions/api/role-menus.js
import { json, readJson, hasRole, audit } from "../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }
function canRead(sess){ return hasRole(sess.roles, ["super_admin","admin"]); }
function onlySA(sess){ return hasRole(sess.roles, ["super_admin"]); }

export async function onRequestGet({ env, data }){
  const sess = data.session;
  if (!canRead(sess)) return json(403,"forbidden",null);

  const roles = await env.DB.prepare("SELECT id,name FROM roles ORDER BY name ASC").all();
  const menus = await env.DB.prepare("SELECT id,code,label,path,sort_order,icon,parent_id FROM menus ORDER BY sort_order ASC").all();
  const role_menus = await env.DB.prepare("SELECT role_id,menu_id,created_at FROM role_menus ORDER BY role_id,menu_id").all();

  return json(200,"ok",{
    roles: roles.results||[],
    menus: menus.results||[],
    role_menus: role_menus.results||[]
  });
}

// POST /api/role-menus
// { role_id, menu_ids:[...] }
export async function onRequestPost({ env, data, request }){
  const sess = data.session;
  if (!onlySA(sess)) return json(403,"forbidden",null);

  const b = await readJson(request);
  const role_id = String(b?.role_id||"").trim();
  const menu_ids = Array.isArray(b?.menu_ids) ? b.menu_ids.map(x=>String(x).trim()).filter(Boolean) : [];
  if (!role_id) return json(400,"invalid_input",{message:"role_id required"});

  await env.DB.prepare("DELETE FROM role_menus WHERE role_id=?").bind(role_id).run();
  const now = nowSec();
  for (const mid of menu_ids){
    await env.DB.prepare("INSERT INTO role_menus (role_id,menu_id,created_at) VALUES (?,?,?)")
      .bind(role_id, mid, now).run();
  }

  await audit(env,{ actor_user_id:sess.uid, action:"role_menus.set", target_type:"role", target_id:role_id, meta:{ count: menu_ids.length }});
  return json(200,"ok",{ updated:true });
}
