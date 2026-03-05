import { json, readJson, hasRole, audit } from "../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }

export async function onRequestPost({ env, data, request }){
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin"])) return json(403,"forbidden",null);

  const b = await readJson(request);
  const role_id = String(b?.role_id||"").trim();
  const menu_ids = Array.isArray(b?.menu_ids) ? b.menu_ids.map(x=>String(x).trim()).filter(Boolean) : [];
  if (!role_id) return json(400,"invalid_input",{message:"role_id required"});

  await env.DB.prepare(`DELETE FROM role_menus WHERE role_id=?`).bind(role_id).run();
  for (const mid of menu_ids){
    await env.DB.prepare(`INSERT INTO role_menus (role_id,menu_id,created_at) VALUES (?,?,?)`)
      .bind(role_id, mid, nowSec()).run();
  }

  await audit(env,{actor_user_id:sess.uid, action:"rbac.role_menus.set", target_type:"role", target_id:role_id, meta:{count:menu_ids.length}});
  return json(200,"ok",{ updated:true });
}
