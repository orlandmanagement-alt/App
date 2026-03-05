// App/functions/api/roles.js
import { json, readJson, hasRole, audit } from "../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }
function canRead(sess){ return hasRole(sess.roles, ["super_admin","admin"]); }
function onlySA(sess){ return hasRole(sess.roles, ["super_admin"]); }

export async function onRequestGet({ env, data }){
  const sess = data.session;
  if (!canRead(sess)) return json(403,"forbidden",null);

  const r = await env.DB.prepare("SELECT id,name,created_at FROM roles ORDER BY name ASC").all();
  return json(200,"ok",{ roles: r.results||[] });
}

export async function onRequestPost({ env, data, request }){
  const sess = data.session;
  if (!onlySA(sess)) return json(403,"forbidden",null);

  const b = await readJson(request);
  const name = String(b?.name||"").trim();
  if (!name) return json(400,"invalid_input",{message:"name required"});

  const id = crypto.randomUUID();
  await env.DB.prepare("INSERT INTO roles (id,name,created_at) VALUES (?,?,?)")
    .bind(id, name, nowSec()).run();

  await audit(env,{ actor_user_id:sess.uid, action:"role.create", target_type:"role", target_id:id, meta:{ name } });
  return json(200,"ok",{ created:true, id });
}

export async function onRequestPut({ env, data, request }){
  const sess = data.session;
  if (!onlySA(sess)) return json(403,"forbidden",null);

  const b = await readJson(request);
  const id = String(b?.id||"").trim();
  const name = String(b?.name||"").trim();
  if (!id || !name) return json(400,"invalid_input",{message:"id & name required"});

  await env.DB.prepare("UPDATE roles SET name=? WHERE id=?").bind(name, id).run();
  await audit(env,{ actor_user_id:sess.uid, action:"role.update", target_type:"role", target_id:id, meta:{ name } });
  return json(200,"ok",{ updated:true });
}

export async function onRequestDelete({ env, data, request }){
  const sess = data.session;
  if (!onlySA(sess)) return json(403,"forbidden",null);

  const url = new URL(request.url);
  const id = String(url.searchParams.get("id")||"").trim();
  if (!id) return json(400,"invalid_input",{message:"id required"});

  await env.DB.prepare("DELETE FROM role_menus WHERE role_id=?").bind(id).run();
  await env.DB.prepare("DELETE FROM user_roles WHERE role_id=?").bind(id).run();
  await env.DB.prepare("DELETE FROM roles WHERE id=?").bind(id).run();

  await audit(env,{ actor_user_id:sess.uid, action:"role.delete", target_type:"role", target_id:id, meta:{} });
  return json(200,"ok",{ deleted:true });
}
