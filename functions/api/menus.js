import { json, readJson, hasRole, audit } from "../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }

export async function onRequestGet({ env, data }){
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin","admin"])) return json(403,"forbidden",null);

  const r = await env.DB.prepare(`
    SELECT id,code,label,path,parent_id,sort_order,icon,created_at
    FROM menus ORDER BY sort_order ASC, created_at ASC
  `).all();
  return json(200,"ok",{ menus: r.results||[] });
}

export async function onRequestPost({ env, data, request }){
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin"])) return json(403,"forbidden",null);

  const b = await readJson(request);
  const id = crypto.randomUUID();
  const code = String(b?.code||"").trim();
  const label = String(b?.label||"").trim();
  const path = String(b?.path||"").trim();
  const parent_id = b?.parent_id ? String(b.parent_id).trim() : null;
  const sort_order = Number(b?.sort_order ?? 50);
  const icon = b?.icon ? String(b.icon).trim() : null;

  if (!code || !label || !path) return json(400,"invalid_input",{message:"code/label/path required"});

  await env.DB.prepare(`
    INSERT INTO menus (id,code,label,path,parent_id,sort_order,icon,created_at)
    VALUES (?,?,?,?,?,?,?,?)
  `).bind(id, code, label, path, parent_id, sort_order, icon, nowSec()).run();

  await audit(env,{actor_user_id:sess.uid, action:"menus.create", target_type:"menu", target_id:id, meta:{code,path}});
  return json(200,"ok",{ created:true, id });
}

export async function onRequestPut({ env, data, request }){
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin"])) return json(403,"forbidden",null);

  const b = await readJson(request);
  const id = String(b?.id||"").trim();
  const code = String(b?.code||"").trim();
  const label = String(b?.label||"").trim();
  const path = String(b?.path||"").trim();
  const parent_id = b?.parent_id ? String(b.parent_id).trim() : null;
  const sort_order = Number(b?.sort_order ?? 50);
  const icon = b?.icon ? String(b.icon).trim() : null;

  if (!id || !code || !label || !path) return json(400,"invalid_input",{message:"id/code/label/path required"});

  await env.DB.prepare(`
    UPDATE menus SET code=?,label=?,path=?,parent_id=?,sort_order=?,icon=?
    WHERE id=?
  `).bind(code, label, path, parent_id, sort_order, icon, id).run();

  await audit(env,{actor_user_id:sess.uid, action:"menus.update", target_type:"menu", target_id:id, meta:{code,path}});
  return json(200,"ok",{ updated:true });
}

export async function onRequestDelete({ env, data, request }){
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin"])) return json(403,"forbidden",null);

  const url = new URL(request.url);
  const id = String(url.searchParams.get("id")||"").trim();
  if (!id) return json(400,"invalid_input",{message:"id required"});

  await env.DB.prepare(`DELETE FROM menus WHERE id=?`).bind(id).run();
  await audit(env,{actor_user_id:sess.uid, action:"menus.delete", target_type:"menu", target_id:id, meta:{}});
  return json(200,"ok",{ deleted:true });
}
