import { json, readJson, requireAuth, hasRole, nowSec } from "../_lib.js";

export async function onRequestGet({ request, env }){
  const a = await requireAuth(env, request); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin","admin","staff"])) return json(403,"forbidden",null);

  const r = await env.DB.prepare(`SELECT id,name,created_at FROM roles ORDER BY name ASC`).all();
  return json(200,"ok",{ roles: r.results || [] });
}

export async function onRequestPost({ request, env }){
  const a = await requireAuth(env, request); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(403,"forbidden",null);

  const b = await readJson(request);
  const name = String(b?.name||"").trim();
  if(!name) return json(400,"invalid_input",null);

  const id = crypto.randomUUID();
  await env.DB.prepare(`INSERT INTO roles (id,name,created_at) VALUES (?,?,?)`).bind(id, name, nowSec()).run();
  return json(200,"ok",{ created:true, id });
}

export async function onRequestPut({ request, env }){
  const a = await requireAuth(env, request); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(403,"forbidden",null);

  const b = await readJson(request);
  const id = String(b?.id||"").trim();
  const name = String(b?.name||"").trim();
  if(!id || !name) return json(400,"invalid_input",null);

  await env.DB.prepare(`UPDATE roles SET name=? WHERE id=?`).bind(name, id).run();
  return json(200,"ok",{ updated:true });
}

export async function onRequestDelete({ request, env }){
  const a = await requireAuth(env, request); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(403,"forbidden",null);

  const url = new URL(request.url);
  const id = String(url.searchParams.get("id")||"").trim();
  if(!id) return json(400,"invalid_input",null);

  await env.DB.prepare(`DELETE FROM roles WHERE id=?`).bind(id).run();
  return json(200,"ok",{ deleted:true });
}
