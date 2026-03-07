import { json, readJson, requireAuth, hasRole, menusHasIcon, nowSec } from "../../_lib.js";

export async function onRequestGet({ request, env }){
  const a = await requireAuth(env, request); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin","admin","staff"])) return json(403,"forbidden",null);

  const hasIcon = await menusHasIcon(env);
  const iconCol = hasIcon ? ", icon" : "";

  const r = await env.DB.prepare(`
    SELECT id,code,label,path,parent_id,sort_order${iconCol},created_at
    FROM menus
    ORDER BY sort_order ASC, created_at ASC
  `).all();

  return json(200,"ok",{ menus: r.results || [] });
}

export async function onRequestPost({ request, env }){
  const a = await requireAuth(env, request); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(403,"forbidden",null);

  const b = await readJson(request);
  const id = (b?.id && String(b.id).trim()) ? String(b.id).trim() : crypto.randomUUID();
  const code = String(b?.code||"").trim();
  const label = String(b?.label||"").trim();
  const path = String(b?.path||"").trim();
  const parent_id = b?.parent_id ? String(b.parent_id).trim() : null;
  const sort_order = Number(b?.sort_order ?? 50);
  const icon = b?.icon ? String(b.icon).trim() : null;

  if(!code || !label || !path) return json(400,"invalid_input",null);

  const now = nowSec();
  const hasIcon = await menusHasIcon(env);

  if(hasIcon){
    await env.DB.prepare(`
      INSERT INTO menus (id,code,label,path,parent_id,sort_order,icon,created_at)
      VALUES (?,?,?,?,?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET
        code=excluded.code,
        label=excluded.label,
        path=excluded.path,
        parent_id=excluded.parent_id,
        sort_order=excluded.sort_order,
        icon=excluded.icon
    `).bind(id, code, label, path, parent_id, sort_order, icon, now).run();
  }else{
    await env.DB.prepare(`
      INSERT INTO menus (id,code,label,path,parent_id,sort_order,created_at)
      VALUES (?,?,?,?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET
        code=excluded.code,
        label=excluded.label,
        path=excluded.path,
        parent_id=excluded.parent_id,
        sort_order=excluded.sort_order
    `).bind(id, code, label, path, parent_id, sort_order, now).run();
  }

  return json(200,"ok",{ upserted:true, id });
}

export async function onRequestDelete({ request, env }){
  const a = await requireAuth(env, request); if(!a.ok) return a.res;
  if(!hasRole(a.roles, ["super_admin"])) return json(403,"forbidden",null);

  const url = new URL(request.url);
  const id = String(url.searchParams.get("id")||"").trim();
  if(!id) return json(400,"invalid_input",null);

  await env.DB.prepare(`DELETE FROM menus WHERE id=?`).bind(id).run();
  return json(200,"ok",{ deleted:true });
}
