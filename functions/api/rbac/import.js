import { json, readJson, hasRole, audit } from "../../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }

export async function onRequestPost({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin"])) return json(403, "forbidden", null);

  const b = await readJson(request);
  const mode = String(b?.mode||"merge").trim();
  const roles = Array.isArray(b?.roles) ? b.roles : [];
  const menus = Array.isArray(b?.menus) ? b.menus : [];
  const role_menus = Array.isArray(b?.role_menus) ? b.role_menus : [];

  if (!["merge","replace"].includes(mode)) return json(400,"invalid_input",{message:"mode invalid"});

  const now = nowSec();

  if (mode === "replace") {
    await env.DB.prepare("DELETE FROM role_menus").run();
    await env.DB.prepare("DELETE FROM menus").run();
    await env.DB.prepare("DELETE FROM roles").run();
  }

  // upsert roles
  for (const r of roles) {
    if (!r?.id || !r?.name) continue;
    await env.DB.prepare(`
      INSERT INTO roles (id,name,created_at)
      VALUES (?,?,?)
      ON CONFLICT(id) DO UPDATE SET name=excluded.name
    `).bind(String(r.id), String(r.name), Number(r.created_at||now)).run();
  }

  // upsert menus
  for (const m of menus) {
    if (!m?.id || !m?.code || !m?.label || !m?.path) continue;
    await env.DB.prepare(`
      INSERT INTO menus (id,code,label,path,parent_id,sort_order,icon,created_at)
      VALUES (?,?,?,?,?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET
        code=excluded.code,label=excluded.label,path=excluded.path,
        parent_id=excluded.parent_id,sort_order=excluded.sort_order,icon=excluded.icon
    `).bind(
      String(m.id), String(m.code), String(m.label), String(m.path),
      m.parent_id ? String(m.parent_id) : null,
      Number(m.sort_order||50),
      m.icon ? String(m.icon) : null,
      Number(m.created_at||now)
    ).run();
  }

  if (mode === "merge") {
    // clear existing only for provided roles (optional). We keep simple: just insert ignore duplicates.
  } else {
    // already deleted above
  }

  // insert role_menus (ignore duplicates)
  for (const rm of role_menus) {
    if (!rm?.role_id || !rm?.menu_id) continue;
    await env.DB.prepare(`
      INSERT OR IGNORE INTO role_menus (role_id,menu_id,created_at)
      VALUES (?,?,?)
    `).bind(String(rm.role_id), String(rm.menu_id), Number(rm.created_at||now)).run();
  }

  await audit(env,{ actor_user_id:sess.uid, action:"rbac.import", target_type:"system", target_id:"rbac", meta:{ mode, roles:roles.length, menus:menus.length, role_menus:role_menus.length }});

  return json(200,"ok",{ imported:true, mode });
}
