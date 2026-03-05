// App/functions/api/menus.js
// /api/menus
// GET    : list menus + role_menus (admin/staff read)
// POST   : upsert menu (super_admin only)
// DELETE : delete menu (super_admin only, only if not referenced)

import { json, readJson, hasRole } from "../_lib.js";

function nowSec() { return Math.floor(Date.now() / 1000); }
function canRead(sess){ return hasRole(sess.roles, ["super_admin","admin","staff"]); }
function onlySuperAdmin(sess){ return hasRole(sess.roles, ["super_admin"]); }

function cleanCode(s){
  const t = String(s||"").trim();
  if(!/^[a-zA-Z0-9_.-]{2,50}$/.test(t)) return "";
  return t;
}
function cleanPath(s){
  const t = String(s||"").trim();
  // allow /xxx or /xxx/yyy
  if(!/^\/[a-zA-Z0-9/_-]*$/.test(t)) return "";
  return t || "/";
}

export async function onRequestGet({ env, data }) {
  const sess = data.session;
  if(!canRead(sess)) return json(403, "forbidden", null);

  const menus = await env.DB.prepare(
    "SELECT id,code,label,path,parent_id,sort_order,created_at FROM menus ORDER BY sort_order ASC, created_at ASC"
  ).all();

  const role_menus = await env.DB.prepare(
    "SELECT role_id,menu_id,created_at FROM role_menus ORDER BY role_id, menu_id"
  ).all();

  return json(200, "ok", { menus: menus.results || [], role_menus: role_menus.results || [] });
}

// Upsert
export async function onRequestPost({ env, data, request }) {
  const sess = data.session;
  if(!onlySuperAdmin(sess)) return json(403, "forbidden", null);

  const b = await readJson(request);
  const id = (b?.id && String(b.id).trim()) ? String(b.id).trim() : crypto.randomUUID();
  const code = cleanCode(b?.code);
  const label = String(b?.label || "").trim();
  const path = cleanPath(b?.path);
  const parent_id = b?.parent_id ? String(b.parent_id).trim() : null;
  const sort_order = Number.isFinite(Number(b?.sort_order)) ? Number(b.sort_order) : 0;

  if(!code || !label || !path) return json(400, "invalid_input", { message:"code/label/path required" });

  // Parent must exist (if provided) and cannot be self
  if (parent_id) {
    if (parent_id === id) return json(400, "invalid_input", { message:"parent_id_cannot_self" });
    const p = await env.DB.prepare("SELECT id FROM menus WHERE id=? LIMIT 1").bind(parent_id).first();
    if (!p) return json(400, "invalid_input", { message:"parent_not_found" });
  }

  const now = nowSec();
  await env.DB.prepare(
    `INSERT INTO menus (id,code,label,path,parent_id,sort_order,created_at)
     VALUES (?,?,?,?,?,?,?)
     ON CONFLICT(id) DO UPDATE SET
       code=excluded.code,
       label=excluded.label,
       path=excluded.path,
       parent_id=excluded.parent_id,
       sort_order=excluded.sort_order`
  ).bind(id, code, label, path, parent_id, sort_order, now).run();

  return json(200, "ok", { upserted:true, id });
}

export async function onRequestDelete({ env, data, request }) {
  const sess = data.session;
  if(!onlySuperAdmin(sess)) return json(403, "forbidden", null);

  const url = new URL(request.url);
  const id = String(url.searchParams.get("id")||"").trim();
  if(!id) return json(400, "invalid_input", { message:"id_required" });

  // Prevent delete if children exist
  const child = await env.DB.prepare("SELECT 1 AS ok FROM menus WHERE parent_id=? LIMIT 1").bind(id).first();
  if(child) return json(409, "conflict", { message:"menu_has_children" });

  // Prevent delete if mapped to roles
  const mapped = await env.DB.prepare("SELECT 1 AS ok FROM role_menus WHERE menu_id=? LIMIT 1").bind(id).first();
  if(mapped) return json(409, "conflict", { message:"menu_in_use_by_role" });

  await env.DB.prepare("DELETE FROM menus WHERE id=?").bind(id).run();
  return json(200, "ok", { deleted:true });
}
