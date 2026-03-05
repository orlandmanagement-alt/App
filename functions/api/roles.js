// App/functions/api/roles.js
// /api/roles
// GET  : list roles (super_admin/admin/staff)
// POST : create role (super_admin only)
// PUT  : rename role (super_admin only)
// DELETE: delete role (super_admin only, only if unused)

import { json, readJson, hasRole } from "../_lib.js";

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function canRead(sess) {
  return hasRole(sess.roles, ["super_admin", "admin", "staff"]);
}
function onlySuperAdmin(sess) {
  return hasRole(sess.roles, ["super_admin"]);
}

function cleanRoleName(s) {
  // role name: letters, numbers, underscore only
  const t = String(s || "").trim();
  if (!t) return "";
  if (!/^[a-zA-Z0-9_]{2,40}$/.test(t)) return "";
  return t;
}

export async function onRequestGet({ env, data }) {
  const sess = data.session;
  if (!canRead(sess)) return json(403, "forbidden", null);

  const r = await env.DB.prepare("SELECT id,name,created_at FROM roles ORDER BY name ASC").all();
  return json(200, "ok", { roles: r.results || [] });
}

export async function onRequestPost({ env, data, request }) {
  const sess = data.session;
  if (!onlySuperAdmin(sess)) return json(403, "forbidden", null);

  const b = await readJson(request);
  const name = cleanRoleName(b?.name);
  if (!name) return json(400, "invalid_input", { message: "invalid_role_name" });

  const exists = await env.DB.prepare("SELECT id FROM roles WHERE name=? LIMIT 1").bind(name).first();
  if (exists) return json(409, "conflict", { message: "role_exists" });

  const id = crypto.randomUUID();
  await env.DB.prepare("INSERT INTO roles (id,name,created_at) VALUES (?,?,?)")
    .bind(id, name, nowSec())
    .run();

  return json(200, "ok", { created: true, id, name });
}

export async function onRequestPut({ env, data, request }) {
  const sess = data.session;
  if (!onlySuperAdmin(sess)) return json(403, "forbidden", null);

  const b = await readJson(request);
  const id = String(b?.id || "").trim();
  const name = cleanRoleName(b?.name);
  if (!id || !name) return json(400, "invalid_input", { message: "id_and_name_required" });

  const row = await env.DB.prepare("SELECT id,name FROM roles WHERE id=? LIMIT 1").bind(id).first();
  if (!row) return json(404, "invalid_input", { message: "role_not_found" });

  const exists = await env.DB.prepare("SELECT id FROM roles WHERE name=? LIMIT 1").bind(name).first();
  if (exists && exists.id !== id) return json(409, "conflict", { message: "role_name_taken" });

  await env.DB.prepare("UPDATE roles SET name=? WHERE id=?").bind(name, id).run();
  return json(200, "ok", { updated: true });
}

export async function onRequestDelete({ env, data, request }) {
  const sess = data.session;
  if (!onlySuperAdmin(sess)) return json(403, "forbidden", null);

  const url = new URL(request.url);
  const id = String(url.searchParams.get("id") || "").trim();
  if (!id) return json(400, "invalid_input", { message: "id_required" });

  // only delete if unused
  const used = await env.DB.prepare("SELECT 1 AS ok FROM user_roles WHERE role_id=? LIMIT 1").bind(id).first();
  if (used) return json(409, "conflict", { message: "role_in_use" });

  const usedMenu = await env.DB.prepare("SELECT 1 AS ok FROM role_menus WHERE role_id=? LIMIT 1").bind(id).first();
  if (usedMenu) return json(409, "conflict", { message: "role_has_menus" });

  await env.DB.prepare("DELETE FROM roles WHERE id=?").bind(id).run();
  return json(200, "ok", { deleted: true });
}
