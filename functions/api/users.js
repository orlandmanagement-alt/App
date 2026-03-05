// App/functions/api/users.js
// Admin-only users (super_admin/admin/staff). Client/Tenant users will be separate later.
//
// Routes:
// GET    /api/users?q=&status=&role=&limit=&offset=
// POST   /api/users                 (super_admin/admin) create admin/staff user
// PUT    /api/users                 (super_admin/admin) update/disable/enable/set_roles/reset_password
// DELETE /api/users?id=...          (super_admin only) hard delete

import {
  json,
  readJson,
  normEmail,
  sha256Base64,
  randomB64,
  pbkdf2Hash,
  hasRole,
  getRolesForUser,
} from "../_lib.js";

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function canRead(session) {
  return hasRole(session.roles, ["super_admin", "admin", "staff"]);
}
function canWrite(session) {
  return hasRole(session.roles, ["super_admin", "admin"]);
}
function onlySuperAdmin(session) {
  return hasRole(session.roles, ["super_admin"]);
}

// Admin module only roles:
const ADMIN_ROLES = new Set(["super_admin", "admin", "staff"]);

async function ensureRole(env, roleName) {
  const now = nowSec();
  let role = await env.DB.prepare("SELECT id,name FROM roles WHERE name=? LIMIT 1")
    .bind(roleName)
    .first();
  if (!role) {
    const id = crypto.randomUUID();
    await env.DB.prepare("INSERT INTO roles (id,name,created_at) VALUES (?,?,?)")
      .bind(id, roleName, now)
      .run();
    role = { id, name: roleName };
  }
  return role;
}

async function setUserRoles(env, userId, roleNames) {
  const now = nowSec();
  const names = Array.from(
    new Set((roleNames || []).map((s) => String(s).trim()).filter(Boolean))
  );

  // Filter admin-only roles
  const filtered = names.filter((r) => ADMIN_ROLES.has(r));
  if (!filtered.length) throw new Error("roles_empty_or_not_allowed");

  const roleIds = [];
  for (const n of filtered) {
    const r = await ensureRole(env, n);
    roleIds.push(r.id);
  }

  await env.DB.prepare("DELETE FROM user_roles WHERE user_id=?").bind(userId).run();
  for (const rid of roleIds) {
    await env.DB.prepare("INSERT INTO user_roles (user_id,role_id,created_at) VALUES (?,?,?)")
      .bind(userId, rid, now)
      .run();
  }
}

async function userHasAnyAdminRole(env, userId) {
  const roles = await getRolesForUser(env, userId);
  return roles.some((r) => ADMIN_ROLES.has(r));
}

// --------------------
// GET /api/users
// --------------------
export async function onRequestGet({ env, data, request }) {
  const sess = data.session;
  if (!canRead(sess)) return json(403, "forbidden", null);

  const url = new URL(request.url);
  const q = String(url.searchParams.get("q") || "").trim().toLowerCase();
  const status = String(url.searchParams.get("status") || "").trim(); // active/disabled
  const role = String(url.searchParams.get("role") || "").trim(); // filter by role name (optional)
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit") || "50")));
  const offset = Math.max(0, Number(url.searchParams.get("offset") || "0"));

  // Base select
  let sql =
    "SELECT id,email_norm,display_name,status,created_at,updated_at,phone_e164,phone_verified,tenant_id FROM users";
  const wh = [];
  const binds = [];

  if (q) {
    wh.push("(email_norm LIKE ? OR display_name LIKE ?)");
    binds.push(`%${q}%`, `%${q}%`);
  }
  if (status) {
    wh.push("status=?");
    binds.push(status);
  }
  if (wh.length) sql += " WHERE " + wh.join(" AND ");
  sql += " ORDER BY updated_at DESC LIMIT ? OFFSET ?";
  binds.push(limit, offset);

  const r = await env.DB.prepare(sql).bind(...binds).all();
  const rows = r.results || [];

  // Attach roles and filter admin-only users
  const out = [];
  for (const u of rows) {
    const roles = await getRolesForUser(env, u.id);
    const adminRoles = roles.filter((x) => ADMIN_ROLES.has(x));

    // only return admin module users
    if (!adminRoles.length) continue;

    // optional role filter
    if (role && !adminRoles.includes(role)) continue;

    out.push({ ...u, roles: adminRoles });
  }

  return json(200, "ok", { users: out, limit, offset });
}

// --------------------
// POST /api/users  (create admin/staff)
// body: { email, display_name?, password, roles:["staff"] or role:"staff" }
// --------------------
export async function onRequestPost({ env, data, request }) {
  const sess = data.session;
  if (!canWrite(sess)) return json(403, "forbidden", null);
  if (!env.HASH_PEPPER) return json(500, "server_error", { message: "missing_HASH_PEPPER" });

  const b = await readJson(request);
  const email = normEmail(b?.email);
  const display_name = String(b?.display_name || "").trim();
  const password = String(b?.password || "");

  let roles = [];
  if (Array.isArray(b?.roles)) roles = b.roles;
  else if (b?.role) roles = [b.role];
  else roles = ["staff"];

  roles = roles.map((x) => String(x).trim()).filter(Boolean);

  // Admin module only
  roles = roles.filter((r) => ADMIN_ROLES.has(r));
  if (!roles.length) return json(400, "invalid_input", { message: "roles_not_allowed" });

  // Only super_admin can create admin/super_admin
  const wantsPriv = roles.some((r) => ["super_admin", "admin"].includes(r));
  if (wantsPriv && !onlySuperAdmin(sess)) {
    return json(403, "forbidden", { message: "only_super_admin_can_assign_privileged_roles" });
  }

  if (!email.includes("@")) return json(400, "invalid_input", { message: "email_invalid" });
  if (password.length < 10) return json(400, "invalid_input", { message: "password_min_10" });

  const exists = await env.DB.prepare("SELECT id FROM users WHERE email_norm=? LIMIT 1")
    .bind(email)
    .first();
  if (exists) return json(409, "conflict", { message: "email_exists" });

  const now = nowSec();
  const user_id = crypto.randomUUID();
  const email_hash = await sha256Base64(`${email}|${env.HASH_PEPPER}`);

  const salt = randomB64(16);
  const iterReq = Number(env.PBKDF2_ITER || 100000);
  const iter = Math.min(100000, Math.max(10000, iterReq));
  const hash = await pbkdf2Hash(password, salt, iter);

  await env.DB.prepare(
    `INSERT INTO users (
      id,email_norm,email_hash,display_name,status,created_at,updated_at,
      password_hash,password_salt,password_iter,password_algo,
      phone_verified,profile_completed
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`
  )
    .bind(
      user_id,
      email,
      email_hash,
      display_name || null,
      "active",
      now,
      now,
      hash,
      salt,
      iter,
      "pbkdf2_sha256",
      0,
      0
    )
    .run();

  await setUserRoles(env, user_id, roles);

  return json(200, "ok", { created: true, user_id });
}

// --------------------
// PUT /api/users
// actions:
// - update:        { user_id, display_name?, status? } (status active/disabled)
// - set_roles:     { user_id, roles:[...] }
// - reset_password:{ user_id, new_password }
// - disable:       { user_id }
// - enable:        { user_id }
// --------------------
export async function onRequestPut({ env, data, request }) {
  const sess = data.session;
  const b = await readJson(request);
  const action = String(b?.action || "").trim();
  const user_id = String(b?.user_id || "").trim();

  if (!action) return json(400, "invalid_input", { message: "action_required" });
  if (!user_id) return json(400, "invalid_input", { message: "user_id_required" });
  if (!canWrite(sess)) return json(403, "forbidden", null);

  // Ensure target is part of admin module
  const isAdminUser = await userHasAnyAdminRole(env, user_id);
  if (!isAdminUser) return json(403, "forbidden", { message: "target_not_admin_user" });

  const now = nowSec();

  if (action === "update") {
    const display_name = b?.display_name != null ? String(b.display_name).trim() : null;
    const status = b?.status != null ? String(b.status).trim() : null;
    if (status && !["active", "disabled"].includes(status)) {
      return json(400, "invalid_input", { message: "status_invalid" });
    }

    await env.DB.prepare(
      "UPDATE users SET display_name=COALESCE(?,display_name), status=COALESCE(?,status), updated_at=? WHERE id=?"
    )
      .bind(display_name, status, now, user_id)
      .run();

    return json(200, "ok", { updated: true });
  }

  if (action === "disable") {
    await env.DB.prepare("UPDATE users SET status='disabled', updated_at=? WHERE id=?")
      .bind(now, user_id)
      .run();
    return json(200, "ok", { disabled: true });
  }

  if (action === "enable") {
    await env.DB.prepare("UPDATE users SET status='active', updated_at=? WHERE id=?")
      .bind(now, user_id)
      .run();
    return json(200, "ok", { enabled: true });
  }

  if (action === "set_roles") {
    const roles = Array.isArray(b?.roles) ? b.roles.map((x) => String(x).trim()).filter(Boolean) : [];
    if (!roles.length) return json(400, "invalid_input", { message: "roles_required" });

    // Filter admin module roles
    const filtered = roles.filter((r) => ADMIN_ROLES.has(r));
    if (!filtered.length) return json(400, "invalid_input", { message: "roles_not_allowed" });

    // Only super_admin can assign admin/super_admin
    const wantsPriv = filtered.some((r) => ["super_admin", "admin"].includes(r));
    if (wantsPriv && !onlySuperAdmin(sess)) {
      return json(403, "forbidden", { message: "only_super_admin_can_assign_privileged_roles" });
    }

    await setUserRoles(env, user_id, filtered);
    return json(200, "ok", { updated: true });
  }

  if (action === "reset_password") {
    // Only super_admin can reset password
    if (!onlySuperAdmin(sess)) return json(403, "forbidden", null);
    if (!env.HASH_PEPPER) return json(500, "server_error", { message: "missing_HASH_PEPPER" });

    const new_password = String(b?.new_password || "");
    if (new_password.length < 10) return json(400, "invalid_input", { message: "password_min_10" });

    const salt = randomB64(16);
    const iterReq = Number(env.PBKDF2_ITER || 100000);
    const iter = Math.min(100000, Math.max(10000, iterReq));
    const hash = await pbkdf2Hash(new_password, salt, iter);

    await env.DB.prepare(
      "UPDATE users SET password_hash=?, password_salt=?, password_iter=?, password_algo=?, updated_at=? WHERE id=?"
    )
      .bind(hash, salt, iter, "pbkdf2_sha256", now, user_id)
      .run();

    return json(200, "ok", { reset: true });
  }

  return json(400, "invalid_input", { message: "unknown_action" });
}

// --------------------
// DELETE /api/users?id=...
// super_admin only, hard delete
// --------------------
export async function onRequestDelete({ env, data, request }) {
  const sess = data.session;
  if (!onlySuperAdmin(sess)) return json(403, "forbidden", null);

  const url = new URL(request.url);
  const id = String(url.searchParams.get("id") || "").trim();
  if (!id) return json(400, "invalid_input", { message: "id_required" });

  // Ensure target is admin-module user
  const isAdminUser = await userHasAnyAdminRole(env, id);
  if (!isAdminUser) return json(403, "forbidden", { message: "target_not_admin_user" });

  // Prevent deleting self accidentally
  if (id === sess.uid) return json(400, "invalid_input", { message: "cannot_delete_self" });

  // cascade should remove user_roles due FK (if FK enforced); still delete mapping first for safety
  await env.DB.prepare("DELETE FROM user_roles WHERE user_id=?").bind(id).run();
  await env.DB.prepare("DELETE FROM users WHERE id=?").bind(id).run();

  return json(200, "ok", { deleted: true });
}
