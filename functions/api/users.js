import { json, readJson, sha256Base64, randomB64, pbkdf2Hash, hasRole, getRolesForUser, normEmail, requireEnv } from "../_lib.js";

export async function onRequestGet({ env, data }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin", "admin", "staff"])) return json(403, "forbidden", null);

  const r = await env.DB.prepare(
    "SELECT id,email_norm,display_name,status,updated_at FROM users ORDER BY updated_at DESC LIMIT 100"
  ).all();

  const users = [];
  for (const u of (r.results || [])) {
    const roles = await getRolesForUser(env, u.id);
    users.push({ ...u, roles });
  }
  return json(200, "ok", { users });
}

export async function onRequestPost({ request, env, data }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin", "admin"])) return json(403, "forbidden", null);

  const miss = requireEnv(env, ["HASH_PEPPER"]);
  if (miss.length) return json(500, "server_error", { message: "missing_env", missing: miss });

  const body = await readJson(request);
  const email = normEmail(body?.email);
  const display_name = String(body?.display_name || "").trim();
  const roleName = String(body?.role || "").trim();
  const password = String(body?.password || "");

  if (!email.includes("@") || password.length < 10) return json(400, "invalid_input", { message: "email/password invalid" });
  if (!["admin", "staff", "client", "talent", "super_admin"].includes(roleName)) return json(400, "invalid_input", { message: "role invalid" });

  // only super_admin can create super_admin
  if (roleName === "super_admin" && !hasRole(sess.roles, ["super_admin"])) {
    return json(403, "forbidden", { message: "only super_admin can create super_admin" });
  }

  const used = await env.DB.prepare("SELECT id FROM users WHERE email_norm=? LIMIT 1").bind(email).first();
  if (used) return json(409, "conflict", { message: "email exists" });

  const now = Math.floor(Date.now() / 1000);

  // ensure role exists
  let role = await env.DB.prepare("SELECT id FROM roles WHERE name=? LIMIT 1").bind(roleName).first();
  if (!role) {
    const rid = crypto.randomUUID();
    await env.DB.prepare("INSERT INTO roles (id,name,created_at) VALUES (?,?,?)").bind(rid, roleName, now).run();
    role = { id: rid };
  }

  const user_id = crypto.randomUUID();
  const email_hash = await sha256Base64(`${email}|${env.HASH_PEPPER}`);
  const salt = randomB64(16);
  const iter = Number(env.PBKDF2_ITER || 210000);
  const hash = await pbkdf2Hash(password, salt, iter);

  await env.DB.prepare(
    `INSERT INTO users (
      id,email_norm,email_hash,display_name,status,created_at,updated_at,
      password_hash,password_salt,password_iter,password_algo
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?)`
  ).bind(
    user_id, email, email_hash, display_name, "active", now, now,
    hash, salt, iter, "pbkdf2_sha256"
  ).run();

  await env.DB.prepare("INSERT INTO user_roles (user_id,role_id,created_at) VALUES (?,?,?)")
    .bind(user_id, role.id, now).run();

  return json(200, "ok", { created: true, user_id });
}

export async function onRequestPut({ request, env, data }) {
  const sess = data.session;
  const body = await readJson(request);
  const action = String(body?.action || "").trim();

  if (action === "disable") {
    if (!hasRole(sess.roles, ["super_admin", "admin"])) return json(403, "forbidden", null);
    const user_id = String(body?.user_id || "").trim();
    if (!user_id) return json(400, "invalid_input", null);

    await env.DB.prepare("UPDATE users SET status='disabled', updated_at=? WHERE id=?")
      .bind(Math.floor(Date.now() / 1000), user_id).run();
    return json(200, "ok", { disabled: true });
  }

  if (action === "reset_password") {
    if (!hasRole(sess.roles, ["super_admin"])) return json(403, "forbidden", null);
    const user_id = String(body?.user_id || "").trim();
    const new_password = String(body?.new_password || "");
    if (!user_id || new_password.length < 10) return json(400, "invalid_input", null);

    const salt = randomB64(16);
    const iter = Number(env.PBKDF2_ITER || 210000);
    const hash = await pbkdf2Hash(new_password, salt, iter);

    await env.DB.prepare(
      "UPDATE users SET password_hash=?,password_salt=?,password_iter=?,password_algo=?,updated_at=? WHERE id=?"
    ).bind(hash, salt, iter, "pbkdf2_sha256", Math.floor(Date.now() / 1000), user_id).run();

    return json(200, "ok", { reset: true });
  }

  if (action === "reset_request") {
    const email = normEmail(body?.email);
    return json(200, "ok", { received: true, email });
  }

  return json(400, "invalid_input", { message: "unknown_action" });
}
