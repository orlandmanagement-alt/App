import { json, readJson, sha256Base64, randomB64, pbkdf2Hash, normEmail } from "../../_lib.js";

export async function onRequestPost({ request, env }) {
  const body = await readJson(request);
  const email = normEmail(body?.email);
  const password = String(body?.password || "");
  const display_name = String(body?.display_name || "Super Admin").trim();

  if (!email.includes("@") || password.length < 10) {
    return json(400, "invalid_input", { message: "email invalid / password min 10" });
  }

  const exists = await env.DB.prepare(
    `SELECT 1 AS ok
     FROM users u
     JOIN user_roles ur ON ur.user_id=u.id
     JOIN roles r ON r.id=ur.role_id
     WHERE r.name='super_admin' AND u.status='active'
     LIMIT 1`
  ).first();
  if (exists) return json(409, "conflict", { message: "super_admin already exists" });

  const used = await env.DB.prepare("SELECT id FROM users WHERE email_norm=? LIMIT 1").bind(email).first();
  if (used) return json(409, "conflict", { message: "email already used" });

  const now = Math.floor(Date.now() / 1000);

  // ensure role exists
  let role = await env.DB.prepare("SELECT id FROM roles WHERE name='super_admin' LIMIT 1").first();
  if (!role) {
    const rid = crypto.randomUUID();
    await env.DB.prepare("INSERT INTO roles (id,name,created_at) VALUES (?,?,?)")
      .bind(rid, "super_admin", now).run();
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
