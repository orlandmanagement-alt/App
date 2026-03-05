import { json, readJson, cookie, pbkdf2Hash, timingSafeEqual, getRolesForUser, createSession } from "../_lib.js";

export async function onRequestPost({ request, env }) {
  const body = await readJson(request);
  const email = String(body?.email || "").trim().toLowerCase();
  const password = String(body?.password || "");

  if (!email.includes("@") || password.length < 6) return json(400, "invalid_input", null);

  const u = await env.DB.prepare(
    "SELECT id,display_name,status,password_hash,password_salt,password_iter FROM users WHERE email_norm=? LIMIT 1"
  ).bind(email).first();

  if (!u) return json(403, "user_belum_terdaftar", null);
  if (String(u.status) !== "active") return json(403, "forbidden", null);
  if (!u.password_hash || !u.password_salt) return json(403, "password_invalid", { message:"password_not_set" });

  const iter = Number(u.password_iter || env.PBKDF2_ITER || 210000);
  const calc = await pbkdf2Hash(password, u.password_salt, iter);
  if (!timingSafeEqual(calc, u.password_hash)) return json(403, "password_invalid", null);

  const roles = await getRolesForUser(env, u.id);
  // admin/staff only (kamu minta admin/staff dulu)
  if (!roles.includes("super_admin") && !roles.includes("admin") && !roles.includes("staff")) {
    return json(403, "forbidden", { message:"role_not_allowed_for_dashboard" });
  }

  const sess = await createSession(env, u.id, roles);
  const res = json(200, "ok", { id: u.id, display_name: u.display_name, roles, exp: sess.exp });
  res.headers.append("set-cookie", cookie("sid", sess.sid, { maxAge: sess.ttl }));
  return res;
}
