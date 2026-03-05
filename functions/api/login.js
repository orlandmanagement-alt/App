import { json, readJson, cookie, pbkdf2Hash, timingSafeEqual, normEmail, getRolesForUser, createSession, requireEnv } from "../_lib.js";

export async function onRequestPost({ request, env }) {
  const miss = requireEnv(env, ["HASH_PEPPER"]);
  if (miss.length) return json(500, "server_error", { message: "missing_env", missing: miss });

  const body = await readJson(request);
  const email = normEmail(body?.email);
  const password = String(body?.password || "");

  if (!email.includes("@") || password.length < 6) return json(400, "invalid_input", null);

  const u = await env.DB.prepare(
    "SELECT id,display_name,status,password_hash,password_salt,password_iter FROM users WHERE email_norm=? LIMIT 1"
  ).bind(email).first();

  if (!u) return json(403, "user_belum_terdaftar", null);
  if (String(u.status) !== "active") return json(403, "forbidden", null);
  if (!u.password_hash || !u.password_salt) return json(403, "password_invalid", { message: "password_not_set" });

  const iter = Number(u.password_iter || env.PBKDF2_ITER || 100000);
  const calc = await pbkdf2Hash(password, u.password_salt, iter);
  if (!timingSafeEqual(calc, u.password_hash)) return json(403, "password_invalid", null);

  const roles = await getRolesForUser(env, u.id);

  // Dashboard ini untuk admin/staff dulu
  const allowed = roles.includes("super_admin") || roles.includes("admin") || roles.includes("staff");
  if (!allowed) return json(403, "forbidden", { message: "role_not_allowed_for_dashboard" });

  const sess = await createSession(env, u.id, roles);
  const res = json(200, "ok", { id: u.id, display_name: u.display_name, roles, exp: sess.exp });
  res.headers.append("set-cookie", cookie("sid", sess.sid, { maxAge: sess.ttl }));
  return res;
}

  async function incPasswordFail(env, ip_hash){
  const now = Math.floor(Date.now()/1000);
  const hf = Math.floor(now/3600)*3600;
  const id = new Date(hf*1000).toISOString().slice(0,13).replace(/[-T:]/g,""); // YYYYMMDDHH
  const day_key = new Date(hf*1000).toISOString().slice(0,10);

  await env.DB.prepare(`
    INSERT INTO hourly_metrics (id,day_key,hour_epoch,password_fail,created_at,updated_at)
    VALUES (?,?,?,?,?,?)
    ON CONFLICT(id) DO UPDATE SET
      password_fail = COALESCE(password_fail,0) + 1,
      updated_at = excluded.updated_at
  `).bind(id, day_key, hf, 1, now, now).run();

  const windowStart = Math.floor(now/300)*300;
  const actId = `password_fail:${windowStart}:${ip_hash}`;
  await env.DB.prepare(`
    INSERT INTO ip_activity (id,ip_hash,kind,cnt,window_start,updated_at)
    VALUES (?,?,?,?,?,?)
    ON CONFLICT(id) DO UPDATE SET
      cnt = cnt + 1,
      updated_at = excluded.updated_at
  `).bind(actId, ip_hash, "password_fail", 1, windowStart, now).run();
}
