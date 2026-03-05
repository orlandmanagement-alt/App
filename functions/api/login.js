import {
  json, readJson, cookie, pbkdf2Hash, timingSafeEqual, normEmail,
  getRolesForUser, createSession, rateLimitKV, audit, sha256Base64
} from "../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }
function getClientIp(req){
  return req.headers.get("cf-connecting-ip")
    || req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    || "0.0.0.0";
}
async function ipHash(env, ip){
  return await sha256Base64(`${ip}|${env.HASH_PEPPER}`);
}

// hourly_metrics schema: id(YYYYMMDDHH), day_key, hour_epoch
function hourFloor(sec){ return Math.floor(sec/3600)*3600; }
function dayKey(sec){
  const d = new Date(sec*1000);
  const y=d.getUTCFullYear(), m=String(d.getUTCMonth()+1).padStart(2,"0"), dd=String(d.getUTCDate()).padStart(2,"0");
  return `${y}-${m}-${dd}`;
}
function hourId(sec){
  const d = new Date(sec*1000);
  const y=d.getUTCFullYear(), m=String(d.getUTCMonth()+1).padStart(2,"0"), dd=String(d.getUTCDate()).padStart(2,"0"), hh=String(d.getUTCHours()).padStart(2,"0");
  return `${y}${m}${dd}${hh}`;
}

async function incPasswordFail(env, ip_hash){
  const now = nowSec();
  const hf = hourFloor(now);
  const id = hourId(hf);
  const dk = dayKey(hf);

  await env.DB.prepare(`
    INSERT INTO hourly_metrics (id,day_key,hour_epoch,password_fail,created_at,updated_at)
    VALUES (?,?,?,?,?,?)
    ON CONFLICT(id) DO UPDATE SET
      password_fail = COALESCE(password_fail,0) + 1,
      updated_at = excluded.updated_at
  `).bind(id, dk, hf, 1, now, now).run();

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

export async function onRequestPost({ request, env }) {
  if (!env.DB) return json(500, "server_error", { message: "missing_binding_DB" });
  if (!env.KV) return json(500, "server_error", { message: "missing_binding_KV" });
  if (!env.HASH_PEPPER) return json(500, "server_error", { message: "missing_HASH_PEPPER" });

  const body = await readJson(request);
  const email = normEmail(body?.email);
  const password = String(body?.password || "");

  if (!email.includes("@") || password.length < 6) return json(400, "invalid_input", null);

  const ip = getClientIp(request);
  const ipH = await ipHash(env, ip);

  // Rate limit: 10 tries / 60 sec per ip+email hash
  const emailKey = await sha256Base64(`${email}|${env.HASH_PEPPER}`);
  const rl = await rateLimitKV(env, `rl:login:${ipH}:${emailKey}`, 10, 60);
  if (!rl.ok) {
    await audit(env, { actor_user_id: null, action: "auth.login.rate_limited", target_type: "email_hash", target_id: emailKey, meta: { n: rl.n } });
    return json(429, "rate_limited", null);
  }

  const u = await env.DB.prepare(
    "SELECT id,display_name,status,password_hash,password_salt,password_iter FROM users WHERE email_norm=? LIMIT 1"
  ).bind(email).first();

  if (!u) {
    await incPasswordFail(env, ipH);
    await audit(env, { actor_user_id: null, action: "auth.login.fail.no_user", target_type: "email_norm", target_id: email, meta: {} });
    return json(403, "user_belum_terdaftar", null);
  }
  if (String(u.status) !== "active") {
    await audit(env, { actor_user_id: u.id, action: "auth.login.fail.disabled", target_type: "user", target_id: u.id, meta: {} });
    return json(403, "forbidden", null);
  }
  if (!u.password_hash || !u.password_salt) {
    await incPasswordFail(env, ipH);
    await audit(env, { actor_user_id: u.id, action: "auth.login.fail.password_not_set", target_type: "user", target_id: u.id, meta: {} });
    return json(403, "password_invalid", { message: "password_not_set" });
  }

  const iter = Number(u.password_iter || env.PBKDF2_ITER || 100000);
  const calc = await pbkdf2Hash(password, u.password_salt, iter);
  if (!timingSafeEqual(calc, u.password_hash)) {
    await incPasswordFail(env, ipH);
    await audit(env, { actor_user_id: u.id, action: "auth.login.fail.bad_password", target_type: "user", target_id: u.id, meta: {} });
    return json(403, "password_invalid", null);
  }

  const roles = await getRolesForUser(env, u.id);

  // dashboard only: super_admin/admin/staff
  const allowed = roles.includes("super_admin") || roles.includes("admin") || roles.includes("staff");
  if (!allowed) {
    await audit(env, { actor_user_id: u.id, action: "auth.login.fail.role_not_allowed", target_type: "user", target_id: u.id, meta: { roles } });
    return json(403, "forbidden", { message: "role_not_allowed_for_dashboard" });
  }

  const sess = await createSession(env, u.id, roles);
  await audit(env, { actor_user_id: u.id, action: "auth.login.ok", target_type: "session", target_id: sess.sid, meta: { roles } });

  const res = json(200, "ok", { id: u.id, display_name: u.display_name, roles, exp: sess.exp });
  res.headers.append("set-cookie", cookie("sid", sess.sid, { maxAge: sess.ttl }));
  return res;
}
