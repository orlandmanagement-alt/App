// App/functions/api/login.js
import {
  json, readJson, cookie, pbkdf2Hash, timingSafeEqual, normEmail,
  getRolesForUser, createSession, rateLimitKV, audit, sha256Base64
} from "../_lib.js";

function nowSec() { return Math.floor(Date.now() / 1000); }
function getClientIp(req) {
  return (
    req.headers.get("cf-connecting-ip") ||
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    "0.0.0.0"
  );
}
async function ipHash(env, ip) { return await sha256Base64(`${ip}|${env.HASH_PEPPER}`); }

function ipPrefix(ip) {
  if (!ip) return "unknown";
  if (ip.includes(".")) {
    const p = ip.split(".");
    if (p.length === 4) return `${p[0]}.${p[1]}.${p[2]}.0/24`;
  }
  if (ip.includes(":")) {
    const parts = ip.split(":").filter(Boolean);
    return parts.slice(0, 4).join(":") + "::/64";
  }
  return "unknown";
}
async function uaHash(env, ua) { return await sha256Base64(`${String(ua||"")}|${env.HASH_PEPPER}`); }
async function ipPrefixHash(env, ip) { return await sha256Base64(`${ipPrefix(ip)}|${env.HASH_PEPPER}`); }

// hourly_metrics helpers (schema baru)
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

async function maybeAutoBlockIp(env, ip_hash){
  if (!env.KV) return;

  const thresh = Number(env.AUTO_BLOCK_PASSWORD_FAIL_THRESHOLD || 25);
  const windowSec = Number(env.AUTO_BLOCK_WINDOW_SEC || 300);
  const ttl = Math.min(86400, Math.max(600, Number(env.AUTO_BLOCK_TTL_SEC || 3600)));

  const now = nowSec();
  const since = now - windowSec;

  const r = await env.DB.prepare(`
    SELECT SUM(cnt) AS total
    FROM ip_activity
    WHERE kind='password_fail' AND ip_hash=? AND window_start >= ?
  `).bind(ip_hash, since).first();

  const total = Number(r?.total || 0);
  if (total < thresh) return;

  const exists = await env.KV.get(`ipblock:${ip_hash}`);
  if (exists) return;

  const reason = `auto_block_password_fail_${total}_in_${windowSec}s`;
  await env.KV.put(`ipblock:${ip_hash}`, reason, { expirationTtl: ttl });

  const id = crypto.randomUUID();
  await env.DB.prepare(`
    INSERT INTO ip_blocks (id,ip_hash,reason,expires_at,revoked_at,created_at,created_by_user_id)
    VALUES (?,?,?,?,NULL,?,NULL)
  `).bind(id, ip_hash, reason, now + ttl, now).run();
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
    await maybeAutoBlockIp(env, ipH);
    await audit(env, { actor_user_id: null, action: "auth.login.fail.no_user", target_type: "email_norm", target_id: email, meta: {} });
    return json(403, "user_belum_terdaftar", null);
  }

  if (String(u.status) !== "active") {
    await audit(env, { actor_user_id: u.id, action: "auth.login.fail.disabled", target_type: "user", target_id: u.id, meta: {} });
    return json(403, "forbidden", null);
  }

  if (!u.password_hash || !u.password_salt) {
    await incPasswordFail(env, ipH);
    await maybeAutoBlockIp(env, ipH);
    await audit(env, { actor_user_id: u.id, action: "auth.login.fail.password_not_set", target_type: "user", target_id: u.id, meta: {} });
    return json(403, "password_invalid", { message: "password_not_set" });
  }

  const iter = Number(u.password_iter || env.PBKDF2_ITER || 100000);
  const calc = await pbkdf2Hash(password, u.password_salt, iter);

  if (!timingSafeEqual(calc, u.password_hash)) {
    await incPasswordFail(env, ipH);
    await maybeAutoBlockIp(env, ipH);
    await audit(env, { actor_user_id: u.id, action: "auth.login.fail.bad_password", target_type: "user", target_id: u.id, meta: {} });
    return json(403, "password_invalid", null);
  }

  const roles = await getRolesForUser(env, u.id);
  const allowed = roles.includes("super_admin") || roles.includes("admin") || roles.includes("staff");
  if (!allowed) {
    await audit(env, { actor_user_id: u.id, action: "auth.login.fail.role_not_allowed", target_type: "user", target_id: u.id, meta: { roles } });
    return json(403, "forbidden", { message: "role_not_allowed_for_dashboard" });
  }

  const ua = request.headers.get("user-agent") || "";
  const ua_h = await uaHash(env, ua);
  const ip_pref_h = await ipPrefixHash(env, ip);

  // update last ip (best effort)
  try {
    const now = nowSec();
    await env.DB.prepare(
      "UPDATE users SET last_ip_hash=?, last_login_at=?, updated_at=? WHERE id=?"
    ).bind(ipH, now, now, u.id).run();
  } catch {}

  const sess = await createSession(env, u.id, roles, { ua_hash: ua_h, ip_prefix_hash: ip_pref_h });

  await audit(env, { actor_user_id: u.id, action: "auth.login.ok", target_type: "session", target_id: sess.sid, meta: { roles } });

  const res = json(200, "ok", { id: u.id, display_name: u.display_name, roles, exp: sess.exp });
  res.headers.append("set-cookie", cookie("sid", sess.sid, { maxAge: sess.ttl }));
  return res;
}
