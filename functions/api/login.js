import {
  json, readJson, cookie, pbkdf2Hash, timingSafeEqual, normEmail,
  getRolesForUser, createSession, rateLimitKV, audit, sha256Base64
} from "../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }
function getClientIp(req){
  return req.headers.get("cf-connecting-ip") || req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "0.0.0.0";
}
function ipPrefix(ip){
  if (!ip) return "unknown";
  if (ip.includes(".")) { const p=ip.split("."); if (p.length===4) return `${p[0]}.${p[1]}.${p[2]}.0/24`; }
  if (ip.includes(":")) { const parts=ip.split(":").filter(Boolean); return parts.slice(0,4).join(":")+"::/64"; }
  return "unknown";
}
async function uaHash(env, ua){ return await sha256Base64(`${String(ua||"")}|${env.HASH_PEPPER}`); }
async function ipPrefixHash(env, ip){ return await sha256Base64(`${ipPrefix(ip)}|${env.HASH_PEPPER}`); }
async function ipHash(env, ip){ return await sha256Base64(`${ip}|${env.HASH_PEPPER}`); }

async function getSetting(env, k, defVal){
  const r = await env.DB.prepare("SELECT v FROM system_settings WHERE k=? LIMIT 1").bind(k).first();
  return r?.v != null ? String(r.v) : String(defVal);
}
async function bumpIpActivity(env, ip_hash, kind, window_start, inc=1){
  const id = `${kind}:${window_start}:${ip_hash}`;
  const now = nowSec();
  await env.DB.prepare(`
    INSERT INTO ip_activity (id,ip_hash,kind,cnt,window_start,updated_at)
    VALUES (?,?,?,?,?,?)
    ON CONFLICT(id) DO UPDATE SET cnt=cnt+excluded.cnt, updated_at=excluded.updated_at
  `).bind(id, ip_hash, kind, inc, window_start, now).run();
  const r = await env.DB.prepare(`SELECT cnt FROM ip_activity WHERE id=? LIMIT 1`).bind(id).first();
  return Number(r?.cnt || 0);
}
async function maybeAutoBlock(env, ip_hash){
  const enabled = (await getSetting(env,"auto_block.enabled","true")) === "true";
  if (!enabled) return { blocked:false };
  const window_sec = Number(await getSetting(env,"auto_block.window_sec","900"));
  const threshold = Number(await getSetting(env,"auto_block.threshold","10"));
  const ttl_sec = Number(await getSetting(env,"auto_block.ttl_sec","3600"));

  const now = nowSec();
  const window_start = now - (now % window_sec);
  const cnt = await bumpIpActivity(env, ip_hash, "password_fail", window_start, 1);

  if (cnt < threshold) return { blocked:false, cnt, threshold };

  await env.KV.put(`ipblock:${ip_hash}`, "auto_block_password_fail", { expirationTtl: ttl_sec });

  const id = crypto.randomUUID();
  const expires_at = now + ttl_sec;
  await env.DB.prepare(`
    INSERT INTO ip_blocks (id,ip_hash,reason,expires_at,revoked_at,created_at,created_by_user_id)
    VALUES (?,?,?,?,NULL,?,NULL)
  `).bind(id, ip_hash, "auto_block_password_fail", expires_at, now).run();

  return { blocked:true, id, expires_at, cnt, threshold };
}

export async function onRequestPost({ request, env }){
  if (!env.DB) return json(500,"server_error",{message:"missing_binding_DB"});
  if (!env.KV) return json(500,"server_error",{message:"missing_binding_KV"});
  if (!env.HASH_PEPPER) return json(500,"server_error",{message:"missing_HASH_PEPPER"});

  const body = await readJson(request);
  const email = normEmail(body?.email);
  const password = String(body?.password || "");
  if (!email.includes("@") || password.length < 6) return json(400,"invalid_input",null);

  const ip = getClientIp(request);
  const ip_h = await ipHash(env, ip);
  const emailKey = await sha256Base64(`${email}|${env.HASH_PEPPER}`);

  const rl = await rateLimitKV(env, `rl:login:${ip_h}:${emailKey}`, 10, 60);
  if (!rl.ok) return json(429, "rate_limited", null);

  const u = await env.DB.prepare(
    "SELECT id,display_name,status,password_hash,password_salt,password_iter FROM users WHERE email_norm=? LIMIT 1"
  ).bind(email).first();

  if (!u || String(u.status) !== "active" || !u.password_hash || !u.password_salt) {
    const ab = await maybeAutoBlock(env, ip_h);
    if (ab.blocked) return json(403,"forbidden",{message:"ip_blocked_auto", expires_at: ab.expires_at});
    return json(403, u ? "password_invalid" : "user_belum_terdaftar", null);
  }

  const iter = Number(u.password_iter || env.PBKDF2_ITER || 100000);
  const calc = await pbkdf2Hash(password, u.password_salt, iter);
  if (!timingSafeEqual(calc, u.password_hash)) {
    const ab = await maybeAutoBlock(env, ip_h);
    if (ab.blocked) return json(403,"forbidden",{message:"ip_blocked_auto", expires_at: ab.expires_at});
    return json(403, "password_invalid", null);
  }

  const roles = await getRolesForUser(env, u.id);
  const allowed = roles.includes("super_admin") || roles.includes("admin") || roles.includes("staff");
  if (!allowed) return json(403, "forbidden", { message:"role_not_allowed_for_dashboard" });

  // update login info (best effort)
  try{
    const now = nowSec();
    await env.DB.prepare("UPDATE users SET last_login_at=?, last_ip_hash=?, updated_at=? WHERE id=?")
      .bind(now, ip_h, now, u.id).run();
  }catch{}

  const sess = await createSession(env, u.id, roles, {
    ua_hash: await uaHash(env, request.headers.get("user-agent")||""),
    ip_prefix_hash: await ipPrefixHash(env, ip),
  });

  await audit(env,{ actor_user_id:u.id, action:"auth.login.ok", target_type:"session", target_id:sess.sid, meta:{ roles } });

  const res = json(200,"ok",{ id:u.id, display_name:u.display_name, roles, exp:sess.exp });
  res.headers.append("set-cookie", cookie("sid", sess.sid, { maxAge: sess.ttl }));
  return res;
}
