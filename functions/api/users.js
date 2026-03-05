// App/functions/api/users.js
import {
  json, readJson, hasRole, normEmail,
  sha256Base64, randomB64, pbkdf2Hash, audit
} from "../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }

function canRead(sess){
  return hasRole(sess.roles, ["super_admin","admin","staff"]);
}
function onlySA(sess){
  return hasRole(sess.roles, ["super_admin"]);
}
function allowedRoleName(role){
  return ["super_admin","admin","staff"].includes(String(role||""));
}

async function ensureRole(env, roleName){
  const r = await env.DB.prepare("SELECT id FROM roles WHERE name=? LIMIT 1").bind(roleName).first();
  if (r?.id) return r.id;
  const id = crypto.randomUUID();
  await env.DB.prepare("INSERT INTO roles (id,name,created_at) VALUES (?,?,?)")
    .bind(id, roleName, nowSec()).run();
  return id;
}

async function setUserRole(env, user_id, roleName){
  const role_id = await ensureRole(env, roleName);
  const now = nowSec();
  // remove existing role links
  await env.DB.prepare("DELETE FROM user_roles WHERE user_id=?").bind(user_id).run();
  await env.DB.prepare("INSERT INTO user_roles (user_id,role_id,created_at) VALUES (?,?,?)")
    .bind(user_id, role_id, now).run();
}

async function getUserRoles(env, user_id){
  const r = await env.DB.prepare(`
    SELECT r.name AS name
    FROM user_roles ur JOIN roles r ON r.id=ur.role_id
    WHERE ur.user_id=?
  `).bind(user_id).all();
  return (r.results||[]).map(x=>x.name);
}

// GET /api/users?limit=50&q=abc
export async function onRequestGet({ env, data, request }){
  const sess = data.session;
  if (!canRead(sess)) return json(403,"forbidden",null);

  const url = new URL(request.url);
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit")||"50")));
  const q = String(url.searchParams.get("q")||"").trim().toLowerCase();

  let sql = `SELECT id,email_norm,display_name,status,updated_at,last_login_at,last_ip_hash FROM users`;
  const binds = [];
  if (q){
    sql += ` WHERE email_norm LIKE ? OR display_name LIKE ?`;
    binds.push(`%${q}%`, `%${q}%`);
  }
  sql += ` ORDER BY updated_at DESC LIMIT ?`;
  binds.push(limit);

  const r = await env.DB.prepare(sql).bind(...binds).all();
  const users = [];
  for (const u of (r.results||[])){
    const roles = await getUserRoles(env, u.id);
    // filter hanya admin/staff/super_admin
    const ok = roles.some(x=>["super_admin","admin","staff"].includes(x));
    if (!ok) continue;

    users.push({
      id: u.id,
      email_norm: u.email_norm,
      display_name: u.display_name,
      status: u.status,
      roles,
      updated_at: u.updated_at,
      last_login_at: u.last_login_at || null,
      last_ip_hash: u.last_ip_hash || null,
    });
  }

  return json(200,"ok",{ users });
}

// POST /api/users
// { email, display_name, role, password(min10) }
export async function onRequestPost({ env, data, request }){
  const sess = data.session;
  if (!onlySA(sess)) return json(403,"forbidden",null);

  const b = await readJson(request);
  const email = normEmail(b?.email);
  const display_name = String(b?.display_name||"").trim() || null;
  const role = String(b?.role||"staff").trim();
  const password = String(b?.password||"");

  if (!email.includes("@") || password.length < 10) return json(400,"invalid_input",{message:"email/password invalid"});
  if (!allowedRoleName(role)) return json(400,"invalid_input",{message:"role not allowed"});

  const used = await env.DB.prepare("SELECT id FROM users WHERE email_norm=? LIMIT 1").bind(email).first();
  if (used) return json(409,"conflict",{message:"email already used"});

  const now = nowSec();
  const user_id = crypto.randomUUID();

  const email_hash = await sha256Base64(`${email}|${env.HASH_PEPPER}`);
  const salt = randomB64(16);
  const iter = Math.min(100000, Math.max(10000, Number(env.PBKDF2_ITER||100000)));
  const hash = await pbkdf2Hash(password, salt, iter);

  await env.DB.prepare(`
    INSERT INTO users (
      id,email_norm,email_hash,display_name,status,created_at,updated_at,
      password_hash,password_salt,password_iter,password_algo
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
  `).bind(
    user_id, email, email_hash, display_name, "active", now, now,
    hash, salt, iter, "pbkdf2_sha256"
  ).run();

  await setUserRole(env, user_id, role);

  await audit(env,{ actor_user_id:sess.uid, action:"user.create", target_type:"user", target_id:user_id, meta:{ email, role } });

  return json(200,"ok",{ created:true, id:user_id });
}

// PUT /api/users
// actions:
// - update_profile: { user_id, display_name, role }
// - reset_password: { user_id, new_password }
// - disable: { user_id }
// - enable: { user_id }
export async function onRequestPut({ env, data, request }){
  const sess = data.session;
  if (!onlySA(sess)) return json(403,"forbidden",null);

  const b = await readJson(request);
  const action = String(b?.action||"").trim();
  const user_id = String(b?.user_id||"").trim();
  if (!action || !user_id) return json(400,"invalid_input",{message:"action & user_id required"});

  const now = nowSec();

  if (action === "update_profile"){
    const display_name = String(b?.display_name||"").trim() || null;
    const role = String(b?.role||"").trim();
    if (role && !allowedRoleName(role)) return json(400,"invalid_input",{message:"role not allowed"});

    await env.DB.prepare("UPDATE users SET display_name=?, updated_at=? WHERE id=?")
      .bind(display_name, now, user_id).run();

    if (role) await setUserRole(env, user_id, role);

    await audit(env,{ actor_user_id:sess.uid, action:"user.update_profile", target_type:"user", target_id:user_id, meta:{ role } });
    if (action === "revoke_sessions") {
  // super_admin only (sudah dicek di atas)
  const now = nowSec();
  await env.DB.prepare(`
    UPDATE users
    SET session_version = session_version + 1,
        updated_at = ?
    WHERE id=?
  `).bind(now, user_id).run();

  await audit(env,{ actor_user_id:sess.uid, action:"user.sessions.revoked", target_type:"user", target_id:user_id, meta:{} });
  return json(200,"ok",{ revoked:true });
}
    
                     return json(200,"ok",{ updated:true });
  }

  if (action === "reset_password"){
    const new_password = String(b?.new_password||"");
    if (new_password.length < 10) return json(400,"invalid_input",{message:"password min 10"});

    const salt = randomB64(16);
    const iter = Math.min(100000, Math.max(10000, Number(env.PBKDF2_ITER||100000)));
    const hash = await pbkdf2Hash(new_password, salt, iter);

    await env.DB.prepare(`
      UPDATE users SET password_hash=?, password_salt=?, password_iter=?, password_algo=?, updated_at=?
      WHERE id=?
    `).bind(hash, salt, iter, "pbkdf2_sha256", now, user_id).run();

    await audit(env,{ actor_user_id:sess.uid, action:"user.reset_password", target_type:"user", target_id:user_id, meta:{} });
    return json(200,"ok",{ updated:true });
  }

  if (action === "disable" || action === "enable"){
    const status = action === "disable" ? "disabled" : "active";
    await env.DB.prepare("UPDATE users SET status=?, updated_at=? WHERE id=?").bind(status, now, user_id).run();
    await audit(env,{ actor_user_id:sess.uid, action:`user.${action}`, target_type:"user", target_id:user_id, meta:{} });
    return json(200,"ok",{ updated:true, status });
  }

  return json(400,"invalid_input",{message:"unknown_action"});
}

// DELETE /api/users?id=...
export async function onRequestDelete({ env, data, request }){
  const sess = data.session;
  if (!onlySA(sess)) return json(403,"forbidden",null);

  const url = new URL(request.url);
  const id = String(url.searchParams.get("id")||"").trim();
  if (!id) return json(400,"invalid_input",{message:"id required"});

  await env.DB.prepare("DELETE FROM user_roles WHERE user_id=?").bind(id).run();
  await env.DB.prepare("DELETE FROM users WHERE id=?").bind(id).run();

  await audit(env,{ actor_user_id:sess.uid, action:"user.delete", target_type:"user", target_id:id, meta:{} });
  return json(200,"ok",{ deleted:true });
}
