import { json, readJson, requireAuth, hasRole, normEmail, randomB64, pbkdf2Hash, sha256Base64, nowSec, getRolesForUser } from "../../_lib.js";

function requireManage(roles){
  // mutations allowed for super_admin & admin only
  return roles.includes("super_admin") || roles.includes("admin");
}

export async function onRequestGet({ request, env }) {
  const a = await requireAuth(env, request);
  if(!a.ok) return a.res;

  // staff can read list; admin/super_admin can read list
  if(!hasRole(a.roles, ["super_admin","admin","staff"])) return json(403,"forbidden",null);

  const url = new URL(request.url);
  const q = String(url.searchParams.get("q")||"").trim().toLowerCase();
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit")||"50")));

  let sql = `SELECT id,email_norm,display_name,status,updated_at FROM users`;
  const binds = [];
  if(q){
    sql += ` WHERE email_norm LIKE ? OR display_name LIKE ?`;
    binds.push(`%${q}%`,`%${q}%`);
  }
  sql += ` ORDER BY updated_at DESC LIMIT ?`;
  binds.push(limit);

  const r = await env.DB.prepare(sql).bind(...binds).all();
  const users = r.results || [];

  // roles per user
  const out = [];
  for(const u of users){
    const roles = await getRolesForUser(env, u.id);
    const last = await env.DB.prepare(`SELECT MAX(created_at) AS last_seen_at FROM sessions WHERE user_id=?`).bind(u.id).first();
    out.push({
      id: u.id,
      email_norm: u.email_norm,
      display_name: u.display_name,
      status: u.status,
      roles,
      last_login_at: last?.last_seen_at || null
    });
  }

  return json(200,"ok",{ users: out });
}

export async function onRequestPost({ request, env }) {
  const a = await requireAuth(env, request);
  if(!a.ok) return a.res;
  if(!requireManage(a.roles)) return json(403,"forbidden",null);

  const b = await readJson(request);
  const email = normEmail(b?.email);
  const display_name = String(b?.display_name||"").trim();
  const roleName = String(b?.role||"staff").trim();
  const password = String(b?.password||"");

  if(!email.includes("@") || password.length < 10) return json(400,"invalid_input",{message:"email/password invalid"});
  if(!["staff","admin","super_admin"].includes(roleName)) return json(400,"invalid_input",{message:"role invalid"});

  const used = await env.DB.prepare(`SELECT id FROM users WHERE email_norm=? LIMIT 1`).bind(email).first();
  if(used) return json(409,"conflict",{message:"email already used"});

  // ensure role exists
  let role = await env.DB.prepare(`SELECT id FROM roles WHERE name=? LIMIT 1`).bind(roleName).first();
  if(!role){
    const rid = crypto.randomUUID();
    await env.DB.prepare(`INSERT INTO roles (id,name,created_at) VALUES (?,?,?)`).bind(rid, roleName, nowSec()).run();
    role = { id: rid };
  }

  const user_id = crypto.randomUUID();
  const email_hash = await sha256Base64(`${email}|${env.HASH_PEPPER}`);
  const salt = randomB64(16);
  const iter = Math.min(100000, Number(env.PBKDF2_ITER || 100000));
  const hash = await pbkdf2Hash(password, salt, iter);
  const now = nowSec();

  await env.DB.prepare(`
    INSERT INTO users (id,email_norm,email_hash,display_name,status,created_at,updated_at,password_hash,password_salt,password_iter,password_algo)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)
  `).bind(user_id, email, email_hash, display_name, "active", now, now, hash, salt, iter, "pbkdf2_sha256").run();

  await env.DB.prepare(`INSERT INTO user_roles (user_id,role_id,created_at) VALUES (?,?,?)`)
    .bind(user_id, role.id, now).run();

  return json(200,"ok",{ created:true, user_id });
}

export async function onRequestPut({ request, env }) {
  const a = await requireAuth(env, request);
  if(!a.ok) return a.res;
  if(!requireManage(a.roles)) return json(403,"forbidden",null);

  const b = await readJson(request);
  const action = String(b?.action||"").trim();
  const user_id = String(b?.user_id||"").trim();
  if(!action || !user_id) return json(400,"invalid_input",null);

  const now = nowSec();

  if(action === "disable" || action === "enable"){
    const status = (action==="disable") ? "disabled" : "active";
    await env.DB.prepare(`UPDATE users SET status=?, updated_at=? WHERE id=?`).bind(status, now, user_id).run();
    return json(200,"ok",{ updated:true });
  }

  // only super_admin can do sensitive actions
  const isSA = a.roles.includes("super_admin");

  if(action === "reset_password"){
    if(!isSA) return json(403,"forbidden",{message:"super_admin_only"});
    const new_password = String(b?.new_password||"");
    if(new_password.length < 10) return json(400,"invalid_input",{message:"min 10"});
    const salt = randomB64(16);
    const iter = Math.min(100000, Number(env.PBKDF2_ITER || 100000));
    const hash = await pbkdf2Hash(new_password, salt, iter);
    await env.DB.prepare(`
      UPDATE users SET password_hash=?, password_salt=?, password_iter=?, password_algo=?, updated_at=?
      WHERE id=?
    `).bind(hash, salt, iter, "pbkdf2_sha256", now, user_id).run();
    return json(200,"ok",{ updated:true });
  }

  if(action === "revoke_sessions"){
    if(!isSA) return json(403,"forbidden",{message:"super_admin_only"});
    await env.DB.prepare(`UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`).bind(now, user_id).run();
    return json(200,"ok",{ revoked:true });
  }

  if(action === "set_roles"){
    if(!isSA) return json(403,"forbidden",{message:"super_admin_only"});
    const roles = Array.isArray(b?.roles) ? b.roles.map(x=>String(x).trim()).filter(Boolean) : [];
    const allowed = ["staff","admin","super_admin"];
    const clean = roles.filter(r=>allowed.includes(r));
    if(!clean.length) return json(400,"invalid_input",{message:"roles empty"});

    // ensure roles exist
    const roleIds = [];
    for(const rn of clean){
      let role = await env.DB.prepare(`SELECT id FROM roles WHERE name=? LIMIT 1`).bind(rn).first();
      if(!role){
        const rid = crypto.randomUUID();
        await env.DB.prepare(`INSERT INTO roles (id,name,created_at) VALUES (?,?,?)`).bind(rid, rn, now).run();
        role = { id: rid };
      }
      roleIds.push(role.id);
    }

    await env.DB.prepare(`DELETE FROM user_roles WHERE user_id=?`).bind(user_id).run();
    for(const rid of roleIds){
      await env.DB.prepare(`INSERT INTO user_roles (user_id,role_id,created_at) VALUES (?,?,?)`).bind(user_id, rid, now).run();
    }
    return json(200,"ok",{ updated:true, count: roleIds.length });
  }

  return json(400,"invalid_input",{message:"unknown_action"});
}
