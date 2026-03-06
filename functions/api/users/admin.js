import { json, readJson, normEmail, hasRole, getRolesForUser, pbkdf2Hash, randomB64, sha256Base64, audit, ensureRole } from "../../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }

export async function onRequestGet({ env, data, request }){
  const sess=data.session;
  if(!hasRole(sess.roles, ["super_admin","admin"])) return json(403,"forbidden",null);

  const url=new URL(request.url);
  const q=String(url.searchParams.get("q")||"").trim().toLowerCase();
  const limit=Math.min(200, Math.max(1, Number(url.searchParams.get("limit")||"50")));

  let sql="SELECT id,email_norm,display_name,status,created_at,updated_at,last_login_at,last_ip_hash,session_version FROM users";
  const binds=[];
  if(q){ sql += " WHERE email_norm LIKE ? OR display_name LIKE ?"; binds.push(`%${q}%`,`%${q}%`); }
  sql += " ORDER BY updated_at DESC LIMIT ?"; binds.push(limit);

  const r=await env.DB.prepare(sql).bind(...binds).all();
  const out=[];
  for (const u of (r.results||[])){
    const roles = await getRolesForUser(env, u.id);
    const adminish = roles.some(x=>["super_admin","admin","staff"].includes(x));
    if (!adminish) continue;
    out.push({ ...u, roles });
  }
  return json(200,"ok",{ users: out });
}

export async function onRequestPost({ env, data, request }){
  const sess=data.session;
  if(!hasRole(sess.roles, ["super_admin","admin"])) return json(403,"forbidden",null);

  const b=await readJson(request);
  const email=normEmail(b?.email);
  const display_name=String(b?.display_name||"").trim() || "User";
  const role=String(b?.role||"staff").trim();
  const password=String(b?.password||"");

  if(!email.includes("@") || password.length < 10) return json(400,"invalid_input",{message:"email invalid / password min 10"});
  if(!["staff","admin","super_admin"].includes(role)) return json(400,"invalid_input",{message:"role invalid"});
  if(role==="super_admin" && !sess.roles.includes("super_admin")) return json(403,"forbidden",{message:"super_admin_only"});

  const used = await env.DB.prepare("SELECT id FROM users WHERE email_norm=? LIMIT 1").bind(email).first();
  if(used) return json(409,"conflict",{message:"email already used"});

  const now=nowSec();
  const user_id=crypto.randomUUID();
  const email_hash=await sha256Base64(`${email}|${env.HASH_PEPPER||""}`);
  const salt=randomB64(16);
  const iter=Math.min(100000, Math.max(10000, Number(env.PBKDF2_ITER||100000)));
  const hash=await pbkdf2Hash(password, salt, iter);

  await env.DB.prepare(`
    INSERT INTO users (id,email_norm,email_hash,display_name,status,created_at,updated_at,password_hash,password_salt,password_iter,password_algo,session_version)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,1)
  `).bind(user_id,email,email_hash,display_name,"active",now,now,hash,salt,iter,"pbkdf2_sha256").run();

  const role_id = await ensureRole(env, role);
  await env.DB.prepare("INSERT INTO user_roles (user_id,role_id,created_at) VALUES (?,?,?)").bind(user_id, role_id, now).run();

  await audit(env,{actor_user_id:sess.uid, action:"users.create", target_type:"user", target_id:user_id, meta:{role}});
  return json(200,"ok",{ created:true, user_id });
}

export async function onRequestPut({ env, data, request }){
  const sess=data.session;
  if(!hasRole(sess.roles, ["super_admin","admin"])) return json(403,"forbidden",null);

  const b=await readJson(request);
  const action=String(b?.action||"").trim();
  const user_id=String(b?.user_id||"").trim();
  if(!action || !user_id) return json(400,"invalid_input",{message:"action/user_id required"});

  const targetRoles = await getRolesForUser(env, user_id);
  if(targetRoles.includes("super_admin") && !sess.roles.includes("super_admin")){
    return json(403,"forbidden",{message:"cannot_modify_super_admin"});
  }

  if(action==="disable" || action==="enable"){
    const status = action==="disable" ? "disabled" : "active";
    await env.DB.prepare("UPDATE users SET status=?, updated_at=? WHERE id=?").bind(status, nowSec(), user_id).run();
    await audit(env,{actor_user_id:sess.uid, action:`users.${action}`, target_type:"user", target_id:user_id, meta:{}});
    return json(200,"ok",{ updated:true });
  }

  if(action==="reset_password"){
    if(!sess.roles.includes("super_admin")) return json(403,"forbidden",{message:"super_admin_only"});
    const new_password=String(b?.new_password||"");
    if(new_password.length < 10) return json(400,"invalid_input",{message:"new_password min 10"});
    const salt=randomB64(16);
    const iter=Math.min(100000, Math.max(10000, Number(env.PBKDF2_ITER||100000)));
    const hash=await pbkdf2Hash(new_password, salt, iter);
    await env.DB.prepare(`
      UPDATE users SET password_hash=?, password_salt=?, password_iter=?, password_algo='pbkdf2_sha256',
      updated_at=?, session_version=session_version+1
      WHERE id=?
    `).bind(hash,salt,iter,nowSec(),user_id).run();
    await audit(env,{actor_user_id:sess.uid, action:"users.reset_password", target_type:"user", target_id:user_id, meta:{}});
    return json(200,"ok",{ reset:true });
  }

  if(action==="set_roles"){
    if(!sess.roles.includes("super_admin")) return json(403,"forbidden",{message:"super_admin_only"});
    const roles = Array.isArray(b?.roles) ? b.roles.map(x=>String(x).trim()).filter(Boolean) : [];
    if(!roles.length) return json(400,"invalid_input",{message:"roles required"});
    for (const r of roles) if(!["super_admin","admin","staff"].includes(r)) return json(400,"invalid_input",{message:"role invalid"});

    await env.DB.prepare("DELETE FROM user_roles WHERE user_id=?").bind(user_id).run();
    for (const r of roles){
      const rid=await ensureRole(env, r);
      await env.DB.prepare("INSERT INTO user_roles (user_id,role_id,created_at) VALUES (?,?,?)").bind(user_id, rid, nowSec()).run();
    }
    await audit(env,{actor_user_id:sess.uid, action:"users.set_roles", target_type:"user", target_id:user_id, meta:{roles}});
    return json(200,"ok",{ updated:true });
  }

  if(action==="revoke_sessions"){
    if(!sess.roles.includes("super_admin")) return json(403,"forbidden",{message:"super_admin_only"});
    await env.DB.prepare("UPDATE users SET session_version=session_version+1, updated_at=? WHERE id=?").bind(nowSec(), user_id).run();
    await audit(env,{actor_user_id:sess.uid, action:"user.sessions.revoked", target_type:"user", target_id:user_id, meta:{}});
    return json(200,"ok",{ revoked:true });
  }

  return json(400,"invalid_input",{message:"unknown_action"});
}

export async function onRequestDelete({ env, data, request }){
  const sess=data.session;
  if(!hasRole(sess.roles, ["super_admin"])) return json(403,"forbidden",null);
  const url=new URL(request.url);
  const id=String(url.searchParams.get("id")||"").trim();
  if(!id) return json(400,"invalid_input",{message:"id required"});
  await env.DB.prepare("DELETE FROM users WHERE id=?").bind(id).run();
  await audit(env,{actor_user_id:sess.uid, action:"users.delete", target_type:"user", target_id:id, meta:{}});
  return json(200,"ok",{ deleted:true });
}
