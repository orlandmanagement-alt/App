// App/functions/api/invites/accept.js
import { json, readJson, pbkdf2Hash, randomB64, sha256Base64, normEmail, audit } from "../../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }
function b64url(s){ return btoa(s).replaceAll("+","-").replaceAll("/","_").replaceAll("=",""); }

async function hmacSign(secret, msg){
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name:"HMAC", hash:"SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
  return b64url(String.fromCharCode(...new Uint8Array(sig)));
}

export async function onRequestPost({ env, request }) {
  if (!env.INVITE_TOKEN_SECRET) return json(500,"server_error",{message:"missing_INVITE_TOKEN_SECRET"});

  const b = await readJson(request);
  const token = String(b?.token||"").trim();
  const display_name = String(b?.display_name||"").trim() || "Admin";
  const password = String(b?.password||"");

  if (!token || password.length < 10) return json(400,"invalid_input",{message:"token/password invalid"});

  const parts = token.split(".");
  if (parts.length !== 4) return json(400,"invalid_input",{message:"bad_token"});

  const [invite_id, expStr, nonce, sig] = parts;
  const exp = Number(expStr||"0");
  if (!invite_id || !nonce || !sig) return json(400,"invalid_input",{message:"bad_token"});
  if (nowSec() > exp) return json(400,"invalid_input",{message:"token_expired"});

  const payload = `${invite_id}.${exp}.${nonce}`;
  const expected = await hmacSign(env.INVITE_TOKEN_SECRET, payload);
  if (expected !== sig) return json(400,"invalid_input",{message:"token_invalid"});

  // load invite
  const inv = await env.DB.prepare(`SELECT * FROM invites WHERE id=? LIMIT 1`).bind(invite_id).first();
  if (!inv) return json(404,"invalid_input",{message:"invite_not_found"});
  if (inv.used_at) return json(400,"invalid_input",{message:"invite_used"});
  if (Number(inv.expires_at||0) < nowSec()) return json(400,"invalid_input",{message:"invite_expired"});

  // We must know email to create user -> store email hash only, so accept requires email too OR we use pre-approved email list.
  // Simpler: pass email in body and verify its hash matches inv.email_hash
  const email = normEmail(b?.email);
  if (!email.includes("@")) return json(400,"invalid_input",{message:"email_required"});
  const email_hash = await sha256Base64(`${email}|${env.HASH_PEPPER||""}`);
  if (email_hash !== inv.email_hash) return json(403,"forbidden",{message:"email_mismatch"});

  // create role if missing
  let roleRow = await env.DB.prepare("SELECT id FROM roles WHERE name=? LIMIT 1").bind(inv.role).first();
  if (!roleRow){
    const rid = crypto.randomUUID();
    await env.DB.prepare("INSERT INTO roles (id,name,created_at) VALUES (?,?,?)").bind(rid, inv.role, nowSec()).run();
    roleRow = { id: rid };
  }

  // create user
  const used = await env.DB.prepare("SELECT id FROM users WHERE email_norm=? LIMIT 1").bind(email).first();
  if (used) return json(409,"conflict",{message:"email already used"});

  const user_id = crypto.randomUUID();
  const salt = randomB64(16);
  const iter = Math.min(100000, Math.max(10000, Number(env.PBKDF2_ITER||100000)));
  const hash = await pbkdf2Hash(password, salt, iter);
  const now = nowSec();

  await env.DB.prepare(`
    INSERT INTO users (id,email_norm,email_hash,display_name,status,created_at,updated_at,password_hash,password_salt,password_iter,password_algo,session_version)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,1)
  `).bind(user_id, email, email_hash, display_name, "active", now, now, hash, salt, iter, "pbkdf2_sha256").run();

  await env.DB.prepare("INSERT INTO user_roles (user_id,role_id,created_at) VALUES (?,?,?)")
    .bind(user_id, roleRow.id, now).run();

  await env.DB.prepare("UPDATE invites SET used_at=?, used_by_user_id=? WHERE id=?")
    .bind(now, user_id, invite_id).run();

  await audit(env,{ actor_user_id:user_id, action:"invite.accepted", target_type:"invite", target_id:invite_id, meta:{ role: inv.role } });
  return json(200,"ok",{ created:true, user_id });
}
