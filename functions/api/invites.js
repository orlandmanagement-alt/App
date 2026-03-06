import { json, readJson, normEmail, hasRole, sha256Base64, audit } from "../_lib.js";
import { sendMail } from "../_mail.js";

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

export async function onRequestGet({ env, data, request }){
  const sess=data.session;
  if(!hasRole(sess.roles, ["super_admin","admin"])) return json(403,"forbidden",null);
  const url=new URL(request.url);
  const limit=Math.min(200, Math.max(1, Number(url.searchParams.get("limit")||"50")));
  const r=await env.DB.prepare(`SELECT id,email_hash,role,expires_at,used_at,used_by_user_id,created_by_user_id,created_at FROM invites ORDER BY created_at DESC LIMIT ?`).bind(limit).all();
  return json(200,"ok",{ invites:r.results||[] });
}

export async function onRequestPost({ env, data, request }){
  const sess=data.session;
  if(!hasRole(sess.roles, ["super_admin","admin"])) return json(403,"forbidden",null);
  if(!env.INVITE_TOKEN_SECRET) return json(500,"server_error",{message:"missing_INVITE_TOKEN_SECRET"});
  if(!env.APP_BASE_URL) return json(500,"server_error",{message:"missing_APP_BASE_URL"});

  const b=await readJson(request);
  const email=normEmail(b?.email);
  const role=String(b?.role||"staff").trim();

  if(!email.includes("@")) return json(400,"invalid_input",{message:"email invalid"});
  if(!["admin","staff","super_admin"].includes(role)) return json(400,"invalid_input",{message:"role invalid"});
  if(role==="super_admin" && !sess.roles.includes("super_admin")) return json(403,"forbidden",{message:"super_admin_only"});

  const exist = await env.DB.prepare("SELECT id FROM users WHERE email_norm=? LIMIT 1").bind(email).first();
  if(exist) return json(409,"conflict",{message:"email already used"});

  const now=nowSec();
  const expires_at=now + 24*3600;
  const invite_id=crypto.randomUUID();
  const email_hash=await sha256Base64(`${email}|${env.HASH_PEPPER||""}`);

  await env.DB.prepare(`INSERT INTO invites (id,email_hash,role,expires_at,used_at,used_by_user_id,created_by_user_id,created_at) VALUES (?,?,?,?,NULL,NULL,?,?)`)
    .bind(invite_id,email_hash,role,expires_at,sess.uid,now).run();

  const exp=expires_at;
  const nonce=crypto.randomUUID();
  const payload=`${invite_id}.${exp}.${nonce}`;
  const sig=await hmacSign(env.INVITE_TOKEN_SECRET, payload);
  const token=`${payload}.${sig}`;

  const base=String(env.APP_BASE_URL).replace(/\/$/,"");
  const link=`${base}/setup.html?invite=${encodeURIComponent(token)}`;

  const subject="Undangan Admin — Orland Dashboard";
  const text=`Kamu diundang sebagai ${role}. Klik link (24 jam):\n${link}`;
  const html=`
    <div style="font-family:Arial;line-height:1.5">
      <h2>Undangan Admin</h2>
      <p>Kamu diundang sebagai <b>${role}</b>. Link berlaku 24 jam.</p>
      <p><a href="${link}" style="display:inline-block;padding:10px 14px;background:#6D28D9;color:#fff;border-radius:10px;text-decoration:none">Set Password</a></p>
      <p style="font-size:12px;color:#666">Jika tombol tidak berfungsi, copy link:</p>
      <p style="font-size:12px"><a href="${link}">${link}</a></p>
    </div>
  `;

  try{ await sendMail(env,{ to:email, subject, html, text }); }
  catch(e){
    await audit(env,{actor_user_id:sess.uid, action:"invite.email_fail", target_type:"invite", target_id:invite_id, meta:{err:String(e)}});
    return json(200,"ok",{ created:true, invite_id, sent:false, link });
  }

  await audit(env,{actor_user_id:sess.uid, action:"invite.created", target_type:"invite", target_id:invite_id, meta:{role}});
  return json(200,"ok",{ created:true, invite_id, sent:true });
}
