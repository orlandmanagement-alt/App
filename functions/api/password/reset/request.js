// App/functions/api/password/reset/request.js
import { json, readJson, normEmail, sha256Base64, audit } from "../../../_lib.js";
import { sendMail } from "../../../_mail.js";

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
  if (!env.RESET_TOKEN_SECRET) return json(500,"server_error",{message:"missing_RESET_TOKEN_SECRET"});
  if (!env.KV) return json(500,"server_error",{message:"missing_binding_KV"});
  if (!env.APP_BASE_URL) return json(500,"server_error",{message:"missing_APP_BASE_URL"});

  const b = await readJson(request);
  const email = normEmail(b?.email);
  if (!email.includes("@")) return json(400,"invalid_input",{message:"email invalid"});

  const u = await env.DB.prepare("SELECT id,status FROM users WHERE email_norm=? LIMIT 1").bind(email).first();

  // Anti enumeration: selalu balas ok
  if (!u || String(u.status)!=="active") return json(200,"ok",{ sent:true });

  const exp = nowSec() + 15*60;
  const nonce = crypto.randomUUID();
  const payload = `${u.id}.${exp}.${nonce}`;
  const sig = await hmacSign(env.RESET_TOKEN_SECRET, payload);
  const token = `${payload}.${sig}`;

  const th = await sha256Base64(`${token}|${env.HASH_PEPPER||""}`);
  await env.KV.put(`pwreset:${th}`, u.id, { expirationTtl: 15*60 });

  const link = `${String(env.APP_BASE_URL).replace(/\/$/,"")}/reset.html?token=${encodeURIComponent(token)}`;

  // ✅ SEND EMAIL
  const subject = "Reset Password — Orland Management Dashboard";
  const text = `Klik link untuk reset password (berlaku 15 menit):\n${link}\n\nJika kamu tidak meminta reset, abaikan email ini.`;
  const html = `
    <div style="font-family:Arial,sans-serif;line-height:1.5">
      <h2>Reset Password</h2>
      <p>Klik tombol di bawah untuk reset password (berlaku 15 menit).</p>
      <p><a href="${link}" style="display:inline-block;padding:10px 14px;background:#6D28D9;color:#fff;border-radius:10px;text-decoration:none">Reset Password</a></p>
      <p style="font-size:12px;color:#666">Jika tombol tidak berfungsi, copy link ini:</p>
      <p style="font-size:12px"><a href="${link}">${link}</a></p>
      <p style="font-size:12px;color:#666">Jika kamu tidak meminta reset, abaikan email ini.</p>
    </div>
  `;

  try {
    await sendMail(env, { to: email, subject, html, text });
  } catch (e) {
    // tetap balas ok tapi audit error
    await audit(env,{ actor_user_id:null, action:"password.reset.email_fail", target_type:"user", target_id:u.id, meta:{ err:String(e) } });
    return json(200,"ok",{ sent:true });
  }

  await audit(env,{ actor_user_id:null, action:"password.reset.email_sent", target_type:"user", target_id:u.id, meta:{} });
  return json(200,"ok",{ sent:true });
}
