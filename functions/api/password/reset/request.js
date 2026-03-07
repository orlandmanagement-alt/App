import { json, readJson, normEmail, requireEnv, nowSec } from "../../../_lib.js";
import { sendResetEmail } from "../../../_mail.js";

/**
 * POST /api/password/reset/request
 * Body: { email }
 * Always returns ok for privacy (even if email not found).
 * Uses KV to store token -> { uid, exp } (TTL)
 */
export async function onRequestPost({ request, env }){
  const miss = requireEnv(env, ["HASH_PEPPER","RESET_TOKEN_SECRET"]);
  if(miss.length) return json(500,"server_error",{message:"missing_env", missing:miss});

  const b = await readJson(request);
  const email = normEmail(b?.email);
  if(!email.includes("@")) return json(400,"invalid_input",null);

  const u = await env.DB.prepare(`SELECT id,email_norm,status FROM users WHERE email_norm=? LIMIT 1`).bind(email).first();
  if(!u || String(u.status)!=="active"){
    return json(200,"ok",{ sent:true });
  }

  // token random + signed
  const raw = crypto.randomUUID() + "." + crypto.randomUUID();
  const sig = await hmac(env.RESET_TOKEN_SECRET, raw);
  const token = b64url(raw + "." + sig);

  const exp = nowSec() + 3600; // 1 hour
  await env.KV.put(`pwreset:${token}`, JSON.stringify({ uid: u.id, exp }), { expirationTtl: 3600 });

  const link = `${new URL(request.url).origin}/reset.html?token=${encodeURIComponent(token)}`;
  await sendResetEmail({ to: u.email_norm, link });

  return json(200,"ok",{ sent:true });
}

async function hmac(secret, msg){
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(String(secret)),
    { name:"HMAC", hash:"SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(String(msg)));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}
function b64url(s){
  return String(s).replaceAll("+","-").replaceAll("/","_").replaceAll("=","");
}
