import { json, readJson, normEmail, sha256Base64, audit } from "../../../_lib.js";

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
  const b = await readJson(request);
  const email = normEmail(b?.email);
  if (!email.includes("@")) return json(400,"invalid_input",{message:"email invalid"});

  const u = await env.DB.prepare("SELECT id,status FROM users WHERE email_norm=? LIMIT 1").bind(email).first();
  // selalu balas ok (anti enumeration)
  if (!u || String(u.status)!=="active") return json(200,"ok",{ sent:true });

  const exp = nowSec() + 15*60; // 15 menit
  const nonce = crypto.randomUUID();
  const payload = `${u.id}.${exp}.${nonce}`;
  const sig = await hmacSign(env.RESET_TOKEN_SECRET, payload);
  const token = `${payload}.${sig}`;

  // store hash token in KV (optional additional check)
  const th = await sha256Base64(`${token}|${env.HASH_PEPPER||""}`);
  await env.KV.put(`pwreset:${th}`, u.id, { expirationTtl: 15*60 });

  await audit(env,{ actor_user_id:null, action:"password.reset.request", target_type:"user", target_id:u.id, meta:{} });

  const base = String(env.APP_BASE_URL || "").trim(); // contoh: https://dashboard.orlandmanagement.com
  const link = base ? `${base}/reset.html?token=${encodeURIComponent(token)}` : null;

  // sementara: return token+link (nanti email)
  return json(200,"ok",{ sent:true, token, link });
}
