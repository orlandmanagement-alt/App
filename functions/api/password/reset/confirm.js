import { json, readJson, pbkdf2Hash, randomB64, sha256Base64, audit } from "../../../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }

function b64urlToB64(s){
  s = String(s||"").replaceAll("-","+").replaceAll("_","/");
  while (s.length % 4) s += "=";
  return s;
}

async function hmacSign(secret, msg){
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name:"HMAC", hash:"SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
  const b64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return b64.replaceAll("+","-").replaceAll("/","_").replaceAll("=","");
}

export async function onRequestPost({ env, request }) {
  if (!env.RESET_TOKEN_SECRET) return json(500,"server_error",{message:"missing_RESET_TOKEN_SECRET"});
  const b = await readJson(request);
  const token = String(b?.token||"").trim();
  const new_password = String(b?.new_password||"");
  if (!token || new_password.length < 10) return json(400,"invalid_input",{message:"token/password invalid"});

  const parts = token.split(".");
  if (parts.length !== 4) return json(400,"invalid_input",{message:"bad_token"});
  const [uid, expStr, nonce, sig] = parts;
  const exp = Number(expStr||"0");
  if (!uid || !nonce || !sig || nowSec() > exp) return json(400,"invalid_input",{message:"token_expired"});

  const payload = `${uid}.${exp}.${nonce}`;
  const expected = await hmacSign(env.RESET_TOKEN_SECRET, payload);
  if (expected !== sig) return json(400,"invalid_input",{message:"token_invalid"});

  // KV check (optional)
  const th = await sha256Base64(`${token}|${env.HASH_PEPPER||""}`);
  const kvUid = await env.KV.get(`pwreset:${th}`);
  if (!kvUid || kvUid !== uid) return json(400,"invalid_input",{message:"token_used_or_invalid"});
  await env.KV.delete(`pwreset:${th}`);

  // set new password
  const salt = randomB64(16);
  const iter = Math.min(100000, Math.max(10000, Number(env.PBKDF2_ITER||100000)));
  const hash = await pbkdf2Hash(new_password, salt, iter);
  const now = nowSec();

  await env.DB.prepare(`
    UPDATE users
    SET password_hash=?, password_salt=?, password_iter=?, password_algo=?, updated_at=?, session_version=session_version+1
    WHERE id=?
  `).bind(hash, salt, iter, "pbkdf2_sha256", now, uid).run();

  await audit(env,{ actor_user_id:null, action:"password.reset.confirm", target_type:"user", target_id:uid, meta:{} });

  return json(200,"ok",{ reset:true });
}
