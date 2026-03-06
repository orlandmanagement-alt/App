import { json, readJson } from "../../../_lib.js";
function nowSec(){ return Math.floor(Date.now()/1000); }

async function hmacSign(secret, msg){
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name:"HMAC", hash:"SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replaceAll("+","-").replaceAll("/","_").replaceAll("=","");
}

export async function onRequestPost({ env, request }) {
  if (!env.RESET_TOKEN_SECRET) return json(500,"server_error",{message:"missing_RESET_TOKEN_SECRET"});
  const b = await readJson(request);
  const token = String(b?.token||"").trim();
  if (!token) return json(400,"invalid_input",{message:"token required"});

  const parts = token.split(".");
  if (parts.length !== 4) return json(400,"invalid_input",{message:"bad_token"});

  const [uid, expStr, nonce, sig] = parts;
  const exp = Number(expStr||"0");
  if (!uid || !nonce || !sig) return json(400,"invalid_input",{message:"bad_token"});
  if (nowSec() > exp) return json(400,"invalid_input",{message:"token_expired"});

  const payload = `${uid}.${exp}.${nonce}`;
  const expected = await hmacSign(env.RESET_TOKEN_SECRET, payload);
  if (expected !== sig) return json(400,"invalid_input",{message:"token_invalid"});

  return json(200,"ok",{ valid:true, uid, exp });
}
