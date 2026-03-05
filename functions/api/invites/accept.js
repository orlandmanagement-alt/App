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
  if (!inv) return
