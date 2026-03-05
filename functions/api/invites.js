// App/functions/api/invites.js
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
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin","admin"])) return json(403,"forbidden",null);

  const url = new URL(request.url);
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit")||"50")));

  const r = await env.DB.prepare(`
    SELECT id,email_hash,role,expires_at,used_at,used_by_user_id,created_by_user_id,created_at
    FROM invites
    ORDER BY created_at DESC
    LIMIT ?
  `).bind(limit).all();

  return json(200,"ok",{ invites: r.results||[] });
}

export async function onRequestPost({ env, data, request }){
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin","admin"])) return json(403,"forbidden",null);
  if (!env.INVITE_TOKEN_SECRET) return json(500,"server_error",{message:"missing_INVITE_TOKEN_SECRET"});
  if (!env.APP_BASE_URL) return json(500,"server_error",{message:"missing_APP_BASE_URL"});

  const b = await readJson(request);
  const email = normEmail(b?.email);
  const role = String(b?.role||"staff").trim();

  if (!email.includes("@")) return json(400,"invalid_input",{message:"email invalid"});
  if (!["admin","staff","super_admin"].includes(role)) return json(400,"invalid_input",{message:"role invalid"});

  // prevent duplicate active user
