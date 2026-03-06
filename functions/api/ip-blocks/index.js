import { json, hasRole } from "../../_lib.js";
function nowSec(){ return Math.floor(Date.now()/1000); }
export async function onRequestGet({ env, data, request }){
  const sess=data.session;
  if(!hasRole(sess.roles, ["super_admin","admin"])) return json(403,"forbidden",null);
  const url=new URL(request.url);
  const active=String(url.searchParams.get("active")||"1")==="1";
  const limit=Math.min(200, Math.max(1, Number(url.searchParams.get("limit")||"100")));
  const now=nowSec();
  const r = active
    ? await env.DB.prepare(`SELECT id,ip_hash,reason,expires_at,revoked_at,created_at,created_by_user_id FROM ip_blocks WHERE revoked_at IS NULL AND expires_at > ? ORDER BY created_at DESC LIMIT ?`).bind(now, limit).all()
    : await env.DB.prepare(`SELECT id,ip_hash,reason,expires_at,revoked_at,created_at,created_by_user_id FROM ip_blocks ORDER BY created_at DESC LIMIT ?`).bind(limit).all();
  return json(200,"ok",{ blocks: r.results||[] });
}
