import { json, hasRole } from "../../_lib.js";
function nowSec(){ return Math.floor(Date.now()/1000); }
export async function onRequestPost({ env, data }){
  const sess=data.session;
  if(!hasRole(sess.roles, ["super_admin"])) return json(403,"forbidden",null);
  const now=nowSec();
  const r=await env.DB.prepare(`SELECT id,ip_hash FROM ip_blocks WHERE revoked_at IS NULL AND expires_at <= ? ORDER BY expires_at ASC LIMIT 500`).bind(now).all();
  let revoked=0;
  for (const b of (r.results||[])){
    await env.DB.prepare("UPDATE ip_blocks SET revoked_at=? WHERE id=?").bind(now, b.id).run();
    try{ await env.KV.delete(`ipblock:${b.ip_hash}`);}catch{}
    revoked++;
  }
  return json(200,"ok",{ revoked });
}
