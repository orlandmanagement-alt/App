import { json, readJson, hasRole, audit } from "../../_lib.js";
function nowSec(){ return Math.floor(Date.now()/1000); }
export async function onRequestPost({ env, data, request }){
  const sess=data.session;
  if(!hasRole(sess.roles, ["super_admin"])) return json(403,"forbidden",null);
  const b=await readJson(request);
  const ip_hash=String(b?.ip_hash||"").trim();
  const ttl_sec=Math.min(7*86400, Math.max(60, Number(b?.ttl_sec||3600)));
  const reason=String(b?.reason||"manual_block").trim();
  if(!ip_hash) return json(400,"invalid_input",{message:"ip_hash required"});

  await env.KV.put(`ipblock:${ip_hash}`, reason, { expirationTtl: ttl_sec });

  const id=crypto.randomUUID();
  const now=nowSec();
  const expires_at=now+ttl_sec;
  await env.DB.prepare(`INSERT INTO ip_blocks (id,ip_hash,reason,expires_at,revoked_at,created_at,created_by_user_id) VALUES (?,?,?,?,NULL,?,?)`)
    .bind(id, ip_hash, reason, expires_at, now, sess.uid).run();

  await audit(env,{ actor_user_id:sess.uid, action:"ipblock.block", target_type:"ip_block", target_id:id, meta:{ttl_sec} });
  return json(200,"ok",{ blocked:true, id, expires_at });
}
