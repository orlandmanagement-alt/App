import { json, readJson, hasRole, audit } from "../../_lib.js";
function nowSec(){ return Math.floor(Date.now()/1000); }
export async function onRequestPost({ env, data, request }){
  const sess=data.session;
  if(!hasRole(sess.roles, ["super_admin"])) return json(403,"forbidden",null);
  const b=await readJson(request);
  const id=String(b?.id||"").trim();
  if(!id) return json(400,"invalid_input",{message:"id required"});

  const row = await env.DB.prepare("SELECT ip_hash FROM ip_blocks WHERE id=? LIMIT 1").bind(id).first();
  if(!row) return json(404,"invalid_input",{message:"not_found"});

  await env.KV.delete(`ipblock:${row.ip_hash}`);
  await env.DB.prepare("UPDATE ip_blocks SET revoked_at=? WHERE id=?").bind(nowSec(), id).run();
  await audit(env,{ actor_user_id:sess.uid, action:"ipblock.unblock", target_type:"ip_block", target_id:id, meta:{} });
  return json(200,"ok",{ unblocked:true });
}
