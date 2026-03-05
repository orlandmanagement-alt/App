// App/functions/api/security/settings.js
import { json, readJson, hasRole, audit } from "../../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }

export async function onRequestGet({ env, data }){
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin","admin"])) return json(403,"forbidden",null);

  const r = await env.DB.prepare(`
    SELECT k,v,updated_at
    FROM system_settings
    WHERE is_secret=0
    ORDER BY k ASC
  `).all();

  return json(200,"ok",{ settings: r.results||[] });
}

export async function onRequestPost({ env, data, request }){
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin"])) return json(403,"forbidden",null);

  const b = await readJson(request);
  const k = String(b?.k||"").trim();
  const v = String(b?.v||"").trim();
  if (!k) return json(400,"invalid_input",{message:"k required"});

  const now = nowSec();
  await env.DB.prepare(`
    INSERT INTO system_settings (k,v,is_secret,updated_at)
    VALUES (?,?,0,?)
    ON CONFLICT(k) DO UPDATE SET v=excluded.v, updated_at=excluded.updated_at
  `).bind(k, v, now).run();

  await audit(env,{actor_user_id:sess.uid, action:"settings.set", target_type:"setting", target_id:k, meta:{}});
  return json(200,"ok",{ updated:true });
}
