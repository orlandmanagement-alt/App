import { json, readJson, requireEnv, nowSec, randomB64, pbkdf2Hash } from "../../../_lib.js";

/**
 * POST /api/password/reset/confirm
 * Body: { token, new_password }
 */
export async function onRequestPost({ request, env }){
  const miss = requireEnv(env, ["RESET_TOKEN_SECRET"]);
  if(miss.length) return json(500,"server_error",{message:"missing_env", missing:miss});

  const b = await readJson(request);
  const token = String(b?.token||"").trim();
  const new_password = String(b?.new_password||"");
  if(!token || new_password.length < 10) return json(400,"invalid_input",null);

  const recStr = await env.KV.get(`pwreset:${token}`);
  if(!recStr) return json(400,"invalid_input",{message:"invalid_or_expired"});

  let rec=null;
  try{ rec = JSON.parse(recStr); }catch{ rec=null; }
  if(!rec?.uid || nowSec() > Number(rec.exp||0)) return json(400,"invalid_input",{message:"expired"});

  const salt = randomB64(16);
  const iter = Math.min(100000, Number(env.PBKDF2_ITER || 100000));
  const hash = await pbkdf2Hash(new_password, salt, iter);

  await env.DB.prepare(`
    UPDATE users SET password_hash=?, password_salt=?, password_iter=?, password_algo=?, updated_at=?
    WHERE id=?
  `).bind(hash, salt, iter, "pbkdf2_sha256", nowSec(), rec.uid).run();

  // revoke sessions for safety
  await env.DB.prepare(`UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`).bind(nowSec(), rec.uid).run();

  await env.KV.delete(`pwreset:${token}`);
  return json(200,"ok",{ reset:true });
}
