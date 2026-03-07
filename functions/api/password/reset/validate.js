import { json, readJson, requireEnv, nowSec } from "../../../_lib.js";

/**
 * POST /api/password/reset/validate
 * Body: { token }
 */
export async function onRequestPost({ request, env }){
  const miss = requireEnv(env, ["RESET_TOKEN_SECRET"]);
  if(miss.length) return json(500,"server_error",{message:"missing_env", missing:miss});

  const b = await readJson(request);
  const token = String(b?.token||"").trim();
  if(!token) return json(400,"invalid_input",null);

  const recStr = await env.KV.get(`pwreset:${token}`);
  if(!recStr) return json(400,"invalid_input",{message:"invalid_or_expired"});

  let rec=null;
  try{ rec = JSON.parse(recStr); }catch{ rec=null; }
  if(!rec?.uid || nowSec() > Number(rec.exp||0)) return json(400,"invalid_input",{message:"expired"});

  return json(200,"ok",{ valid:true });
}
