import { json, hasRole } from "../../_lib.js";
export async function onRequestGet({ env, data, request }){
  const sess=data.session;
  if(!hasRole(sess.roles, ["super_admin","admin","staff"])) return json(403,"forbidden",null);
  const url=new URL(request.url);
  const id=String(url.searchParams.get("id")||"").trim();
  if(!id) return json(400,"invalid_input",{message:"id_required"});
  const inc=await env.DB.prepare("SELECT id,severity,type,status,summary,details_json,owner_user_id,created_at,updated_at FROM incidents WHERE id=? LIMIT 1").bind(id).first();
  if(!inc) return json(404,"invalid_input",{message:"not_found"});
  return json(200,"ok",{ incident: inc });
}
