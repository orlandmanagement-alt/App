import { json, readJson, hasRole, audit } from "../_lib.js";
function nowSec(){ return Math.floor(Date.now()/1000); }
function canRW(sess){ return hasRole(sess.roles, ["super_admin","admin"]); }

export async function onRequestGet({ env, data, request }){
  const sess=data.session;
  if(!hasRole(sess.roles, ["super_admin","admin","staff"])) return json(403,"forbidden",null);
  const url=new URL(request.url);
  const q=String(url.searchParams.get("q")||"").trim();
  const limit=Math.min(200, Math.max(1, Number(url.searchParams.get("limit")||"20")));
  let sql="SELECT id,severity,type,status,summary,owner_user_id,created_at,updated_at FROM incidents";
  const binds=[];
  if(q){ sql += " WHERE type LIKE ? OR summary LIKE ?"; binds.push(`%${q}%`,`%${q}%`); }
  sql += " ORDER BY created_at DESC LIMIT ?"; binds.push(limit);
  const r=await env.DB.prepare(sql).bind(...binds).all();
  return json(200,"ok",{ incidents:r.results||[] });
}

export async function onRequestPost({ env, data, request }){
  const sess=data.session;
  if(!canRW(sess)) return json(403,"forbidden",null);
  const b=await readJson(request);
  const severity=String(b?.severity||"medium").trim();
  const type=String(b?.type||"sec_manual").trim();
  const summary=String(b?.summary||"").trim();
  const details_json=b?.details_json ? JSON.stringify(b.details_json) : null;
  if(!summary || !type) return json(400,"invalid_input",{message:"type & summary required"});
  if(!["low","medium","high","critical"].includes(severity)) return json(400,"invalid_input",{message:"bad severity"});

  const id=crypto.randomUUID();
  const now=nowSec();
  await env.DB.prepare("INSERT INTO incidents (id,severity,type,status,summary,details_json,created_at,updated_at,owner_user_id) VALUES (?,?,?,?,?,?,?, ?, NULL)")
    .bind(id,severity,type,"open",summary,details_json,now,now).run();
  await audit(env,{actor_user_id:sess.uid, action:"incident.create", target_type:"incident", target_id:id, meta:{severity,type}});
  return json(200,"ok",{ created:true, id });
}

export async function onRequestPut({ env, data, request }){
  const sess=data.session;
  if(!canRW(sess)) return json(403,"forbidden",null);
  const b=await readJson(request);
  const action=String(b?.action||"").trim();
  const id=String(b?.id||"").trim();
  if(!action||!id) return json(400,"invalid_input",{message:"action & id required"});
  const now=nowSec();

  if(action==="ack"){
    await env.DB.prepare("UPDATE incidents SET status='ack', owner_user_id=COALESCE(owner_user_id,?), updated_at=? WHERE id=?").bind(sess.uid, now, id).run();
    await audit(env,{actor_user_id:sess.uid, action:"incident.ack", target_type:"incident", target_id:id, meta:{}});
    return json(200,"ok",{ updated:true });
  }
  if(action==="close"){
    await env.DB.prepare("UPDATE incidents SET status='closed', updated_at=? WHERE id=?").bind(now, id).run();
    await audit(env,{actor_user_id:sess.uid, action:"incident.close", target_type:"incident", target_id:id, meta:{}});
    return json(200,"ok",{ updated:true });
  }
  if(action==="assign"){
    const owner_user_id=String(b?.owner_user_id||"").trim();
    if(!owner_user_id) return json(400,"invalid_input",{message:"owner_user_id required"});
    await env.DB.prepare("UPDATE incidents SET owner_user_id=?, updated_at=? WHERE id=?").bind(owner_user_id, now, id).run();
    await audit(env,{actor_user_id:sess.uid, action:"incident.assign", target_type:"incident", target_id:id, meta:{owner_user_id}});
    return json(200,"ok",{ updated:true });
  }
  return json(400,"invalid_input",{message:"unknown_action"});
}
