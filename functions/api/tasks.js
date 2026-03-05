// App/functions/api/tasks.js
// GET  /api/tasks?status=&type=&limit=
// POST /api/tasks  { type, payload, delay_sec }  (super_admin only)

import { json, readJson, hasRole } from "../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }
function canRead(sess){ return hasRole(sess.roles, ["super_admin","admin"]); }
function onlySuperAdmin(sess){ return hasRole(sess.roles, ["super_admin"]); }

function validType(t){
  return ["notify_incident","cleanup","backup","custom"].includes(t);
}

export async function onRequestGet({ env, data, request }){
  const sess = data.session;
  if(!canRead(sess)) return json(403,"forbidden",null);

  const url = new URL(request.url);
  const status = String(url.searchParams.get("status")||"").trim();
  const type = String(url.searchParams.get("type")||"").trim();
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit")||"50")));

  let sql = `SELECT id,type,status,attempts,next_run_at,last_error,created_at,updated_at FROM tasks`;
  const wh = [];
  const binds = [];

  if(status){ wh.push("status=?"); binds.push(status); }
  if(type){ wh.push("type=?"); binds.push(type); }
  if(wh.length) sql += " WHERE " + wh.join(" AND ");
  sql += " ORDER BY created_at DESC LIMIT ?";
  binds.push(limit);

  const r = await env.DB.prepare(sql).bind(...binds).all();
  return json(200,"ok",{ tasks: r.results || [] });
}

export async function onRequestPost({ env, data, request }){
  const sess = data.session;
  if(!onlySuperAdmin(sess)) return json(403,"forbidden",null);

  const b = await readJson(request);
  const type = String(b?.type||"").trim();
  const payload = b?.payload ?? {};
  const delay_sec = Math.min(86400, Math.max(0, Number(b?.delay_sec||0)));

  if(!validType(type)) return json(400,"invalid_input",{ message:"type_invalid" });

  const id = crypto.randomUUID();
  const now = nowSec();
  const next_run_at = now + delay_sec;

  await env.DB.prepare(`
    INSERT INTO tasks (id,type,payload_json,status,attempts,next_run_at,last_error,created_at,updated_at)
    VALUES (?,?,?,'queued',0,?,NULL,?,?)
  `).bind(id, type, JSON.stringify(payload), next_run_at, now, now).run();

  return json(200,"ok",{ enqueued:true, id, type, next_run_at });
}
