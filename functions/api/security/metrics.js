// App/functions/api/security/metrics.js
// POST /api/security/metrics
// Increment hourly_metrics & ip_activity counters.
// Only super_admin/admin can call (atau kamu bisa jadikan internal later).

import { json, readJson, hasRole, sha256Base64 } from "../../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }

function hourFloor(sec){
  return Math.floor(sec / 3600) * 3600;
}
function dayKey(sec){
  const d = new Date(sec * 1000);
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth()+1).padStart(2,"0");
  const dd = String(d.getUTCDate()).padStart(2,"0");
  return `${y}-${m}-${dd}`;
}
function hourId(sec){
  const d = new Date(sec * 1000);
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth()+1).padStart(2,"0");
  const dd = String(d.getUTCDate()).padStart(2,"0");
  const hh = String(d.getUTCHours()).padStart(2,"0");
  return `${y}${m}${dd}${hh}`;
}
async function ipHash(env, ip){
  return await sha256Base64(`${ip}|${env.HASH_PEPPER}`);
}
function getClientIp(req){
  return req.headers.get("cf-connecting-ip")
    || req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    || "0.0.0.0";
}

export async function onRequestPost({ env, data, request }) {
  const sess = data.session;
  if(!hasRole(sess.roles, ["super_admin","admin"])) return json(403,"forbidden",null);
  if(!env.HASH_PEPPER) return json(500,"server_error",{ message:"missing_HASH_PEPPER" });

  const b = await readJson(request);
  const metric = String(b?.metric||"").trim(); // password_fail | otp_verify_fail | session_anomaly
  const inc = Math.min(1000, Math.max(1, Number(b?.inc||1)));

  if(!["password_fail","otp_verify_fail","session_anomaly"].includes(metric)){
    return json(400,"invalid_input",{ message:"metric_invalid" });
  }

  const now = nowSec();
  const hf = hourFloor(now);
  const id = hourId(hf);
  const dk = dayKey(hf);

  // Upsert hourly_metrics
  await env.DB.prepare(`
    INSERT INTO hourly_metrics (id,day_key,hour_epoch,${metric},created_at,updated_at)
    VALUES (?,?,?,?,?,?)
    ON CONFLICT(id) DO UPDATE SET
      ${metric} = COALESCE(${metric},0) + ?,
      updated_at = excluded.updated_at
  `).bind(id, dk, hf, inc, now, now, inc).run();

  // ip_activity
  const ip = getClientIp(request);
  const h = await ipHash(env, ip);
  const windowStart = Math.floor(now/300)*300; // 5-min window
  const actId = `${metric}:${windowStart}:${h}`;

  await env.DB.prepare(`
    INSERT INTO ip_activity (id,ip_hash,kind,cnt,window_start,updated_at)
    VALUES (?,?,?,?,?,?)
    ON CONFLICT(id) DO UPDATE SET
      cnt = cnt + ?,
      updated_at = excluded.updated_at
  `).bind(actId, h, metric, inc, windowStart, now, inc).run();

  return json(200,"ok",{ metric, inc, hour_id:id, hour_epoch:hf, day_key:dk });
}
