// App/functions/api/alert-rules.js
// /api/alert-rules
// GET    : list rules (super_admin/admin)
// POST   : create rule (super_admin)
// PUT    : update rule (super_admin)
// DELETE : delete rule (super_admin)

import { json, readJson, hasRole } from "../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }
function canRead(sess){ return hasRole(sess.roles, ["super_admin","admin"]); }
function onlySuperAdmin(sess){ return hasRole(sess.roles, ["super_admin"]); }

function cleanMetric(s){
  const v = String(s||"").trim();
  // allow only known metrics
  const ok = ["password_fail","otp_verify_fail","session_anomaly"].includes(v);
  return ok ? v : "";
}
function cleanSeverity(s){
  const v = String(s||"").trim().toLowerCase();
  return ["low","medium","high","critical"].includes(v) ? v : "";
}

export async function onRequestGet({ env, data }){
  const sess = data.session;
  if(!canRead(sess)) return json(403,"forbidden",null);

  const r = await env.DB.prepare(`
    SELECT id,enabled,metric,window_minutes,threshold,severity,cooldown_minutes,created_at,updated_at
    FROM alert_rules
    ORDER BY created_at DESC
  `).all();

  return json(200,"ok",{ rules: r.results || [] });
}

export async function onRequestPost({ env, data, request }){
  const sess = data.session;
  if(!onlySuperAdmin(sess)) return json(403,"forbidden",null);

  const b = await readJson(request);
  const metric = cleanMetric(b?.metric);
  const window_minutes = Math.min(1440, Math.max(1, Number(b?.window_minutes||15)));
  const threshold = Math.max(1, Number(b?.threshold||10));
  const severity = cleanSeverity(b?.severity) || "medium";
  const cooldown_minutes = Math.min(1440, Math.max(1, Number(b?.cooldown_minutes||60)));
  const enabled = Number(b?.enabled ?? 1) ? 1 : 0;

  if(!metric) return json(400,"invalid_input",{ message:"metric_invalid" });

  const id = crypto.randomUUID();
  const now = nowSec();

  await env.DB.prepare(`
    INSERT INTO alert_rules (id,enabled,metric,window_minutes,threshold,severity,cooldown_minutes,created_at,updated_at)
    VALUES (?,?,?,?,?,?,?,?,?)
  `).bind(id, enabled, metric, window_minutes, threshold, severity, cooldown_minutes, now, now).run();

  return json(200,"ok",{ created:true, id });
}

export async function onRequestPut({ env, data, request }){
  const sess = data.session;
  if(!onlySuperAdmin(sess)) return json(403,"forbidden",null);

  const b = await readJson(request);
  const id = String(b?.id||"").trim();
  if(!id) return json(400,"invalid_input",{ message:"id_required" });

  const now = nowSec();

  // Optional fields
  const enabled = (b?.enabled == null) ? null : (Number(b.enabled) ? 1 : 0);
  const metric = (b?.metric == null) ? null : cleanMetric(b.metric);
  const window_minutes = (b?.window_minutes == null) ? null : Math.min(1440, Math.max(1, Number(b.window_minutes)));
  const threshold = (b?.threshold == null) ? null : Math.max(1, Number(b.threshold));
  const severity = (b?.severity == null) ? null : (cleanSeverity(b.severity) || "");
  const cooldown_minutes = (b?.cooldown_minutes == null) ? null : Math.min(1440, Math.max(1, Number(b.cooldown_minutes)));

  if (metric === "") return json(400,"invalid_input",{ message:"metric_invalid" });
  if (severity === "") return json(400,"invalid_input",{ message:"severity_invalid" });

  const sets = ["updated_at=?"];
  const binds = [now];

  if (enabled !== null) { sets.push("enabled=?"); binds.push(enabled); }
  if (metric !== null) { sets.push("metric=?"); binds.push(metric); }
  if (window_minutes !== null) { sets.push("window_minutes=?"); binds.push(window_minutes); }
  if (threshold !== null) { sets.push("threshold=?"); binds.push(threshold); }
  if (severity !== null) { sets.push("severity=?"); binds.push(severity); }
  if (cooldown_minutes !== null) { sets.push("cooldown_minutes=?"); binds.push(cooldown_minutes); }

  binds.push(id);

  await env.DB.prepare(`UPDATE alert_rules SET ${sets.join(", ")} WHERE id=?`).bind(...binds).run();
  return json(200,"ok",{ updated:true });
}

export async function onRequestDelete({ env, data, request }){
  const sess = data.session;
  if(!onlySuperAdmin(sess)) return json(403,"forbidden",null);

  const url = new URL(request.url);
  const id = String(url.searchParams.get("id")||"").trim();
  if(!id) return json(400,"invalid_input",{ message:"id_required" });

  await env.DB.prepare(`DELETE FROM alert_rules WHERE id=?`).bind(id).run();
  return json(200,"ok",{ deleted:true });
}
