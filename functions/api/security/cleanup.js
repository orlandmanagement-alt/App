// App/functions/api/security/cleanup.js
// POST /api/security/cleanup
// Retention cleanup for tasks/dlq/audit/ip_activity/ip_blocks
// super_admin only

import { json, hasRole } from "../../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }

export async function onRequestPost({ env, data }) {
  const sess = data.session;
  if(!hasRole(sess.roles, ["super_admin"])) return json(403,"forbidden",null);

  const now = nowSec();
  const auditDays = Number(env.RETENTION_DAYS_AUDIT || 90);
  const tasksDays = Number(env.RETENTION_DAYS_TASKS || 30);

  const auditCut = now - auditDays*86400;
  const tasksCut = now - tasksDays*86400;
  const ipActCut = now - 7*86400;
  const ipBlockCut = now - 90*86400;

  await env.DB.prepare(`DELETE FROM audit_logs WHERE created_at < ?`).bind(auditCut).run();
  await env.DB.prepare(`DELETE FROM tasks WHERE status='done' AND updated_at < ?`).bind(tasksCut).run();
  await env.DB.prepare(`DELETE FROM dlq WHERE created_at < ?`).bind(now - 90*86400).run();
  await env.DB.prepare(`DELETE FROM ip_activity WHERE window_start < ?`).bind(ipActCut).run();
  await env.DB.prepare(`
    DELETE FROM ip_blocks
    WHERE created_at < ? AND (revoked_at IS NOT NULL OR expires_at < ?)
  `).bind(ipBlockCut, now).run();

  return json(200,"ok",{ cleaned:true, auditCut, tasksCut, ipActCut, ipBlockCut });
}
