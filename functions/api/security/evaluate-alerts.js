// App/functions/api/security/evaluate-alerts.js
// POST /api/security/evaluate-alerts
// Manual trigger: scan alert_rules and create incidents if thresholds breached.
// Uses hourly_metrics (metric sums over window_minutes).
//
// Only super_admin can trigger (safe).

import { json, hasRole } from "../../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }

export async function onRequestPost({ env, data }) {
  const sess = data.session;
  if(!hasRole(sess.roles, ["super_admin"])) return json(403,"forbidden",null);

  const now = nowSec();
  const rules = await env.DB.prepare(`
    SELECT id,enabled,metric,window_minutes,threshold,severity,cooldown_minutes
    FROM alert_rules
    WHERE enabled=1
    ORDER BY created_at ASC
  `).all();

  const fired = [];
  const skipped = [];

  for (const r of (rules.results||[])) {
    const windowSec = Number(r.window_minutes||15) * 60;
    const since = now - windowSec;

    // sum metric in window from hourly_metrics by hour_epoch
    const q = await env.DB.prepare(`
      SELECT SUM(COALESCE(${r.metric},0)) AS v
      FROM hourly_metrics
      WHERE hour_epoch >= ?
    `).bind(since).first();

    const v = Number(q?.v || 0);
    if (v < Number(r.threshold||0)) {
      skipped.push({ rule_id:r.id, value:v, reason:"below_threshold" });
      continue;
    }

    // cooldown: avoid spamming incidents
    const cooldownSec = Number(r.cooldown_minutes||60) * 60;
    const recent = await env.DB.prepare(`
      SELECT 1 AS ok
      FROM incidents
      WHERE type=? AND created_at >= ?
      LIMIT 1
    `).bind(`alert_${r.metric}`, now - cooldownSec).first();

    if (recent) {
      skipped.push({ rule_id:r.id, value:v, reason:"cooldown" });
      continue;
    }

    const incId = crypto.randomUUID();
    const summary = `Alert ${r.metric}: value=${v} >= threshold=${r.threshold} (window=${r.window_minutes}m)`;

    await env.DB.prepare(`
      INSERT INTO incidents (id,severity,type,summary,status,owner_user_id,details_json,created_at,updated_at)
      VALUES (?,?,?,?,?,?,?,?,?)
    `).bind(
      incId,
      r.severity,
      `alert_${r.metric}`,
      summary,
      "open",
      null,
      JSON.stringify({ rule_id:r.id, value:v, threshold:r.threshold, window_minutes:r.window_minutes }),
      now,
      now
    ).run();

    fired.push({ rule_id:r.id, incident_id:incId, value:v });
  }

  return json(200,"ok",{ fired, skipped });
}
