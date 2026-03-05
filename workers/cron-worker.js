// workers/cron-worker.js
// Cron Worker for Orland Management
// - Process tasks table (queued jobs)
// - Evaluate alert rules & create incidents
// - Optional cleanup retention
//
// Bindings required (Wrangler):
// - DB (D1) -> same DB as Pages project
// - KV (KV) -> optional (only if some tasks need KV)
//
// Vars:
// - CRON_PROCESS_TASKS="true|false"
// - CRON_EVAL_ALERTS="true|false"
// - CRON_CLEANUP="true|false"

export default {
  async fetch(req, env) {
    // optional manual trigger (protected by a secret token if you want)
    return new Response("ok");
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(runCron(env));
  },
};

function nowSec() { return Math.floor(Date.now() / 1000); }

async function runCron(env) {
  const doTasks = String(env.CRON_PROCESS_TASKS || "true") === "true";
  const doAlerts = String(env.CRON_EVAL_ALERTS || "true") === "true";
  const doCleanup = String(env.CRON_CLEANUP || "false") === "true";

  if (doTasks) await processTasks(env, 10);
  if (doAlerts) await evaluateAlerts(env);
  if (doCleanup) await cleanupRetention(env);
}

/* =========================
 * TASK PROCESSOR (tasks + dlq)
 * ========================= */

function validTaskType(t) {
  return ["notify_incident", "cleanup", "backup", "custom"].includes(t);
}

async function processTasks(env, limit = 10) {
  const now = nowSec();

  const r = await env.DB.prepare(
    `SELECT id,type,payload_json,attempts,next_run_at
     FROM tasks
     WHERE status='queued' AND next_run_at<=?
     ORDER BY next_run_at ASC
     LIMIT ?`
  ).bind(now, limit).all();

  for (const t of (r.results || [])) {
    try {
      await env.DB.prepare(`UPDATE tasks SET status='processing', updated_at=? WHERE id=?`)
        .bind(nowSec(), t.id).run();

      if (!validTaskType(t.type)) throw new Error("unknown_task_type");

      const payload = JSON.parse(t.payload_json || "{}");

      // dispatch
      if (t.type === "cleanup") await cleanupRetention(env);
      else if (t.type === "notify_incident") await taskNotifyIncident(env, payload);
      else {
        // backup/custom placeholder
      }

      await env.DB.prepare(`UPDATE tasks SET status='done', updated_at=? WHERE id=?`)
        .bind(nowSec(), t.id).run();
    } catch (e) {
      const attempts = Number(t.attempts || 0) + 1;
      const err = String(e?.message || e).slice(0, 500);

      if (attempts >= 5) {
        await env.DB.prepare(
          `INSERT INTO dlq (id,task_id,type,payload_json,error,created_at)
           VALUES (?,?,?,?,?,?)`
        ).bind(crypto.randomUUID(), t.id, t.type, t.payload_json, err, nowSec()).run();

        await env.DB.prepare(
          `UPDATE tasks SET status='dlq', attempts=?, last_error=?, updated_at=? WHERE id=?`
        ).bind(attempts, err, nowSec(), t.id).run();
      } else {
        const backoff = Math.min(3600, (2 ** attempts) * 30);
        const nextRun = nowSec() + backoff;

        await env.DB.prepare(
          `UPDATE tasks SET status='queued', attempts=?, last_error=?, next_run_at=?, updated_at=? WHERE id=?`
        ).bind(attempts, err, nextRun, nowSec(), t.id).run();
      }
    }
  }
}

/* =========================
 * ALERT EVALUATION (auto create incidents)
 * Uses: alert_rules + hourly_metrics + incidents
 * ========================= */

async function evaluateAlerts(env) {
  const now = nowSec();
  const rules = await env.DB.prepare(`
    SELECT id,enabled,metric,window_minutes,threshold,severity,cooldown_minutes
    FROM alert_rules
    WHERE enabled=1
    ORDER BY created_at ASC
  `).all();

  for (const r of (rules.results || [])) {
    const windowSec = Number(r.window_minutes || 15) * 60;
    const since = now - windowSec;

    // hourly_metrics schema: hour_epoch + metric columns
    const q = await env.DB.prepare(`
      SELECT SUM(COALESCE(${r.metric},0)) AS v
      FROM hourly_metrics
      WHERE hour_epoch >= ?
    `).bind(since).first();

    const v = Number(q?.v || 0);
    if (v < Number(r.threshold || 0)) continue;

    // cooldown check (avoid repeat)
    const cooldownSec = Number(r.cooldown_minutes || 60) * 60;
    const recent = await env.DB.prepare(`
      SELECT 1 AS ok
      FROM incidents
      WHERE type=? AND created_at >= ?
      LIMIT 1
    `).bind(`alert_${r.metric}`, now - cooldownSec).first();

    if (recent) continue;

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
      JSON.stringify({ rule_id: r.id, value: v, threshold: r.threshold, window_minutes: r.window_minutes }),
      now,
      now
    ).run();

    // enqueue notify task (optional)
    await enqueueTask(env, "notify_incident", { incident_id: incId }, 0);
  }
}

async function enqueueTask(env, type, payload, delay_sec = 0) {
  const id = crypto.randomUUID();
  const now = nowSec();
  await env.DB.prepare(
    `INSERT INTO tasks (id,type,payload_json,status,attempts,next_run_at,last_error,created_at,updated_at)
     VALUES (?,?,?,'queued',0,?,NULL,?,?)`
  ).bind(id, type, JSON.stringify(payload || {}), now + delay_sec, now, now).run();
  return id;
}

/* =========================
 * NOTIFY INCIDENT (placeholder)
 * You can integrate WhatsApp/Twilio later
 * ========================= */

async function taskNotifyIncident(env, payload) {
  const incident_id = String(payload?.incident_id || "").trim();
  if (!incident_id) throw new Error("invalid_payload_incident_id");

  // for now: just mark updated_at (or do nothing)
  await env.DB.prepare(`UPDATE incidents SET updated_at=? WHERE id=?`)
    .bind(nowSec(), incident_id).run();
}

/* =========================
 * RETENTION CLEANUP
 * ========================= */

async function cleanupRetention(env) {
  const now = nowSec();
  const auditDays = Number(env.RETENTION_DAYS_AUDIT || 90);
  const tasksDays = Number(env.RETENTION_DAYS_TASKS || 30);

  const auditCut = now - auditDays * 86400;
  const tasksCut = now - tasksDays * 86400;

  await env.DB.prepare(`DELETE FROM audit_logs WHERE created_at < ?`).bind(auditCut).run();
  await env.DB.prepare(`DELETE FROM tasks WHERE status='done' AND updated_at < ?`).bind(tasksCut).run();
  await env.DB.prepare(`DELETE FROM dlq WHERE created_at < ?`).bind(now - 90 * 86400).run();
  await env.DB.prepare(`DELETE FROM ip_activity WHERE window_start < ?`).bind(now - 7 * 86400).run();
  await env.DB.prepare(`
    DELETE FROM ip_blocks
    WHERE created_at < ? AND (revoked_at IS NOT NULL OR expires_at < ?)
  `).bind(now - 90 * 86400, now).run();
}
