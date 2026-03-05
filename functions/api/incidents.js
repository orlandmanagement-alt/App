// App/functions/api/incidents.js
// /api/incidents
// GET  : list incidents
// POST : create incident (admin/super_admin)
// PUT  : actions (admin/super_admin)
// GET /api/incidents/get?id=... (detail)

import { json, readJson, hasRole } from "../_lib.js";

function nowSec() { return Math.floor(Date.now() / 1000); }

function canRead(sess) {
  return hasRole(sess.roles, ["super_admin", "admin", "staff"]);
}
function canWrite(sess) {
  return hasRole(sess.roles, ["super_admin", "admin"]);
}

function cleanSeverity(s) {
  const v = String(s || "").trim().toLowerCase();
  if (["low", "medium", "high", "critical"].includes(v)) return v;
  return "";
}
function cleanStatus(s) {
  const v = String(s || "").trim().toLowerCase();
  // allow known statuses
  const ok = ["open", "ack", "closed", "resolved", "investigating"].includes(v);
  return ok ? v : "";
}
function cleanType(s) {
  const t = String(s || "").trim();
  if (!t || t.length > 80) return "";
  return t;
}
function cleanSummary(s) {
  const t = String(s || "").trim();
  if (!t || t.length > 240) return "";
  return t;
}

export async function onRequestGet({ env, data, request }) {
  const sess = data.session;
  if (!canRead(sess)) return json(403, "forbidden", null);

  const url = new URL(request.url);
  const q = String(url.searchParams.get("q") || "").trim();
  const status = String(url.searchParams.get("status") || "").trim().toLowerCase();
  const severity = String(url.searchParams.get("severity") || "").trim().toLowerCase();
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit") || "20")));

  let sql = `SELECT id,severity,type,status,summary,owner_user_id,created_at,updated_at
             FROM incidents`;
  const wh = [];
  const binds = [];

  if (q) {
    wh.push("(type LIKE ? OR summary LIKE ?)");
    binds.push(`%${q}%`, `%${q}%`);
  }
  if (status) {
    wh.push("status=?");
    binds.push(status);
  }
  if (severity) {
    wh.push("severity=?");
    binds.push(severity);
  }

  if (wh.length) sql += " WHERE " + wh.join(" AND ");
  sql += " ORDER BY created_at DESC LIMIT ?";
  binds.push(limit);

  const r = await env.DB.prepare(sql).bind(...binds).all();
  return json(200, "ok", { incidents: r.results || [] });
}

// detail
export async function onRequestGet2({ env, data, request }) {
  const sess = data.session;
  if (!canRead(sess)) return json(403, "forbidden", null);

  const url = new URL(request.url);
  const id = String(url.searchParams.get("id") || "").trim();
  if (!id) return json(400, "invalid_input", { message: "id_required" });

  const inc = await env.DB.prepare(
    `SELECT id,severity,type,status,summary,owner_user_id,details_json,created_at,updated_at
     FROM incidents WHERE id=? LIMIT 1`
  ).bind(id).first();

  if (!inc) return json(404, "invalid_input", { message: "not_found" });
  return json(200, "ok", { incident: inc });
}

// Create
export async function onRequestPost({ env, data, request }) {
  const sess = data.session;
  if (!canWrite(sess)) return json(403, "forbidden", null);

  const b = await readJson(request);
  const severity = cleanSeverity(b?.severity) || "medium";
  const type = cleanType(b?.type);
  const summary = cleanSummary(b?.summary);
  const details_json = b?.details_json != null ? JSON.stringify(b.details_json) : null;

  if (!type || !summary) return json(400, "invalid_input", { message: "type_and_summary_required" });

  const id = crypto.randomUUID();
  const now = nowSec();

  await env.DB.prepare(
    `INSERT INTO incidents (id,severity,type,summary,status,owner_user_id,details_json,created_at,updated_at)
     VALUES (?,?,?,?,?,?,?,?,?)`
  ).bind(
    id,
    severity,
    type,
    summary,
    "open",
    null,
    details_json,
    now,
    now
  ).run();

  return json(200, "ok", { created: true, id });
}

// Actions
// PUT body:
// { action:"ack"|"assign"|"close"|"reopen"|"update", id, owner_user_id?, summary?, severity?, type?, status?, details_json? }
export async function onRequestPut({ env, data, request }) {
  const sess = data.session;
  if (!canWrite(sess)) return json(403, "forbidden", null);

  const b = await readJson(request);
  const action = String(b?.action || "").trim().toLowerCase();
  const id = String(b?.id || "").trim();
  if (!id || !action) return json(400, "invalid_input", { message: "id_and_action_required" });

  const now = nowSec();

  const exists = await env.DB.prepare("SELECT id,status FROM incidents WHERE id=? LIMIT 1").bind(id).first();
  if (!exists) return json(404, "invalid_input", { message: "not_found" });

  if (action === "ack") {
    await env.DB.prepare(
      "UPDATE incidents SET status='ack', owner_user_id=COALESCE(owner_user_id, ?), updated_at=? WHERE id=?"
    ).bind(sess.uid, now, id).run();
    return json(200, "ok", { ack: true });
  }

  if (action === "assign") {
    const owner_user_id = String(b?.owner_user_id || "").trim();
    if (!owner_user_id) return json(400, "invalid_input", { message: "owner_user_id_required" });
    await env.DB.prepare(
      "UPDATE incidents SET owner_user_id=?, status=CASE WHEN status='open' THEN 'ack' ELSE status END, updated_at=? WHERE id=?"
    ).bind(owner_user_id, now, id).run();
    return json(200, "ok", { assigned: true });
  }

  if (action === "close") {
    await env.DB.prepare(
      "UPDATE incidents SET status='closed', updated_at=? WHERE id=?"
    ).bind(now, id).run();
    return json(200, "ok", { closed: true });
  }

  if (action === "reopen") {
    await env.DB.prepare(
      "UPDATE incidents SET status='open', updated_at=? WHERE id=?"
    ).bind(now, id).run();
    return json(200, "ok", { reopened: true });
  }

  if (action === "update") {
    const severity = b?.severity != null ? cleanSeverity(b.severity) : "";
    const status = b?.status != null ? cleanStatus(b.status) : "";
    const type = b?.type != null ? cleanType(b.type) : "";
    const summary = b?.summary != null ? cleanSummary(b.summary) : "";
    const details_json = b?.details_json != null ? JSON.stringify(b.details_json) : null;

    // build dynamic update
    const sets = ["updated_at=?"];
    const binds = [now];

    if (severity) { sets.push("severity=?"); binds.push(severity); }
    if (status) { sets.push("status=?"); binds.push(status); }
    if (type) { sets.push("type=?"); binds.push(type); }
    if (summary) { sets.push("summary=?"); binds.push(summary); }
    if (details_json !== null) { sets.push("details_json=?"); binds.push(details_json); }

    binds.push(id);

    await env.DB.prepare(`UPDATE incidents SET ${sets.join(", ")} WHERE id=?`)
      .bind(...binds)
      .run();

    return json(200, "ok", { updated: true });
  }

  return json(400, "invalid_input", { message: "unknown_action" });
}
