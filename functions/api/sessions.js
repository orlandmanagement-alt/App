import { json, readJson, hasRole } from "../_lib.js";

function nowSec() { return Math.floor(Date.now() / 1000); }

export async function onRequestGet({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin", "admin"])) return json(403, "forbidden", null);

  const url = new URL(request.url);
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit") || "50")));
  const user_id = String(url.searchParams.get("user_id") || "").trim();

  let sql = `SELECT id,user_id,created_at,expires_at,revoked_at,last_seen_at,ip_hash,ua_hash,ip_prefix_hash
             FROM sessions`;
  const wh = [];
  const binds = [];

  if (user_id) { wh.push("user_id=?"); binds.push(user_id); }
  if (wh.length) sql += " WHERE " + wh.join(" AND ");
  sql += " ORDER BY created_at DESC LIMIT ?";
  binds.push(limit);

  const r = await env.DB.prepare(sql).bind(...binds).all();
  return json(200, "ok", { sessions: r.results || [] });
}

// revoke session by id (super_admin only)
export async function onRequestPost({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin"])) return json(403, "forbidden", null);

  const b = await readJson(request);
  const action = String(b?.action || "").trim();
  const id = String(b?.id || "").trim();

  if (action !== "revoke" || !id) return json(400, "invalid_input", { message: "use {action:'revoke', id}" });

  await env.DB.prepare("UPDATE sessions SET revoked_at=? WHERE id=?").bind(nowSec(), id).run();
  return json(200, "ok", { revoked: true });
}
