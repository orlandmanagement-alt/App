import { json, readJson, requireAuth, hasRole, nowSec, sha256Base64 } from "../../_lib.js";

/**
 * GET  /api/ip-blocks?active=1&limit=100
 * POST /api/ip-blocks/block      { ip_hash, ttl_sec, reason }
 * POST /api/ip-blocks/unblock    { id }
 * POST /api/ip-blocks/purge      {}
 */

export async function onRequestGet({ request, env }) {
  const a = await requireAuth(env, request); if (!a.ok) return a.res;
  if (!hasRole(a.roles, ["super_admin","admin"])) return json(403,"forbidden",null);

  const url = new URL(request.url);
  const active = String(url.searchParams.get("active") || "1") === "1";
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit") || "100")));

  let sql = `
    SELECT id, ip_hash, reason, expires_at, revoked_at, created_at, created_by_user_id
    FROM ip_blocks
  `;
  const binds = [];
  if (active) {
    sql += ` WHERE revoked_at IS NULL AND expires_at > ? `;
    binds.push(nowSec());
  }
  sql += ` ORDER BY created_at DESC LIMIT ? `;
  binds.push(limit);

  const r = await env.DB.prepare(sql).bind(...binds).all();
  return json(200,"ok",{ blocks: r.results || [] });
}

export async function onRequestPost({ request, env }) {
  const url = new URL(request.url);
  const p = url.pathname;

  const a = await requireAuth(env, request); if (!a.ok) return a.res;
  if (!hasRole(a.roles, ["super_admin"])) return json(403,"forbidden",null);

  const body = await readJson(request);

  if (p.endsWith("/block")) {
    const ip_hash = String(body?.ip_hash||"").trim();
    const ttl_sec = Math.min(7*86400, Math.max(60, Number(body?.ttl_sec||3600)));
    const reason = String(body?.reason||"manual_block").trim() || "manual_block";
    if (!ip_hash) return json(400,"invalid_input",{message:"ip_hash_required"});

    // KV marker optional (if KV bound)
    try { await env.KV.put(`ipblock:${ip_hash}`, reason, { expirationTtl: ttl_sec }); } catch {}

    const id = crypto.randomUUID();
    const now = nowSec();
    await env.DB.prepare(`
      INSERT INTO ip_blocks (id, ip_hash, reason, expires_at, revoked_at, created_at, created_by_user_id)
      VALUES (?,?,?,?,NULL,?,?)
    `).bind(id, ip_hash, reason, now + ttl_sec, now, a.uid).run();

    return json(200,"ok",{ blocked:true, id, expires_at: now + ttl_sec });
  }

  if (p.endsWith("/unblock")) {
    const id = String(body?.id||"").trim();
    if (!id) return json(400,"invalid_input",{message:"id_required"});

    const row = await env.DB.prepare(`SELECT ip_hash FROM ip_blocks WHERE id=? LIMIT 1`).bind(id).first();
    if (!row) return json(404,"invalid_input",{message:"not_found"});

    try { await env.KV.delete(`ipblock:${row.ip_hash}`); } catch {}

    await env.DB.prepare(`UPDATE ip_blocks SET revoked_at=? WHERE id=?`).bind(nowSec(), id).run();
    return json(200,"ok",{ unblocked:true });
  }

  if (p.endsWith("/purge")) {
    // revoke expired entries (best effort)
    const now = nowSec();
    const r = await env.DB.prepare(`
      UPDATE ip_blocks SET revoked_at=?
      WHERE revoked_at IS NULL AND expires_at <= ?
    `).bind(now, now).run();

    return json(200,"ok",{ revoked: r.meta?.changes || 0 });
  }

  return json(404,"invalid_input",{message:"Not found"});
}
