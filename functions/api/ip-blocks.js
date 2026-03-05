// App/functions/api/ip-blocks.js
// CRUD IP Blocks (D1 + KV)
// - GET  /api/ip-blocks?active=true&limit=200
// - POST /api/ip-blocks { action:"block", ip:"1.2.3.4" OR ip_hash:"...", ttl_sec, reason }
// - POST /api/ip-blocks { action:"unblock", id:"..." OR ip_hash:"..." }
// - GET  /api/ip-blocks/check?ip_hash=...

import { json, readJson, hasRole, sha256Base64 } from "../_lib.js";

function nowSec() { return Math.floor(Date.now() / 1000); }

function getClientIp(req) {
  return (
    req.headers.get("cf-connecting-ip") ||
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    "0.0.0.0"
  );
}

async function ipHash(env, ip) {
  return await sha256Base64(`${ip}|${env.HASH_PEPPER}`);
}

function canRead(sess) {
  return hasRole(sess.roles, ["super_admin", "admin"]);
}
function onlySuperAdmin(sess) {
  return hasRole(sess.roles, ["super_admin"]);
}

// ---------- GET list ----------
export async function onRequestGet({ env, data, request }) {
  const sess = data.session;
  if (!canRead(sess)) return json(403, "forbidden", null);

  const url = new URL(request.url);
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit") || "200")));
  const activeOnly = String(url.searchParams.get("active") || "true") === "true";

  let sql = `
    SELECT id, ip_hash, reason, expires_at, revoked_at, created_at, created_by_user_id
    FROM ip_blocks
  `;
  const binds = [];

  if (activeOnly) {
    sql += ` WHERE revoked_at IS NULL AND expires_at > ? `;
    binds.push(nowSec());
  }
  sql += ` ORDER BY created_at DESC LIMIT ? `;
  binds.push(limit);

  const r = await env.DB.prepare(sql).bind(...binds).all();
  return json(200, "ok", { blocks: r.results || [] });
}

// ---------- GET check ----------
export async function onRequestGet2({ env, data, request }) {
  const sess = data.session;
  if (!canRead(sess)) return json(403, "forbidden", null);

  const url = new URL(request.url);
  const ip_hash = String(url.searchParams.get("ip_hash") || "").trim();
  if (!ip_hash) return json(400, "invalid_input", { message: "ip_hash_required" });

  const v = await env.KV.get(`ipblock:${ip_hash}`);
  return json(200, "ok", { blocked: !!v, reason: v || null });
}

// Pages routing butuh file terpisah untuk /check
// Jadi buat file khusus: api/ip-blocks/check.js (di bawah)

// ---------- POST actions ----------
export async function onRequestPost({ env, data, request }) {
  const sess = data.session;
  const b = await readJson(request);
  const action = String(b?.action || "").trim();

  if (!env.KV) return json(500, "server_error", { message: "missing_binding_KV" });
  if (!env.HASH_PEPPER) return json(500, "server_error", { message: "missing_HASH_PEPPER" });

  if (action === "block") {
    if (!onlySuperAdmin(sess)) return json(403, "forbidden", null);

    const ip = b?.ip ? String(b.ip).trim() : null;
    const ip_hash_in = b?.ip_hash ? String(b.ip_hash).trim() : null;

    const ttl_sec = Math.min(7 * 86400, Math.max(60, Number(b?.ttl_sec || 3600)));
    const reason = String(b?.reason || "manual_block").trim();

    const finalHash = ip_hash_in || (ip ? await ipHash(env, ip) : "");
    if (!finalHash) return json(400, "invalid_input", { message: "provide ip or ip_hash" });

    // KV enforcement
    await env.KV.put(`ipblock:${finalHash}`, reason, { expirationTtl: ttl_sec });

    // D1 record
    const id = crypto.randomUUID();
    const now = nowSec();
    const expires_at = now + ttl_sec;

    await env.DB.prepare(
      `INSERT INTO ip_blocks (id,ip_hash,reason,expires_at,revoked_at,created_at,created_by_user_id)
       VALUES (?,?,?,?,NULL,?,?)`
    ).bind(id, finalHash, reason, expires_at, now, sess.uid).run();

    return json(200, "ok", { blocked: true, id, ip_hash: finalHash, expires_at });
  }

  if (action === "unblock") {
    if (!onlySuperAdmin(sess)) return json(403, "forbidden", null);

    const id = b?.id ? String(b.id).trim() : "";
    const ip_hash_in = b?.ip_hash ? String(b.ip_hash).trim() : "";

    if (!id && !ip_hash_in) return json(400, "invalid_input", { message: "provide id or ip_hash" });

    let finalHash = ip_hash_in;

    if (id) {
      const row = await env.DB.prepare("SELECT ip_hash FROM ip_blocks WHERE id=? LIMIT 1").bind(id).first();
      if (!row) return json(404, "invalid_input", { message: "not_found" });
      finalHash = row.ip_hash;

      await env.DB.prepare("UPDATE ip_blocks SET revoked_at=? WHERE id=?").bind(nowSec(), id).run();
    } else {
      const now = nowSec();
      await env.DB.prepare(`
        UPDATE ip_blocks SET revoked_at=?
        WHERE id IN (
          SELECT id FROM ip_blocks
          WHERE ip_hash=? AND revoked_at IS NULL AND expires_at > ?
          ORDER BY created_at DESC LIMIT 1
        )
      `).bind(now, finalHash, now).run();
    }

    await env.KV.delete(`ipblock:${finalHash}`);
    return json(200, "ok", { unblocked: true, ip_hash: finalHash });
  }

  if (action === "block_my_ip") {
    // convenience for testing (super_admin)
    if (!onlySuperAdmin(sess)) return json(403, "forbidden", null);

    const ttl_sec = Math.min(3600, Math.max(60, Number(b?.ttl_sec || 300)));
    const reason = String(b?.reason || "test_block_my_ip").trim();

    const ip = getClientIp(request);
    const h = await ipHash(env, ip);

    await env.KV.put(`ipblock:${h}`, reason, { expirationTtl: ttl_sec });

    const id = crypto.randomUUID();
    const now = nowSec();
    await env.DB.prepare(
      `INSERT INTO ip_blocks (id,ip_hash,reason,expires_at,revoked_at,created_at,created_by_user_id)
       VALUES (?,?,?,?,NULL,?,?)`
    ).bind(id, h, reason, now + ttl_sec, now, sess.uid).run();

    return json(200, "ok", { blocked: true, id, ip_hash: h, ttl_sec });
  }

  return json(400, "invalid_input", { message: "unknown_action" });
}
