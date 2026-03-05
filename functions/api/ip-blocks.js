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
  // hash only (no raw ip stored)
  return await sha256Base64(`${ip}|${env.HASH_PEPPER}`);
}

export async function onRequestGet({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin", "admin"])) return json(403, "forbidden", null);

  const url = new URL(request.url);
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit") || "100")));
  const activeOnly = String(url.searchParams.get("active") || "true") === "true";

  let sql = `SELECT id,ip_hash,reason,expires_at,revoked_at,created_at,created_by_user_id
             FROM ip_blocks`;
  const binds = [];
  if (activeOnly) {
    sql += ` WHERE revoked_at IS NULL AND expires_at > ?`;
    binds.push(nowSec());
  }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  binds.push(limit);

  const r = await env.DB.prepare(sql).bind(...binds).all();
  return json(200, "ok", { blocks: r.results || [] });
}

// POST actions: block / unblock
export async function onRequestPost({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin"])) return json(403, "forbidden", null);
  if (!env.HASH_PEPPER) return json(500, "server_error", { message: "missing_HASH_PEPPER" });
  if (!env.KV) return json(500, "server_error", { message: "missing_KV_binding" });

  const b = await readJson(request);
  const action = String(b?.action || "").trim();

  if (action === "block") {
    // allow block by ip OR by ip_hash
    const ip = b?.ip ? String(b.ip).trim() : null;
    const ip_hash = b?.ip_hash ? String(b.ip_hash).trim() : null;

    const ttl_sec = Math.min(7 * 86400, Math.max(60, Number(b?.ttl_sec || 3600)));
    const reason = String(b?.reason || "manual_block").trim();

    const finalHash = ip_hash || (ip ? await ipHash(env, ip) : "");
    if (!finalHash) return json(400, "invalid_input", { message: "provide ip or ip_hash" });

    // KV enforcement key
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
    const id = String(b?.id || "").trim();
    const ip_hash = b?.ip_hash ? String(b.ip_hash).trim() : null;
    if (!id && !ip_hash) return json(400, "invalid_input", { message: "provide id or ip_hash" });

    let finalHash = ip_hash;

    if (id) {
      const row = await env.DB.prepare("SELECT ip_hash FROM ip_blocks WHERE id=? LIMIT 1").bind(id).first();
      if (!row) return json(404, "invalid_input", { message: "not_found" });
      finalHash = row.ip_hash;

      await env.DB.prepare("UPDATE ip_blocks SET revoked_at=? WHERE id=?").bind(nowSec(), id).run();
    } else {
      // revoke latest active record by hash (best effort)
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

  if (action === "check_my_ip") {
    // admin can check (debug)
    if (!hasRole(sess.roles, ["super_admin", "admin"])) return json(403, "forbidden", null);
    const ip = getClientIp(request);
    const h = await ipHash(env, ip);
    const v = await env.KV.get(`ipblock:${h}`);
    return json(200, "ok", { ip_hash: h, blocked: !!v, reason: v || null });
  }

  return json(400, "invalid_input", { message: "unknown_action" });
}
