import { json, readJson, hasRole, sha256Base64 } from "../../_lib.js";

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

export async function onRequestGet({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin", "admin"])) return json(403, "forbidden", null);

  const ip = getClientIp(request);
  const h = await ipHash(env, ip);
  const reason = await env.KV.get(`ipblock:${h}`);

  return json(200, "ok", { ip_hash: h, blocked: !!reason, reason: reason || null });
}

export async function onRequestPost({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin"])) return json(403, "forbidden", null);

  const b = await readJson(request);
  const action = String(b?.action || "").trim();

  const ip = getClientIp(request);
  const h = await ipHash(env, ip);

  if (action === "block_my_ip") {
    const ttl_sec = Math.min(86400, Math.max(60, Number(b?.ttl_sec || 600)));
    const reason = String(b?.reason || "test_block").trim();

    await env.KV.put(`ipblock:${h}`, reason, { expirationTtl: ttl_sec });

    const id = crypto.randomUUID();
    const now = nowSec();
    await env.DB.prepare(`
      INSERT INTO ip_blocks (id,ip_hash,reason,expires_at,revoked_at,created_at,created_by_user_id)
      VALUES (?,?,?,?,NULL,?,?)
    `).bind(id, h, reason, now + ttl_sec, now, sess.uid).run();

    return json(200, "ok", { blocked: true, ip_hash: h, ttl_sec });
  }

  if (action === "unblock_my_ip") {
    await env.KV.delete(`ipblock:${h}`);
    const now = nowSec();
    await env.DB.prepare(`
      UPDATE ip_blocks SET revoked_at=?
      WHERE ip_hash=? AND revoked_at IS NULL AND expires_at > ?
    `).bind(now, h, now).run();

    return json(200, "ok", { unblocked: true, ip_hash: h });
  }

  return json(400, "invalid_input", { message: "unknown_action" });
}
