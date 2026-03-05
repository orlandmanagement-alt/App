import { json, readJson, hasRole, audit } from "../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }

export async function onRequestGet({ env, data, request }){
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin","admin"])) return json(403,"forbidden",null);

  const url = new URL(request.url);
  const active = String(url.searchParams.get("active")||"1") === "1";
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit")||"100")));
  const now = nowSec();

  const sql = active
    ? `SELECT id,ip_hash,reason,expires_at,revoked_at,created_at,created_by_user_id
       FROM ip_blocks
       WHERE revoked_at IS NULL AND expires_at > ?
       ORDER BY created_at DESC LIMIT ?`
    : `SELECT id,ip_hash,reason,expires_at,revoked_at,created_at,created_by_user_id
       FROM ip_blocks
       ORDER BY created_at DESC LIMIT ?`;

  const r = active
    ? await env.DB.prepare(sql).bind(now, limit).all()
    : await env.DB.prepare(sql).bind(limit).all();

  return json(200,"ok",{ blocks: r.results||[] });
}

export async function onRequestPost({ env, data, request }){
  // router by pathname:
  const path = new URL(request.url).pathname;

  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin"])) return json(403,"forbidden",null);
  if (!env.KV) return json(500,"server_error",{message:"missing_binding_KV"});

  const now = nowSec();
  const b = await readJson(request);

  if (path.endsWith("/block")) {
    const ip_hash = String(b?.ip_hash||"").trim();
    const ttl_sec = Math.min(7*86400, Math.max(60, Number(b?.ttl_sec||3600)));
    const reason = String(b?.reason||"manual_block").trim();
    if (!ip_hash) return json(400,"invalid_input",{message:"ip_hash required"});

    await env.KV.put(`ipblock:${ip_hash}`, reason, { expirationTtl: ttl_sec });

    const id = crypto.randomUUID();
    const expires_at = now + ttl_sec;
    await env.DB.prepare(`
      INSERT INTO ip_blocks (id,ip_hash,reason,expires_at,created_at,created_by_user_id)
      VALUES (?,?,?,?,?,?)
    `).bind(id, ip_hash, reason, expires_at, now, sess.uid).run();

    await audit(env,{actor_user_id:sess.uid, action:"ipblock.block", target_type:"ip_block", target_id:id, meta:{ttl_sec}});
    return json(200,"ok",{ blocked:true, id, expires_at });
  }

  if (path.endsWith("/unblock")) {
    const id = String(b?.id||"").trim();
    if (!id) return json(400,"invalid_input",{message:"id required"});

    const row = await env.DB.prepare(`SELECT ip_hash FROM ip_blocks WHERE id=? LIMIT 1`).bind(id).first();
    if (!row) return json(404,"invalid_input",{message:"not_found"});

    await env.KV.delete(`ipblock:${row.ip_hash}`);
    await env.DB.prepare(`UPDATE ip_blocks SET revoked_at=? WHERE id=?`).bind(now, id).run();

    await audit(env,{actor_user_id:sess.uid, action:"ipblock.unblock", target_type:"ip_block", target_id:id, meta:{}});
    return json(200,"ok",{ unblocked:true });
  }

  if (path.endsWith("/unblock-hash")) {
    const ip_hash = String(b?.ip_hash||"").trim();
    if (!ip_hash) return json(400,"invalid_input",{message:"ip_hash required"});

    await env.KV.delete(`ipblock:${ip_hash}`);
    await env.DB.prepare(`
      UPDATE ip_blocks SET revoked_at=?
      WHERE ip_hash=? AND revoked_at IS NULL AND expires_at > ?
    `).bind(now, ip_hash, now).run();

    await audit(env,{actor_user_id:sess.uid, action:"ipblock.unblock_hash", target_type:"ip_hash", target_id:ip_hash, meta:{}});
    return json(200,"ok",{ unblocked:true });
  }

  return json(404,"invalid_input",{message:"not_found"});
}
