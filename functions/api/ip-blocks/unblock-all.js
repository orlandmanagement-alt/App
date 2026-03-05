import { json, readJson, hasRole } from "../../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }

export async function onRequestPost({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin"])) return json(403, "forbidden", null);

  const b = await readJson(request);
  const ip_hash = String(b?.ip_hash||"").trim();
  if (!ip_hash) return json(400, "invalid_input", { message: "ip_hash_required" });

  const now = nowSec();
  await env.DB.prepare(`
    UPDATE ip_blocks
    SET revoked_at=?
    WHERE ip_hash=? AND revoked_at IS NULL AND expires_at > ?
  `).bind(now, ip_hash, now).run();

  await env.KV.delete(`ipblock:${ip_hash}`);
  return json(200, "ok", { unblocked: true, ip_hash });
}
