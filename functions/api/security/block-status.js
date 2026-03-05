import { json } from "../../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }

export async function onRequestGet({ env, data }) {
  const sess = data.session;
  const now = nowSec();

  const u = await env.DB.prepare(`
    SELECT id,email_norm,display_name,last_ip_hash,last_login_at
    FROM users WHERE id=? LIMIT 1
  `).bind(sess.uid).first();

  if (!u?.last_ip_hash) return json(200, "ok", { blocked: false, reason: null, user: u });

  const b = await env.DB.prepare(`
    SELECT id,reason,expires_at,created_at
    FROM ip_blocks
    WHERE ip_hash=? AND revoked_at IS NULL AND expires_at > ?
    ORDER BY created_at DESC LIMIT 1
  `).bind(u.last_ip_hash, now).first();

  return json(200, "ok", { blocked: !!b, reason: b?.reason || null, block: b || null, user: u });
}
