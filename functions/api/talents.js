import { json } from "../_lib.js";

export async function onRequestGet({ env }) {
  const r = await env.DB.prepare(
    `SELECT u.id,u.email_norm,u.display_name,u.status,u.updated_at
     FROM users u
     JOIN user_roles ur ON ur.user_id=u.id
     JOIN roles r ON r.id=ur.role_id
     WHERE r.name='talent'
     ORDER BY u.updated_at DESC
     LIMIT 200`
  ).all();

  const talents = [];
  for (const u of (r.results || [])) {
    // photo metadata in KV (optional)
    const metaRaw = await env.KV.get(`u_meta:${u.id}`);
    let photo_url = null;
    if (metaRaw) {
      const meta = JSON.parse(metaRaw);
      if (meta.photo_public_url) photo_url = meta.photo_public_url;
    }
    talents.push({ ...u, photo_url });
  }

  return json(200, "ok", { talents });
}
