import { json, hasRole } from "../_lib.js";

export async function onRequestGet({ env, data }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin", "admin", "staff"])) return json(403, "forbidden", null);

  const r = await env.DB.prepare(
    `SELECT u.id,u.email_norm,u.display_name,u.status,u.updated_at
     FROM users u
     JOIN user_roles ur ON ur.user_id=u.id
     JOIN roles r ON r.id=ur.role_id
     WHERE r.name='talent'
     ORDER BY u.updated_at DESC
     LIMIT 200`
  ).all();

  // optional photo metadata in KV
  const talents = [];
  for (const u of (r.results || [])) {
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
