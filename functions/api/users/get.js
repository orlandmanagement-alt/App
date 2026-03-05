import { json, hasRole } from "../../_lib.js";

export async function onRequestGet({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin", "admin", "staff"])) return json(403, "forbidden", null);

  const url = new URL(request.url);
  const id = String(url.searchParams.get("id") || "").trim();
  if (!id) return json(400, "invalid_input", { message: "id_required" });

  const u = await env.DB.prepare(`
    SELECT
      id,email_norm,display_name,status,created_at,updated_at,
      phone_e164,phone_verified,tenant_id,
      last_ip_hash,last_login_at,session_version
    FROM users
    WHERE id=? LIMIT 1
  `).bind(id).first();

  if (!u) return json(404, "invalid_input", { message: "not_found" });

  // roles
  const rr = await env.DB.prepare(`
    SELECT r.name AS name
    FROM user_roles ur JOIN roles r ON r.id=ur.role_id
    WHERE ur.user_id=?
  `).bind(id).all();

  return json(200, "ok", { user: u, roles: (rr.results || []).map(x => x.name) });
}
