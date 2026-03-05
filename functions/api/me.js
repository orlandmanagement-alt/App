import { json } from "../_lib.js";

export async function onRequestGet({ env, data }) {
  const sess = data.session;
  const u = await env.DB.prepare("SELECT id,display_name,status FROM users WHERE id=? LIMIT 1")
    .bind(sess.uid).first();

  if (!u) return json(401, "unauthorized", null);
  return json(200, "ok", { id: u.id, display_name: u.display_name, roles: sess.roles, status: u.status });
}
