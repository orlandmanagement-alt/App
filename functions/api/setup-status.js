import { json } from "../_lib.js";

export async function onRequestGet({ env }) {
  const r = await env.DB.prepare(
    `SELECT 1 AS ok
     FROM users u
     JOIN user_roles ur ON ur.user_id=u.id
     JOIN roles r ON r.id=ur.role_id
     WHERE r.name='super_admin' AND u.status='active'
     LIMIT 1`
  ).first();
  return json(200, "ok", { setup_required: !r });
}
