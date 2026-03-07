import { json, requireAuth } from "../_lib.js";

export async function onRequestGet({ request, env }) {
  const a = await requireAuth(env, request);
  if(!a.ok) return a.res;

  const u = await env.DB.prepare("SELECT id,email_norm,display_name,status FROM users WHERE id=? LIMIT 1")
    .bind(a.uid).first();

  return json(200, "ok", {
    id: u?.id,
    email_norm: u?.email_norm,
    display_name: u?.display_name,
    status: u?.status,
    roles: a.roles
  });
}
