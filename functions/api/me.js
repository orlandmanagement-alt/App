import { json } from "../_lib.js";

export async function onRequestGet({ env, data }) {
  const sess = data.session;
  const u = await env.DB.prepare(`SELECT id,email_norm,display_name,status,last_login_at,photo_key,photo_url FROM users WHERE id=? LIMIT 1`)
    .bind(sess.uid).first();
  return json(200, "ok", {
    id:u?.id,
    email_norm:u?.email_norm,
    display_name:u?.display_name,
    status:u?.status,
    last_login_at:u?.last_login_at||null,
    photo_key:u?.photo_key||null,
    photo_url:u?.photo_url||null,
    roles:sess.roles||[],
    exp:sess.exp
  });
}
