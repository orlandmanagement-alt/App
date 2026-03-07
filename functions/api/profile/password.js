import { json, readJson, requireAuth, randomB64, pbkdf2Hash, nowSec } from "../../_lib.js";

export async function onRequestPost({ request, env }) {
  const a = await requireAuth(env, request);
  if(!a.ok) return a.res;

  const body = await readJson(request);
  const new_password = String(body?.new_password || "");
  if(new_password.length < 10) return json(400,"invalid_input",{message:"min 10"});

  const salt = randomB64(16);
  const iter = Math.min(100000, Number(env.PBKDF2_ITER || 100000));
  const hash = await pbkdf2Hash(new_password, salt, iter);

  await env.DB.prepare(`
    UPDATE users SET password_hash=?, password_salt=?, password_iter=?, password_algo=?, updated_at=?
    WHERE id=?
  `).bind(hash, salt, iter, "pbkdf2_sha256", nowSec(), a.uid).run();

  return json(200,"ok",{ updated:true });
}
