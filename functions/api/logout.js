// App/functions/api/logout.js
import { json } from "../_lib.js";

export async function onRequestPost({ env, data }) {
  const sid = data.session?.sid;
  if (sid) {
    try { await env.KV.delete(`sess:${sid}`); } catch {}
  }
  return json(200, "ok", { logged_out: true });
}
