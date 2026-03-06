import { json } from "../_lib.js";

export async function onRequestPost({ env, data }) {
  const sid = data.session?.sid;
  if (sid) { try { await env.KV.delete(`sess:${sid}`); } catch {} }
  const res = json(200,"ok",{ logged_out:true });
  res.headers.append("set-cookie", "sid=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0");
  return res;
}
