import { json, readCookie, cookie } from "../_lib.js";

export async function onRequestPost({ request, env }) {
  const sid = readCookie(request, "sid");
  if (sid) await env.KV.delete(`sess:${sid}`);

  const res = json(200, "ok", { logged_out: true });
  res.headers.append("set-cookie", cookie("sid", "", { maxAge: 0 }));
  return res;
}
