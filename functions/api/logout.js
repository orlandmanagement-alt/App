import { json, requireAuth, revokeSessionBySid, cookie } from "../_lib.js";

export async function onRequestPost({ request, env }) {
  const a = await requireAuth(env, request);
  if (!a.ok) return a.res;

  await revokeSessionBySid(env, a.token);

  const res = json(200, "ok", { logged_out: true });
  // clear cookie
  res.headers.append("set-cookie", cookie("sid","", { maxAge: 0 }));
  return res;
}
