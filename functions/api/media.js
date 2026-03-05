// App/functions/api/media.js
import { json, hasRole } from "../_lib.js";

export async function onRequestGet({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin","admin","staff"])) return json(403,"forbidden",null);
  if (!env.R2) return json(500,"server_error",{message:"missing_binding_R2"});

  const url = new URL(request.url);
  const key = String(url.searchParams.get("key")||"").trim();
  if (!key) return json(400,"invalid_input",{message:"key_required"});

  const obj = await env.R2.get(key);
  if (!obj) return new Response("not_found", { status: 404 });

  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  headers.set("cache-control", "private, max-age=600"); // 10 min
  headers.set("x-content-type-options", "nosniff");

  return new Response(obj.body, { status: 200, headers });
}
