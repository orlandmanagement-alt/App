export async function onRequestGet({ request, env }) {
  const sid = readCookie(request, "sid");
  if (!sid) return json(401, "unauthorized", null);

  const rec = await env.KV.get(`sess:${sid}`);
  if (!rec) return json(401, "unauthorized", null);

  const sess = JSON.parse(rec);
  if (Math.floor(Date.now()/1000) > Number(sess.exp||0)) return json(401, "unauthorized", null);

  const u = await env.DB.prepare("SELECT id,display_name,status FROM users WHERE id=? LIMIT 1").bind(sess.uid).first();
  if (!u) return json(401, "unauthorized", null);

  return json(200, "ok", { id: u.id, display_name: u.display_name, roles: sess.roles, status: u.status });
}

function readCookie(req, name){
  const c = req.headers.get("cookie") || "";
  const m = c.match(new RegExp("(^|;\\s*)"+name+"=([^;]+)"));
  return m ? decodeURIComponent(m[2]) : "";
}
function json(code, status, data){
  return new Response(JSON.stringify({ status, data }), { status: code, headers: { "content-type":"application/json; charset=utf-8" } });
}
