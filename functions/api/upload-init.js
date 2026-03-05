export async function onRequestPost({ request, env }) {
  const sid = readCookie(request, "sid");
  if (!sid) return json(401, "unauthorized", null);
  const rec = await env.KV.get(`sess:${sid}`); if (!rec) return json(401, "unauthorized", null);
  const sess = JSON.parse(rec);

  const body = await request.json().catch(()=>null);
  const filename = String(body?.filename || "file.bin");
  const contentType = String(body?.content_type || "application/octet-stream");

  const key = `users/${sess.uid}/avatar/${crypto.randomUUID()}-${safeName(filename)}`;

  // Signed URL (PUT)
  const url = await env.R2.createSignedUrl(key, { method: "PUT", expiresIn: 60, contentType });

  return json(200, "ok", { upload_url: url, object_key: key });
}

function safeName(s){ return String(s||"").replace(/[^a-zA-Z0-9._-]/g,"_").slice(0,80); }
function readCookie(req, name){
  const c = req.headers.get("cookie") || "";
  const m = c.match(new RegExp("(^|;\\s*)"+name+"=([^;]+)"));
  return m ? decodeURIComponent(m[2]) : "";
}
function json(code, status, data){
  return new Response(JSON.stringify({ status, data }), { status: code, headers: { "content-type":"application/json; charset=utf-8" } });
}
