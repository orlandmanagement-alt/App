import { json, hasRole } from "../../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }
function extFromName(n){
  const s = String(n||"").toLowerCase();
  const i = s.lastIndexOf(".");
  return i>0 ? s.slice(i+1).replace(/[^a-z0-9]/g,"") : "bin";
}

export async function onRequestPost({ env, data, request }) {
  const sess=data.session;
  if(!hasRole(sess.roles, ["super_admin","admin","staff"])) return json(403,"forbidden",null);
  if(!env.R2) return json(500,"server_error",{message:"missing_binding_R2"});

  const ct = request.headers.get("content-type") || "";
  if(!ct.includes("multipart/form-data")) return json(400,"invalid_input",{message:"multipart required"});

  const form = await request.formData();
  const file = form.get("file");
  if(!file || typeof file === "string") return json(400,"invalid_input",{message:"file required"});

  const maxBytes = 5 * 1024 * 1024;
  const buf = await file.arrayBuffer();
  if(buf.byteLength > maxBytes) return json(400,"invalid_input",{message:"max 5MB"});

  const ext = extFromName(file.name);
  const key = `avatars/${sess.uid}/${nowSec()}.${ext}`;

  await env.R2.put(key, buf, { httpMetadata: { contentType: file.type || "application/octet-stream" } });

  // Use private serve endpoint by default
  const url = `/api/media?key=${encodeURIComponent(key)}`;

  const now = nowSec();
  await env.DB.prepare("UPDATE users SET photo_key=?, photo_url=?, updated_at=? WHERE id=?").bind(key, url, now, sess.uid).run();

  return json(200,"ok",{ uploaded:true, key, url });
}
