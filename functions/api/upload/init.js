import { json, readJson } from "../../_lib.js";

function safeName(s) {
  return String(s || "file").replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 80);
}

export async function onRequestPost({ request, env, data }) {
  const sess = data.session;

  const body = await readJson(request);
  const filename = safeName(body?.filename || "avatar.jpg");
  const contentType = String(body?.content_type || "application/octet-stream");

  const key = `users/${sess.uid}/avatar/${crypto.randomUUID()}-${filename}`;

  // Signed URL PUT (60 seconds)
  const upload_url = await env.R2.createSignedUrl(key, {
    method: "PUT",
    expiresIn: 60,
    contentType,
  });

  return json(200, "ok", { upload_url, object_key: key });
}
