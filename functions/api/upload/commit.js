import { json, readJson } from "../../_lib.js";

export async function onRequestPost({ request, env, data }) {
  const sess = data.session;
  const body = await readJson(request);
  const object_key = String(body?.object_key || "").trim();
  if (!object_key) return json(400, "invalid_input", null);

  // Simpan metadata di KV. Kalau kamu punya R2 custom domain/public URL, isi photo_public_url.
  const meta = {
    photo_key: object_key,
    // photo_public_url: `https://r2.orlandmanagement.com/${object_key}`, // aktifkan jika kamu set domain public R2
    updated_at: Math.floor(Date.now() / 1000),
  };

  await env.KV.put(`u_meta:${sess.uid}`, JSON.stringify(meta));
  return json(200, "ok", { saved: true, object_key });
}
