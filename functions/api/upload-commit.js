import { json, readJson } from "../_lib.js";

export async function onRequestPost({ request, env, data }) {
  const sess = data.session;
  const body = await readJson(request);
  const object_key = String(body?.object_key || "").trim();
  if (!object_key) return json(400, "invalid_input", null);

  // OPTIONAL: buat public URL via custom domain R2 (kalau sudah kamu set)
  // Jika belum punya, simpan object_key saja.
  const meta = {
    photo_key: object_key,
    // photo_public_url: `https://r2-public.yourdomain.com/${object_key}`, // isi jika kamu punya public bucket route
    updated_at: Math.floor(Date.now()/1000),
  };

  await env.KV.put(`u_meta:${sess.uid}`, JSON.stringify(meta));
  return json(200, "ok", { saved:true, object_key });
}
