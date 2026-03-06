import { json } from "../_lib.js";

export async function onRequestGet({ env }) {
  const out = { ok: true, bindings: {} };
  out.bindings.DB = !!env.DB;
  out.bindings.KV = !!env.KV;
  out.bindings.R2 = !!env.R2;
  out.bindings.HASH_PEPPER = !!env.HASH_PEPPER;

  try {
    const r = await env.DB.prepare("SELECT 1 AS ok").first();
    out.d1 = r?.ok === 1;
  } catch (e) {
    out.d1 = false;
    out.d1_error = String(e?.message || e);
  }

  return json(200, "ok", out);
}
