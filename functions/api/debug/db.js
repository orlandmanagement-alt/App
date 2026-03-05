import { json } from "../../_lib.js";

export async function onRequestGet({ env }) {
  const t = await env.DB.prepare(
    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT 50"
  ).all();
  return json(200, "ok", { tables: (t.results || []).map(x => x.name) });
}
