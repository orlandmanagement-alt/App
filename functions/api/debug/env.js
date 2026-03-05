import { json } from "../../_lib.js";

export async function onRequestGet({ env }) {
  return json(200, "ok", {
    hasDB: !!env.DB,
    hasKV: !!env.KV,
    hasR2: !!env.R2,
    hasPepper: !!env.HASH_PEPPER,
  });
}
