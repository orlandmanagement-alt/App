// App/functions/api/security/auto-block.js
import { json, readJson, hasRole } from "../../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }

export async function onRequestGet({ env, data }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin","admin"])) return json(403,"forbidden",null);

  const r = await env.DB.prepare(`
    SELECT k,v FROM system_settings
    WHERE k IN ('auto_block.enabled','auto_block.window_sec','auto_block.threshold','auto_block.ttl_sec')
  `).all();
  const map = {};
  for (const x of (r.results||[])) map[x.k] = x.v;

  return json(200,"ok",{
    enabled: (map["auto_block.enabled"]||"true") === "true",
    window_sec: Number(map["auto_block.window_sec"]||"900"),
    threshold: Number(map["auto_block.threshold"]||"10"),
    ttl_sec: Number(map["auto_block.ttl_sec"]||"3600"),
  });
}

export async function onRequestPost({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin"])) return json(403,"forbidden",null);

  const b = await readJson(request);
  const enabled = String(b?.enabled ?? "true") === "true";
  const window_sec = Math.min(86400, Math.max(60, Number(b?.window_sec||900)));
  const threshold = Math.min(500, Math.max(3, Number(b?.threshold||10)));
  const ttl_sec = Math.min(7*86400, Math.max(300, Number(b?.ttl_sec||3600)));
  const now = nowSec();

  const up = async (k,v)=>env.DB.prepare(`
    INSERT INTO system_settings (k,v,is_secret,updated_at)
    VALUES (?,?,0,?)
    ON CONFLICT(k) DO UPDATE SET v=excluded.v, updated_at=excluded.updated_at
  `).bind(k,String(v),now).run();

  await up("auto_block.enabled", enabled ? "true":"false");
  await up("auto_block.window_sec", window_sec);
  await up("auto_block.threshold", threshold);
  await up("auto_block.ttl_sec", ttl_sec);

  return json(200,"ok",{ updated:true });
}
