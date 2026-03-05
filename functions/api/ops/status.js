import { json, hasRole } from "../../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }

async function count(env, sql, binds=[]){
  const r = await env.DB.prepare(sql).bind(...binds).first();
  return Number(r?.cnt || 0);
}

export async function onRequestGet({ env, data }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin","admin"])) return json(403, "forbidden", null);

  const now = nowSec();

  const users = await count(env, "SELECT COUNT(*) AS cnt FROM users");
  const roles = await count(env, "SELECT COUNT(*) AS cnt FROM roles");
  const menus = await count(env, "SELECT COUNT(*) AS cnt FROM menus");
  const role_menus = await count(env, "SELECT COUNT(*) AS cnt FROM role_menus");
  const incidents_open = await count(env, "SELECT COUNT(*) AS cnt FROM incidents WHERE status!='closed'");
  const ip_blocks_active = await count(env, "SELECT COUNT(*) AS cnt FROM ip_blocks WHERE revoked_at IS NULL AND expires_at > ?", [now]);

  return json(200, "ok", {
    users, roles, menus, role_menus,
    incidents_open,
    ip_blocks_active,
    now
  });
}
