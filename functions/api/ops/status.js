import { json, requireAuth } from "../../_lib.js";

export async function onRequestGet({ request, env }) {
  const a = await requireAuth(env, request);
  if(!a.ok) return a.res;

  const one = async (sql, binds=[]) => (await env.DB.prepare(sql).bind(...binds).first()) || {};

  const users = await one("SELECT COUNT(*) AS c FROM users WHERE status='active'");
  const roles = await one("SELECT COUNT(*) AS c FROM roles");
  const menus = await one("SELECT COUNT(*) AS c FROM menus");
  const role_menus = await one("SELECT COUNT(*) AS c FROM role_menus");
  const incidents_open = await one("SELECT COUNT(*) AS c FROM incidents WHERE status='open'");
  const ip_blocks_active = await one("SELECT COUNT(*) AS c FROM ip_blocks WHERE revoked_at IS NULL AND expires_at > strftime('%s','now')");

  return json(200,"ok",{
    now: Math.floor(Date.now()/1000),
    users: Number(users.c||0),
    roles: Number(roles.c||0),
    menus: Number(menus.c||0),
    role_menus: Number(role_menus.c||0),
    incidents_open: Number(incidents_open.c||0),
    ip_blocks_active: Number(ip_blocks_active.c||0),
  });
}
