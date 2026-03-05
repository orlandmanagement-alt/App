import { json, hasRole } from "../../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }

export async function onRequestGet({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin"])) return json(403, "forbidden", null);

  const url = new URL(request.url);
  const days = Math.min(90, Math.max(1, Number(url.searchParams.get("days") || "7")));
  const since = nowSec() - days*86400;
  const now = nowSec();

  const roles = await env.DB.prepare(`SELECT id,name,created_at FROM roles ORDER BY name ASC`).all();
  const menus = await env.DB.prepare(`SELECT id,code,label,path,parent_id,sort_order,icon,created_at FROM menus ORDER BY sort_order ASC`).all();
  const role_menus = await env.DB.prepare(`SELECT role_id,menu_id,created_at FROM role_menus ORDER BY role_id,menu_id`).all();

  const settings = await env.DB.prepare(`SELECT k,v,is_secret,updated_at FROM system_settings WHERE is_secret=0 ORDER BY k ASC`).all();

  const incidents = await env.DB.prepare(`
    SELECT id,severity,type,status,summary,created_at,updated_at
    FROM incidents
    WHERE created_at >= ?
    ORDER BY created_at DESC
    LIMIT 2000
  `).bind(since).all();

  const blocks = await env.DB.prepare(`
    SELECT id,ip_hash,reason,expires_at,revoked_at,created_at,created_by_user_id
    FROM ip_blocks
    WHERE created_at >= ?
    ORDER BY created_at DESC
    LIMIT 2000
  `).bind(since).all();

  return json(200, "ok", {
    kind: "admin_snapshot",
    created_at: now,
    days,
    rbac: {
      roles: roles.results || [],
      menus: menus.results || [],
      role_menus: role_menus.results || [],
    },
    settings: settings.results || [],
    security: {
      incidents: incidents.results || [],
      ip_blocks: blocks.results || [],
    }
  });
}
