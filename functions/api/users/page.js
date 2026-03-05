import { json, hasRole } from "../../_lib.js";

function b64e(s){ return btoa(unescape(encodeURIComponent(s))); }
function b64d(s){ return decodeURIComponent(escape(atob(s))); }

export async function onRequestGet({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin","admin"])) return json(403,"forbidden",null);

  const url = new URL(request.url);
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit")||"50")));
  const q = String(url.searchParams.get("q")||"").trim().toLowerCase();
  const cursor = String(url.searchParams.get("cursor")||"").trim();

  // cursor = JSON { updated_at, id }
  let c = null;
  if (cursor) { try { c = JSON.parse(b64d(cursor)); } catch {} }

  const binds = [];
  let where = "1=1";
  if (q) {
    where += " AND (email_norm LIKE ? OR display_name LIKE ?)";
    binds.push(`%${q}%`,`%${q}%`);
  }
  if (c?.updated_at && c?.id) {
    where += " AND (updated_at < ? OR (updated_at = ? AND id < ?))";
    binds.push(Number(c.updated_at), Number(c.updated_at), String(c.id));
  }

  const r = await env.DB.prepare(`
    SELECT id,email_norm,display_name,status,updated_at,last_login_at,last_ip_hash,session_version
    FROM users
    WHERE ${where}
    ORDER BY updated_at DESC, id DESC
    LIMIT ?
  `).bind(...binds, limit+1).all();

  const rows = r.results || [];
  const has_more = rows.length > limit;
  const items = has_more ? rows.slice(0, limit) : rows;

  const next_cursor = has_more
    ? b64e(JSON.stringify({ updated_at: items[items.length-1].updated_at, id: items[items.length-1].id }))
    : null;

  return json(200,"ok",{ users: items, next_cursor });
}
