import { json, hasRole } from "../../_lib.js";

function b64e(s){ return btoa(unescape(encodeURIComponent(s))); }
function b64d(s){ return decodeURIComponent(escape(atob(s))); }

export async function onRequestGet({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin","admin"])) return json(403,"forbidden",null);

  const url = new URL(request.url);
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit")||"50")));
  const q = String(url.searchParams.get("q")||"").trim();
  const cursor = String(url.searchParams.get("cursor")||"").trim();

  let c = null;
  if (cursor) { try { c = JSON.parse(b64d(cursor)); } catch {} }

  const binds = [];
  let where = "1=1";
  if (q) { where += " AND action LIKE ?"; binds.push(`%${q}%`); }
  if (c?.created_at && c?.id) {
    where += " AND (created_at < ? OR (created_at = ? AND id < ?))";
    binds.push(Number(c.created_at), Number(c.created_at), String(c.id));
  }

  const r = await env.DB.prepare(`
    SELECT id,actor_user_id,action,target_type,target_id,meta_json,created_at
    FROM audit_logs
    WHERE ${where}
    ORDER BY created_at DESC, id DESC
    LIMIT ?
  `).bind(...binds, limit+1).all();

  const rows = r.results || [];
  const has_more = rows.length > limit;
  const items = has_more ? rows.slice(0, limit) : rows;

  const next_cursor = has_more
    ? btoa(JSON.stringify({ created_at: items[items.length-1].created_at, id: items[items.length-1].id }))
    : null;

  return json(200,"ok",{ rows: items, next_cursor });
}
