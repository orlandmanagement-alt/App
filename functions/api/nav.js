// App/functions/api/nav.js
// GET /api/nav
// Return menus allowed for current user (based on role_menus), ordered by sort_order.
// super_admin: return all menus.

import { json, hasRole } from "../_lib.js";

export async function onRequestGet({ env, data }) {
  const sess = data.session;
  const roles = sess.roles || [];

  // super_admin sees all
  if (hasRole(roles, ["super_admin"])) {
    const r = await env.DB.prepare(`
      SELECT id,code,label,path,parent_id,sort_order,icon,created_at
      FROM menus
      ORDER BY sort_order ASC, created_at ASC
    `).all();
    return json(200, "ok", { menus: r.results || [] });
  }

  // admin/staff: filter by role_menus
  if (!hasRole(roles, ["admin", "staff"])) return json(403, "forbidden", null);

  const r = await env.DB.prepare(`
    SELECT DISTINCT
      m.id,m.code,m.label,m.path,m.parent_id,m.sort_order,m.icon,m.created_at
    FROM menus m
    JOIN role_menus rm ON rm.menu_id = m.id
    JOIN roles ro ON ro.id = rm.role_id
    WHERE ro.name IN (${roles.map(() => "?").join(",")})
    ORDER BY m.sort_order ASC, m.created_at ASC
  `).bind(...roles).all();

  const menus = r.results || [];

  // Optional: ensure parent menu ikut kebawa (kalau ada child tapi parent belum di-assign)
  // Ambil parent_id yang belum ada di list, lalu fetch.
  const have = new Set(menus.map((m) => m.id));
  const missingParents = Array.from(new Set(menus.map((m) => m.parent_id).filter(Boolean)))
    .filter((pid) => !have.has(pid));

  if (missingParents.length) {
    const p = await env.DB.prepare(`
      SELECT id,code,label,path,parent_id,sort_order,icon,created_at
      FROM menus
      WHERE id IN (${missingParents.map(() => "?").join(",")})
    `).bind(...missingParents).all();

    for (const x of (p.results || [])) {
      if (!have.has(x.id)) menus.push(x);
    }

    // re-sort
    menus.sort((a, b) => {
      const sa = Number(a.sort_order || 0);
      const sb = Number(b.sort_order || 0);
      if (sa !== sb) return sa - sb;
      return Number(a.created_at || 0) - Number(b.created_at || 0);
    });
  }

  return json(200, "ok", { menus });
}
