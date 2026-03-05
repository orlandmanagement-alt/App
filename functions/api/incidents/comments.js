import { json, readJson, hasRole, sha256Base64, audit } from "../../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }

export async function onRequestGet({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin","admin","staff"])) return json(403, "forbidden", null);

  const url = new URL(request.url);
  const incident_id = String(url.searchParams.get("incident_id") || "").trim();
  const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit") || "50")));
  if (!incident_id) return json(400, "invalid_input", { message: "incident_id_required" });

  const r = await env.DB.prepare(`
    SELECT id,incident_id,author_user_id,body,created_at
    FROM incident_comments
    WHERE incident_id=?
    ORDER BY created_at DESC
    LIMIT ?
  `).bind(incident_id, limit).all();

  return json(200, "ok", { comments: r.results || [] });
}

export async function onRequestPost({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin","admin","staff"])) return json(403, "forbidden", null);

  const b = await readJson(request);
  const incident_id = String(b?.incident_id || "").trim();
  const body = String(b?.body || "").trim();
  if (!incident_id || body.length < 1) return json(400, "invalid_input", { message: "incident_id/body required" });
  if (body.length > 2000) return json(400, "invalid_input", { message: "body too long" });

  const id = crypto.randomUUID();
  const now = nowSec();
  const body_hash = await sha256Base64(body);

  await env.DB.prepare(`
    INSERT INTO incident_comments (id,incident_id,author_user_id,body,body_hash,created_at)
    VALUES (?,?,?,?,?,?)
  `).bind(id, incident_id, sess.uid, body, body_hash, now).run();

  await audit(env,{ actor_user_id:sess.uid, action:"incident.comment.create", target_type:"incident", target_id:incident_id, meta:{ comment_id:id }});
  return json(200, "ok", { created: true, id });
}
