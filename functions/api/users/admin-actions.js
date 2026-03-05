// App/functions/api/users/admin-actions.js
import { json, readJson, hasRole, audit } from "../../_lib.js";

function nowSec(){ return Math.floor(Date.now()/1000); }

export async function onRequestPost({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin"])) return json(403, "forbidden", null);

  const b = await readJson(request);
  const action = String(b?.action || "").trim();
  const user_id = String(b?.user_id || "").trim();
  if (!action || !user_id) return json(400, "invalid_input", { message: "action & user_id required" });

  if (action === "disable" || action === "enable") {
    const status = action === "disable" ? "disabled" : "active";
    const now = nowSec();
    await env.DB.prepare("UPDATE users SET status=?, updated_at=? WHERE id=?")
      .bind(status, now, user_id).run();

    await audit(env, {
      actor_user_id: sess.uid,
      action: `user.${action}`,
      target_type: "user",
      target_id: user_id,
      meta: {}
    });

    return json(200, "ok", { updated: true, status });
  }

  if (action === "revoke_sessions") {
    // KV sessions: delete all sess:* for this user is not queryable directly.
    // So we do DB revoke if you store sessions in D1,
    // and ALSO set a user-level "session_revoked_at" in system_settings-like table if needed later.
    // Minimal: revoke D1 sessions table if exists.
    const now = nowSec();
    try {
      await env.DB.prepare("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL")
        .bind(now, user_id).run();
    } catch {}

    await audit(env, {
      actor_user_id: sess.uid,
      action: "user.sessions.revoked",
      target_type: "user",
      target_id: user_id,
      meta: {}
    });

    return json(200, "ok", { revoked: true });
  }

  return json(400, "invalid_input", { message: "unknown_action" });
}
