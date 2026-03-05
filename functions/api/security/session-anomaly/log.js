// App/functions/api/security/session-anomaly/log.js
import { json, readJson, hasRole, audit } from "../../../_lib.js";

export async function onRequestPost({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin", "admin"])) return json(403, "forbidden", null);

  const b = await readJson(request);
  const user_id = b?.user_id ? String(b.user_id).trim() : sess.uid;
  const reason = String(b?.reason || "unknown").trim().slice(0, 120);
  const meta = b?.meta ?? {};

  await audit(env, {
    actor_user_id: sess.uid,
    action: "session.anomaly.logged",
    target_type: "user",
    target_id: user_id,
    meta: { reason, ...meta }
  });

  return json(200, "ok", { logged: true });
}
