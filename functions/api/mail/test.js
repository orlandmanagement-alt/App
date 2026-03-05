import { json, readJson, hasRole } from "../../_lib.js";
import { sendMail } from "../../_mail.js";

export async function onRequestPost({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin"])) return json(403, "forbidden", null);

  const b = await readJson(request);
  const to = String(b?.to || "").trim().toLowerCase();
  if (!to.includes("@")) return json(400, "invalid_input", { message: "to invalid" });

  await sendMail(env, {
    to,
    subject: "Test Email — Orland Dashboard",
    text: "Jika kamu menerima email ini, konfigurasi email sudah OK.",
    html: `<div style="font-family:Arial"><h3>Test Email OK</h3><p>Konfigurasi email sudah benar ✅</p></div>`,
  });

  return json(200, "ok", { sent: true });
}
