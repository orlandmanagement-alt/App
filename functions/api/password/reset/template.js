import { json, hasRole } from "../../../_lib.js";

export async function onRequestGet({ env, data, request }) {
  const sess = data.session;
  if (!hasRole(sess.roles, ["super_admin"])) return json(403,"forbidden",null);

  const url = new URL(request.url);
  const token = String(url.searchParams.get("token")||"").trim();
  const base = String(env.APP_BASE_URL||"").replace(/\/$/,"");
  const link = base ? `${base}/reset.html?token=${encodeURIComponent(token||"TOKEN_CONTOH")}` : "(missing APP_BASE_URL)";

  const html = `
    <div style="font-family:Arial,sans-serif;line-height:1.5">
      <h2>Reset Password</h2>
      <p>Klik tombol di bawah untuk reset password (berlaku 15 menit).</p>
      <p><a href="${link}" style="display:inline-block;padding:10px 14px;background:#6D28D9;color:#fff;border-radius:10px;text-decoration:none">Reset Password</a></p>
      <p style="font-size:12px;color:#666">Jika tombol tidak berfungsi, copy link ini:</p>
      <p style="font-size:12px"><a href="${link}">${link}</a></p>
    </div>
  `;
  return json(200,"ok",{ link, html });
}
