// App/functions/_mail.js — FULLPACK
export async function sendMail(env, { to, subject, html, text }) {
  const provider = String(env.MAIL_PROVIDER || "resend").toLowerCase();

  if (provider === "resend") {
    if (!env.RESEND_API_KEY) throw new Error("missing_RESEND_API_KEY");
    if (!env.MAIL_FROM) throw new Error("missing_MAIL_FROM");

    const resp = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "authorization": `Bearer ${env.RESEND_API_KEY}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        from: env.MAIL_FROM,
        to: [to],
        subject,
        html,
        text,
      }),
    });

    if (!resp.ok) {
      const body = await resp.text().catch(() => "");
      throw new Error(`resend_failed_${resp.status}:${body.slice(0,200)}`);
    }
    return { ok: true };
  }

  throw new Error("mail_provider_not_supported");
}
