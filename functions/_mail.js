import { nowSec } from "./_lib.js";

/**
 * _mail.js — STUB
 * Nanti bisa diganti Email provider (MailChannels / Resend / SMTP) jika sudah siap.
 * Sekarang: hanya console.log (akan terlihat di Pages Functions logs).
 */
export async function sendResetEmail({ to, link }) {
  console.log("[mail.stub]", { to, link, at: nowSec() });
  return true;
}
