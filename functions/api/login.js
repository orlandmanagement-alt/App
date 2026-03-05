export async function onRequestPost({ request, env }) {
  const body = await request.json().catch(() => null);
  const email = String(body?.email || "").trim().toLowerCase();
  const password = String(body?.password || "");

  if (!email.includes("@") || password.length < 6) {
    return json(400, "invalid_input", null);
  }

  const u = await env.DB.prepare(
    "SELECT id,display_name,status,password_hash,password_salt,password_iter FROM users WHERE email_norm=? LIMIT 1"
  ).bind(email).first();

  if (!u) return json(403, "user_belum_terdaftar", null);
  if (String(u.status) !== "active") return json(403, "forbidden", null);

  const ok = await verifyPbkdf2(password, u.password_salt, Number(u.password_iter || 210000), u.password_hash);
  if (!ok) return json(403, "password_invalid", null);

  // roles
  const roles = await env.DB.prepare(
    `SELECT r.name AS name
     FROM user_roles ur JOIN roles r ON r.id=ur.role_id
     WHERE ur.user_id=?`
  ).bind(u.id).all();

  const roleList = (roles.results || []).map(x => x.name);

  // session (opaque id stored in KV)
  const sid = crypto.randomUUID();
  const exp = Math.floor(Date.now()/1000) + 2*3600; // contoh 2 jam
  await env.KV.put(`sess:${sid}`, JSON.stringify({ uid: u.id, roles: roleList, exp }), { expirationTtl: 2*3600 });

  const res = json(200, "ok", { id: u.id, display_name: u.display_name, roles: roleList });
  res.headers.append("set-cookie", cookie("sid", sid, { maxAge: 2*3600 }));
  return res;
}

function json(code, status, data){
  return new Response(JSON.stringify({ status, data }), {
    status: code,
    headers: { "content-type":"application/json; charset=utf-8" }
  });
}

function cookie(name, value, opt){
  const maxAge = opt?.maxAge ?? 3600;
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

async function verifyPbkdf2(password, saltB64, iter, expectedB64){
  if (!saltB64 || !expectedB64) return false;
  const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name:"PBKDF2", hash:"SHA-256", salt, iterations: iter }, key, 256);
  const b64 = btoa(String.fromCharCode(...new Uint8Array(bits)));
  return timingSafeEqual(b64, expectedB64);
}

function timingSafeEqual(a,b){
  a=String(a||""); b=String(b||"");
  if(a.length!==b.length) return false;
  let r=0; for(let i=0;i<a.length;i++) r|=a.charCodeAt(i)^b.charCodeAt(i);
  return r===0;
}
