import { json, readJson, pbkdf2Hash, timingSafeEqual, randomB64, audit } from "../../_lib.js";
function nowSec(){ return Math.floor(Date.now()/1000); }

export async function onRequestPost({ env, data, request }){
  const sess=data.session;
  const b=await readJson(request);
  const old_password=String(b?.old_password||"");
  const new_password=String(b?.new_password||"");
  if(new_password.length < 10) return json(400,"invalid_input",{message:"new_password min 10"});

  const u=await env.DB.prepare("SELECT id,password_hash,password_salt,password_iter FROM users WHERE id=? LIMIT 1").bind(sess.uid).first();
  if(!u) return json(404,"invalid_input",{message:"not_found"});
  if(!u.password_hash || !u.password_salt) return json(403,"forbidden",{message:"password_not_set"});

  const iter = Math.min(100000, Math.max(10000, Number(u.password_iter||100000)));
  const calc = await pbkdf2Hash(old_password, u.password_salt, iter);
  if(!timingSafeEqual(calc, u.password_hash)) return json(403,"forbidden",{message:"old_password_invalid"});

  const salt=randomB64(16);
  const hash=await pbkdf2Hash(new_password, salt, iter);
  const now=nowSec();

  await env.DB.prepare(`
    UPDATE users SET password_hash=?, password_salt=?, password_iter=?, password_algo='pbkdf2_sha256',
    updated_at=?, session_version=session_version+1
    WHERE id=?
  `).bind(hash,salt,iter,now,sess.uid).run();

  await audit(env,{ actor_user_id:sess.uid, action:"password.change", target_type:"user", target_id:sess.uid, meta:{} });
  return json(200,"ok",{ changed:true });
}
