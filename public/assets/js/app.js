/* Orland Dashboard — multipage app.js (Bootstrap + Purple)
 * Same-origin API under /api/*
 */
(function(){
  "use strict";

  async function api(path, opt = {}) {
    const headers = Object.assign({}, opt.headers || {});
    if (opt.body != null && !headers["content-type"]) headers["content-type"] = "application/json";
    try {
      const res = await fetch(path, {
        method: opt.method || "GET",
        headers,
        body: opt.body || undefined,
        credentials: "include",
      });
      const ct = res.headers.get("content-type") || "";
      if (!ct.includes("application/json")) {
        const text = await res.text().catch(() => "");
        return { status: "server_error", data: { http: res.status, body: text.slice(0, 280) } };
      }
      return await res.json();
    } catch (e) {
      return { status: "network_error", data: { message: String(e?.message || e) } };
    }
  }

  const $ = (sel, root=document) => root.querySelector(sel);
  const $$ = (sel, root=document) => Array.from(root.querySelectorAll(sel));
  function esc(s){ return String(s??"").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;"); }

  function toast(msg, type="info"){
    const host = document.getElementById("toast-host");
    if(!host) return alert(msg);
    const div = document.createElement("div");
    div.className = "toast-item";
    div.innerHTML = `<div style="font-weight:800">${esc(type.toUpperCase())}</div><div class="small-muted" style="margin-top:4px">${esc(msg)}</div>`;
    host.appendChild(div);
    setTimeout(()=>{ div.style.opacity="0"; div.style.transform="translateY(6px)"; }, 2400);
    setTimeout(()=>div.remove(), 3200);
  }

  function diceBear(seed){
    const s = encodeURIComponent(String(seed||"user"));
    return `https://api.dicebear.com/8.x/initials/svg?seed=${s}&backgroundColor=6d28d9&textColor=ffffff`;
  }

  function bindPasswordToggles(){
    $$(".pw-toggle").forEach(btn=>{
      btn.addEventListener("click", ()=>{
        const id = btn.getAttribute("data-target");
        const input = document.getElementById(id);
        if(!input) return;
        const isPw = input.getAttribute("type")==="password";
        input.setAttribute("type", isPw ? "text" : "password");
        btn.innerHTML = isPw ? '<i class="fa-solid fa-eye-slash"></i>' : '<i class="fa-solid fa-eye"></i>';
      });
    });
  }

  // ---------- Auth pages ----------
  async function pageLogin(){
    const out = $("#debugOut");

    // already logged in?
    const me0 = await api("/api/me");
    if (out) out.textContent = JSON.stringify(me0, null, 2);
    if(me0.status === "ok"){ location.href="/dashboard.html"; return; }

    const st = await api("/api/setup/status");
    if(out) out.textContent = JSON.stringify(st,null,2);
    if(st.status==="ok" && st.data?.setup_required){
      location.href = "/setup.html";
      return;
    }

    $("#btnLogin")?.addEventListener("click", async ()=>{
      const email = String($("#email")?.value||"").trim().toLowerCase();
      const password = String($("#password")?.value||"");
      const r = await api("/api/login", { method:"POST", body: JSON.stringify({ email, password }) });
      if(out) out.textContent = JSON.stringify(r,null,2);
      if(r.status==="ok"){
        toast("Login sukses", "success");
        location.href="/dashboard.html";
      } else toast("Login gagal: "+r.status, "error");
    });

    $("#password")?.addEventListener("keydown",(e)=>{ if(e.key==="Enter") $("#btnLogin")?.click(); });
  }

  async function pageSetup(){
    const out = $("#debugOut");
    const st = await api("/api/setup/status");
    if(out) out.textContent = JSON.stringify(st,null,2);

    const params = new URLSearchParams(location.search);
    const invite = params.get("invite");

    if(st.status==="ok" && !st.data?.setup_required && !invite){
      location.href = "/index.html";
      return;
    }
    if(invite){ const t=$("#setupTitle"); if(t) t.textContent="Accept Invite (Admin)"; }

    $("#btnSetup")?.addEventListener("click", async ()=>{
      const display_name = String($("#display_name")?.value||"").trim();
      const email = String($("#email")?.value||"").trim().toLowerCase();
      const password = String($("#password")?.value||"");
      if(!email.includes("@") || password.length<10){ toast("Email invalid / password min 10", "error"); return; }

      let r;
      if(invite){
        r = await api("/api/invites/accept", { method:"POST", body: JSON.stringify({ token: invite, email, display_name, password }) });
      }else{
        r = await api("/api/setup/bootstrap", { method:"POST", body: JSON.stringify({ email, display_name, password }) });
      }
      if(out) out.textContent = JSON.stringify(r,null,2);
      if(r.status==="ok"){ toast("Berhasil. Silakan login.", "success"); location.href="/index.html"; }
      else toast("Gagal: "+r.status, "error");
    });
  }

  async function pageResetRequest(){
    const out = $("#debugOut");
    $("#btnSend")?.addEventListener("click", async ()=>{
      const email = String($("#email")?.value||"").trim().toLowerCase();
      const r = await api("/api/password/reset/request", { method:"POST", body: JSON.stringify({ email }) });
      if(out) out.textContent = JSON.stringify(r,null,2);
      toast("Jika email terdaftar, link reset dikirim.", "info");
    });
  }

  async function pageResetConfirm(){
    const out = $("#debugOut");
    const token = new URLSearchParams(location.search).get("token") || "";
    if(!token){ toast("Token tidak ada", "error"); return; }
    const v = await api("/api/password/reset/validate", { method:"POST", body: JSON.stringify({ token }) });
    if(out) out.textContent = JSON.stringify(v,null,2);
    if(v.status!=="ok"){ toast("Token invalid/expired", "error"); return; }

    $("#btnReset")?.addEventListener("click", async ()=>{
      const new_password = String($("#password")?.value||"");
      if(new_password.length<10){ toast("Password min 10", "error"); return; }
      const r = await api("/api/password/reset/confirm", { method:"POST", body: JSON.stringify({ token, new_password }) });
      if(out) out.textContent = JSON.stringify(r,null,2);
      if(r.status==="ok"){ toast("Reset sukses. Silakan login.", "success"); location.href="/index.html"; }
      else toast("Gagal: "+r.status, "error");
    });
  }

  // ---------- Shared authed shell ----------
  async function bootAuthed(pageKey){
    const out = $("#debugOut");
    const me = await api("/api/me");
    if(out) out.textContent = JSON.stringify(me,null,2);
    if(me.status!=="ok"){ location.href="/index.html"; return null; }

    $("#meName").textContent = me.data.display_name || me.data.email_norm || me.data.id;
    $("#meRole").textContent = (me.data.roles||[]).join(", ");
    $("#meAvatar").src = diceBear(me.data.email_norm || me.data.id);

    $("#btnLogout")?.addEventListener("click", async ()=>{
      await api("/api/logout", { method:"POST", body:"{}" });
      location.href="/index.html";
    });

    $("#navToggle")?.addEventListener("click", ()=>{
      $("#sidebar")?.classList.toggle("open");
    });

    const nav = await api("/api/nav");
    if(nav.status==="ok"){
      renderNav(nav.data.tree || nav.data.menus || []);
    }

    const map = {
      overview:["Overview","Ringkasan sistem & KPI"],
      users:["Users","CRUD admin/staff"],
      roles:["Roles","Kelola role"],
      menus:["Menus","Kelola menu & icon"],
      rbac:["RBAC","Assign menus ke role"],
      security:["Security","Metrics & trend"],
      ipblocks:["IP Blocks","Kelola IP blokir"],
      audit:["Audit Logs","Jejak aktivitas"],
      ops:["Ops","System status"],
      profile:["Profile","Akun kamu & ganti password"],
    };
    const t = map[pageKey] || ["Dashboard",""];
    $("#pageTitle").textContent = t[0];
    $("#pageSubtitle").textContent = t[1];

    return me;
  }

  function renderNav(tree){
    const root = $("#navList");
    if(!root) return;

    // always add profile
    const fixed = [{ label:"Profile", code:"profile", path:"/profile", icon:"fa-solid fa-id-badge", children:[] }];

    const items = [];
    const walk = (node, depth=0)=>{
      items.push({ ...node, depth });
      (node.children||[]).forEach(ch=>walk(ch, depth+1));
    };
    (fixed.concat(Array.isArray(tree)?tree:[])).forEach(n=>walk(n,0));

    root.innerHTML = items.map(m=>{
      const pad = 10 + (m.depth*14);
      const icon = m.icon ? `<i class="${esc(m.icon)}"></i>` : `<i class="fa-solid fa-circle-dot" style="opacity:.55"></i>`;
      const href = pathToHref(m.path || "");
      return `<a class="nav-item" href="${esc(href)}" style="padding-left:${pad}px" data-href="${esc(href)}">${icon}<span>${esc(m.label||m.code||"Menu")}</span></a>`;
    }).join("");

    const cur = location.pathname.replace(/\/+$/,"");
    $$(".nav-item", root).forEach(a=>{
      const h = (a.getAttribute("data-href")||"").replace(/\/+$/,"");
      a.classList.toggle("active", h===cur);
    });
  }

  function pathToHref(p){
    const map = {
      "/dashboard": "/dashboard.html",
      "/users": "/users.html",
      "/roles": "/roles.html",
      "/menus": "/menus.html",
      "/rbac": "/rbac.html",
      "/security": "/security.html",
      "/ipblocks": "/ipblocks.html",
      "/audit": "/audit.html",
      "/ops": "/ops.html",
      "/profile": "/profile.html",
    };
    return map[p] || "/dashboard.html";
  }

  // ---------- Page implementations (UI only; API in Functions) ----------
  async function pageOverview(){
    const me = await bootAuthed("overview"); if(!me) return;
    const out = $("#debugOut");

    const ops = await api("/api/ops/status");
    if(out) out.textContent = JSON.stringify({ me, ops }, null, 2);
    if(ops.status==="ok"){
      $("#kpiUsers").textContent = ops.data.users;
      $("#kpiRoles").textContent = ops.data.roles;
      $("#kpiMenus").textContent = ops.data.menus;
      $("#kpiIpBlocks").textContent = ops.data.ip_blocks_active;
      $("#opsBox").innerHTML = `
        <div class="row g-2">
          <div class="col-md-4"><div class="kpi"><div class="small-muted">Incidents open</div><div style="font-size:22px;font-weight:900">${esc(ops.data.incidents_open)}</div></div></div>
          <div class="col-md-4"><div class="kpi"><div class="small-muted">Role menus</div><div style="font-size:22px;font-weight:900">${esc(ops.data.role_menus)}</div></div></div>
          <div class="col-md-4"><div class="kpi"><div class="small-muted">Active IP blocks</div><div style="font-size:22px;font-weight:900">${esc(ops.data.ip_blocks_active)}</div></div></div>
        </div>
      `;
    } else {
      $("#opsBox").textContent = "Failed: " + ops.status;
    }
  }

  async function pageProfile(){
    const me = await bootAuthed("profile"); if(!me) return;
    const out = $("#debugOut");

    $("#profileBox").innerHTML = `
      <div class="row g-3">
        <div class="col-md-6">
          <div class="orland-card p-3">
            <div style="font-weight:900">Info</div>
            <div class="small-muted mt-2">Email: <b>${esc(me.data.email_norm||"")}</b></div>
            <div class="small-muted">Name: <b>${esc(me.data.display_name||"")}</b></div>
            <div class="small-muted">Roles: <b>${esc((me.data.roles||[]).join(", "))}</b></div>
          </div>
        </div>
        <div class="col-md-6">
          <div class="orland-card p-3">
            <div style="font-weight:900">Change Password</div>
            <div class="small-muted mt-2">Min 10 chars.</div>
            <div class="input-group mt-2">
              <input id="pwNew" type="password" class="form-control orland-input" placeholder="new password">
              <button class="btn orland-btn-ghost pw-toggle" type="button" data-target="pwNew"><i class="fa-solid fa-eye"></i></button>
            </div>
            <button id="btnPw" class="orland-btn mt-3 w-100">Update</button>
          </div>
        </div>
      </div>
    `;

    bindPasswordToggles();

    $("#btnPw").onclick = async ()=>{
      const new_password = String($("#pwNew").value||"");
      if(new_password.length<10) return toast("Min 10", "error");
      const r = await api("/api/profile/password", { method:"POST", body: JSON.stringify({ new_password }) });
      if(out) out.textContent = JSON.stringify(r,null,2);
      toast(r.status, r.status==="ok"?"success":"error");
      if(r.status==="ok") $("#pwNew").value="";
    };
  }

  // NOTE: Users/Roles/Menus/RBAC/Security/IPBlocks/Audit/Ops handlers
  // will be included in PART 2/4 & PART 3/4 to keep script stable + not too long in one message.

  document.addEventListener("DOMContentLoaded", async ()=>{
    bindPasswordToggles();

    const dp = document.body.getAttribute("data-page") || "";
    if(dp==="login"){ await pageLogin(); return; }
    if(dp==="setup"){ await pageSetup(); return; }
    if(dp==="reset-request"){ await pageResetRequest(); return; }
    if(dp==="reset-confirm"){ await pageResetConfirm(); return; }

    const page = window.__PAGE__ || "";
    if(page==="overview") return pageOverview();
    if(page==="profile") return pageProfile();

    // Other pages wired in PART 2/4 + PART 3/4
    await bootAuthed("overview");
  });
})();
