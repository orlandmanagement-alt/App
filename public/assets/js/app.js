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

    // Title
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
    };
    const t = map[pageKey] || ["Dashboard",""];
    $("#pageTitle").textContent = t[0];
    $("#pageSubtitle").textContent = t[1];

    return me;
  }

  function renderNav(tree){
    const root = $("#navList");
    if(!root) return;
    const items = [];
    const walk = (node, depth=0)=>{
      items.push({ ...node, depth });
      (node.children||[]).forEach(ch=>walk(ch, depth+1));
    };
    (Array.isArray(tree)?tree:[]).forEach(n=>walk(n,0));

    root.innerHTML = items.map(m=>{
      const pad = 10 + (m.depth*14);
      const icon = m.icon ? `<i class="${esc(m.icon)}"></i>` : `<i class="fa-solid fa-circle-dot" style="opacity:.55"></i>`;
      // Convert backend paths to our multipage filenames when available
      const href = pathToHref(m.path || "");
      return `<a class="nav-item" href="${esc(href)}" style="padding-left:${pad}px" data-href="${esc(href)}">${icon}<span>${esc(m.label||m.code||"Menu")}</span></a>`;
    }).join("");

    const cur = location.pathname;
    $$(".nav-item", root).forEach(a=>a.classList.toggle("active", a.getAttribute("data-href")===cur));
  }

  function pathToHref(p){
    // Map known paths to pages; fallback to dashboard.html
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
    };
    return map[p] || "/dashboard.html";
  }

  // ---------- Page implementations ----------
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

  async function pageUsers(){
    await bootAuthed("users") || (await Promise.resolve());
    const out = $("#debugOut");

    async function load(){
      const q = String($("#q")?.value||"").trim();
      const limit = String($("#limit")?.value||"50").trim();
      const url = "/api/users/admin?limit="+encodeURIComponent(limit) + (q?("&q="+encodeURIComponent(q)):"");
      const r = await api(url);
      if(out) out.textContent = JSON.stringify(r,null,2);
      if(r.status!=="ok"){ $("#usersTable").innerHTML = `<div class="small-muted">Gagal: ${esc(r.status)}</div>`; return; }
      const rows = r.data.users || [];
      $("#usersTable").innerHTML = `
        <table class="table table-darkish table-sm align-middle">
          <thead><tr><th>User</th><th>Status</th><th>Roles</th><th>Last Login</th><th style="width:280px">Action</th></tr></thead>
          <tbody>
            ${rows.map(u=>`
              <tr>
                <td>
                  <div class="d-flex align-items-center gap-2">
                    <img class="avatar" src="${diceBear(u.email_norm||u.id)}" alt="avatar" />
                    <div>
                      <div style="font-weight:800">${esc(u.display_name||"")}</div>
                      <div class="small-muted">${esc(u.email_norm||"")}</div>
                      <div class="small-muted" style="font-size:11px">id: <code>${esc(u.id||"")}</code></div>
                    </div>
                  </div>
                </td>
                <td>${esc(u.status||"")}</td>
                <td>${esc((u.roles||[]).join(", "))}</td>
                <td class="small-muted">${esc(String(u.last_login_at||""))}</td>
                <td>
                  <div class="d-flex flex-wrap gap-2">
                    <button class="orland-btn-ghost btnDisable" data-id="${esc(u.id)}">${u.status==="disabled"?"Enable":"Disable"}</button>
                    <button class="orland-btn-ghost btnReset" data-id="${esc(u.id)}">Reset PW</button>
                    <button class="orland-btn-ghost btnRoles" data-id="${esc(u.id)}">Roles</button>
                    <button class="orland-btn-ghost btnRevoke" data-id="${esc(u.id)}">Revoke</button>
                  </div>
                </td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      `;

      $$(".btnDisable").forEach(btn=>btn.onclick = async ()=>{
        const id = btn.getAttribute("data-id");
        const action = btn.textContent.includes("Enable") ? "enable" : "disable";
        const rr = await api("/api/users/admin", { method:"PUT", body: JSON.stringify({ action, user_id:id }) });
        if(out) out.textContent = JSON.stringify(rr,null,2);
        toast(rr.status, rr.status==="ok"?"success":"error");
        if(rr.status==="ok") await load();
      });

      $$(".btnReset").forEach(btn=>btn.onclick = async ()=>{
        const id = btn.getAttribute("data-id");
        const pw = prompt("New password (min 10):");
        if(!pw || pw.length<10) return toast("Min 10", "error");
        const rr = await api("/api/users/admin", { method:"PUT", body: JSON.stringify({ action:"reset_password", user_id:id, new_password: pw }) });
        if(out) out.textContent = JSON.stringify(rr,null,2);
        toast(rr.status, rr.status==="ok"?"success":"error");
      });

      $$(".btnRoles").forEach(btn=>btn.onclick = async ()=>{
        const id = btn.getAttribute("data-id");
        const roles = prompt("roles comma-separated (staff,admin,super_admin):", "staff") || "";
        const arr = roles.split(",").map(s=>s.trim()).filter(Boolean);
        const rr = await api("/api/users/admin", { method:"PUT", body: JSON.stringify({ action:"set_roles", user_id:id, roles: arr }) });
        if(out) out.textContent = JSON.stringify(rr,null,2);
        toast(rr.status, rr.status==="ok"?"success":"error");
        if(rr.status==="ok") await load();
      });

      $$(".btnRevoke").forEach(btn=>btn.onclick = async ()=>{
        const id = btn.getAttribute("data-id");
        const rr = await api("/api/users/admin", { method:"PUT", body: JSON.stringify({ action:"revoke_sessions", user_id:id }) });
        if(out) out.textContent = JSON.stringify(rr,null,2);
        toast(rr.status, rr.status==="ok"?"success":"error");
      });
    }

    $("#btnReload")?.addEventListener("click", load);
    $("#btnSearch")?.addEventListener("click", load);
    $("#btnCreate")?.addEventListener("click", async ()=>{
      const email = prompt("Email:"); if(!email) return;
      const display_name = prompt("Display name:", "") || "";
      const role = prompt("Role (staff/admin):","staff") || "staff";
      const password = prompt("Password (min 10):","") || "";
      if(password.length<10) return toast("Password min 10", "error");
      const rr = await api("/api/users/admin", { method:"POST", body: JSON.stringify({ email, display_name, role, password }) });
      if(out) out.textContent = JSON.stringify(rr,null,2);
      toast(rr.status, rr.status==="ok"?"success":"error");
      if(rr.status==="ok") await load();
    });

    await load();
  }

  async function pageRoles(){
    await bootAuthed("roles");
    const out = $("#debugOut");

    async function load(){
      const r = await api("/api/roles");
      if(out) out.textContent = JSON.stringify(r,null,2);
      if(r.status!=="ok"){ $("#rolesTable").innerHTML = `<div class="small-muted">Gagal: ${esc(r.status)}</div>`; return; }
      const rows = r.data.roles || [];
      $("#rolesTable").innerHTML = `
        <table class="table table-darkish table-sm align-middle">
          <thead><tr><th>Name</th><th>ID</th><th>Created</th><th style="width:240px">Action</th></tr></thead>
          <tbody>
            ${rows.map(x=>`
              <tr>
                <td><b>${esc(x.name)}</b></td>
                <td class="small-muted"><code>${esc(x.id)}</code></td>
                <td class="small-muted">${esc(String(x.created_at||""))}</td>
                <td>
                  <div class="d-flex gap-2 flex-wrap">
                    <button class="orland-btn-ghost btnEdit" data-id="${esc(x.id)}" data-name="${esc(x.name)}">Edit</button>
                    <button class="orland-btn-ghost btnDel" data-id="${esc(x.id)}">Delete</button>
                  </div>
                </td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      `;

      $$(".btnEdit").forEach(b=>b.onclick = async ()=>{
        const id=b.getAttribute("data-id");
        const cur=b.getAttribute("data-name");
        const name=prompt("Role name:", cur) || "";
        if(!name.trim()) return;
        const rr = await api("/api/roles", { method:"PUT", body: JSON.stringify({ id, name }) });
        if(out) out.textContent = JSON.stringify(rr,null,2);
        toast(rr.status, rr.status==="ok"?"success":"error");
        if(rr.status==="ok") await load();
      });

      $$(".btnDel").forEach(b=>b.onclick = async ()=>{
        const id=b.getAttribute("data-id");
        if(!confirm("Delete role?")) return;
        const rr = await api("/api/roles?id="+encodeURIComponent(id), { method:"DELETE" });
        if(out) out.textContent = JSON.stringify(rr,null,2);
        toast(rr.status, rr.status==="ok"?"success":"error");
        if(rr.status==="ok") await load();
      });
    }

    $("#btnReload")?.addEventListener("click", load);
    $("#btnCreate")?.addEventListener("click", async ()=>{
      const name = prompt("Role name:", "");
      if(!name) return;
      const rr = await api("/api/roles", { method:"POST", body: JSON.stringify({ name }) });
      if(out) out.textContent = JSON.stringify(rr,null,2);
      toast(rr.status, rr.status==="ok"?"success":"error");
      if(rr.status==="ok") await load();
    });

    await load();
  }

  async function pageMenus(){
    await bootAuthed("menus");
    const out = $("#debugOut");

    async function load(){
      const r = await api("/api/menus");
      if(out) out.textContent = JSON.stringify(r,null,2);
      if(r.status!=="ok"){ $("#menusTable").innerHTML = `<div class="small-muted">Gagal: ${esc(r.status)}</div>`; return; }
      const rows = r.data.menus || [];
      $("#menusTable").innerHTML = `
        <table class="table table-darkish table-sm align-middle">
          <thead><tr><th>Menu</th><th>Path</th><th>Parent</th><th>Sort</th><th>Icon</th><th style="width:220px">Action</th></tr></thead>
          <tbody>
            ${rows.map(m=>`
              <tr>
                <td><b>${esc(m.label)}</b> <span class="small-muted">(${esc(m.code)})</span><div class="small-muted" style="font-size:11px">id: <code>${esc(m.id)}</code></div></td>
                <td class="small-muted">${esc(m.path)}</td>
                <td class="small-muted"><code>${esc(m.parent_id||"")}</code></td>
                <td>${esc(String(m.sort_order||""))}</td>
                <td>${m.icon ? `<i class="${esc(m.icon)}"></i> <span class="small-muted">${esc(m.icon)}</span>` : `<span class="small-muted">-</span>`}</td>
                <td>
                  <div class="d-flex gap-2 flex-wrap">
                    <button class="orland-btn-ghost btnFill" data-json='${esc(JSON.stringify(m))}'>Fill</button>
                    <button class="orland-btn-ghost btnDel" data-id="${esc(m.id)}">Delete</button>
                  </div>
                </td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      `;

      $$(".btnFill").forEach(b=>b.onclick = ()=>{
        const obj = JSON.parse(b.getAttribute("data-json") || "{}");
        $("#id").value = obj.id || "";
        $("#code").value = obj.code || "";
        $("#label").value = obj.label || "";
        $("#path").value = obj.path || "";
        $("#parent_id").value = obj.parent_id || "";
        $("#sort_order").value = String(obj.sort_order ?? 50);
        $("#icon").value = obj.icon || "";
        toast("Form filled", "info");
      });

      $$(".btnDel").forEach(b=>b.onclick = async ()=>{
        const id=b.getAttribute("data-id");
        if(!confirm("Delete menu?")) return;
        const rr = await api("/api/menus?id="+encodeURIComponent(id), { method:"DELETE" });
        if(out) out.textContent = JSON.stringify(rr,null,2);
        toast(rr.status, rr.status==="ok"?"success":"error");
        if(rr.status==="ok") await load();
      });
    }

    $("#btnReload")?.addEventListener("click", load);

    $("#btnSeed")?.addEventListener("click", async ()=>{
      const rr = await api("/api/menus/seed", { method:"POST", body:"{}" });
      if(out) out.textContent = JSON.stringify(rr,null,2);
      toast(rr.status, rr.status==="ok"?"success":"error");
      if(rr.status==="ok") await load();
    });

    $("#btnUpsert")?.addEventListener("click", async ()=>{
      const payload = {
        id: String($("#id").value||"").trim() || null,
        code: String($("#code").value||"").trim(),
        label: String($("#label").value||"").trim(),
        path: String($("#path").value||"").trim(),
        parent_id: String($("#parent_id").value||"").trim() || null,
        sort_order: Number(String($("#sort_order").value||"50")),
        icon: String($("#icon").value||"").trim() || null,
      };
      const rr = await api("/api/menus", { method:"POST", body: JSON.stringify(payload) });
      if(out) out.textContent = JSON.stringify(rr,null,2);
      toast(rr.status, rr.status==="ok"?"success":"error");
      if(rr.status==="ok") await load();
    });

    await load();
  }

  async function pageRbac(){
    await bootAuthed("rbac");
    const out = $("#debugOut");

    let roles=[], menus=[], role_menus=[];

    async function load(){
      const r = await api("/api/rbac/bundle");
      if(out) out.textContent = JSON.stringify(r,null,2);
      if(r.status!=="ok"){ $("#menuChecks").innerHTML = `<div class="small-muted">Gagal: ${esc(r.status)}</div>`; return; }
      roles = r.data.roles || [];
      menus = r.data.menus || [];
      role_menus = r.data.role_menus || [];

      $("#roleSelect").innerHTML = roles.map(x=>`<option value="${esc(x.id)}">${esc(x.name)}</option>`).join("");
      renderChecks();
    }

    function renderChecks(){
      const rid = $("#roleSelect").value;
      const set = new Set(role_menus.filter(x=>x.role_id===rid).map(x=>x.menu_id));
      $("#menuChecks").innerHTML = menus.map(m=>`
        <div class="col-md-4">
          <label class="orland-card p-2 d-flex gap-2 align-items-start" style="cursor:pointer">
            <input type="checkbox" data-mid="${esc(m.id)}" ${set.has(m.id)?"checked":""} style="margin-top:4px">
            <div>
              <div style="font-weight:800">${m.icon?`<i class="${esc(m.icon)} me-2"></i>`:""}${esc(m.label)}</div>
              <div class="small-muted" style="font-size:12px">${esc(m.path)} • <code>${esc(m.code)}</code></div>
            </div>
          </label>
        </div>
      `).join("");
    }

    $("#roleSelect")?.addEventListener("change", renderChecks);
    $("#btnReload")?.addEventListener("click", load);

    $("#btnSave")?.addEventListener("click", async ()=>{
      const rid = $("#roleSelect").value;
      const menu_ids = $$("#menuChecks input[type=checkbox]").filter(x=>x.checked).map(x=>x.getAttribute("data-mid"));
      const rr = await api("/api/role-menus/set", { method:"POST", body: JSON.stringify({ role_id: rid, menu_ids }) });
      if(out) out.textContent = JSON.stringify(rr,null,2);
      toast(rr.status, rr.status==="ok"?"success":"error");
      if(rr.status==="ok") await load();
    });

    await load();
  }

  async function pageSecurity(){
    await bootAuthed("security");
    const out = $("#debugOut");

    async function loadMetrics(){
      const days = $("#days").value || "7";
      const r = await api("/api/security/metrics?days="+encodeURIComponent(days));
      if(out) out.textContent = JSON.stringify(r,null,2);
      if(r.status!=="ok"){ toast("Failed: "+r.status, "error"); return; }
      const series = r.data.series || [];
      const sum = (k)=>series.reduce((a,x)=>a+Number(x[k]||0),0);

      $("#kpiActiveBlocks").textContent = r.data.active_ip_blocks;
      $("#kpiPwFail").textContent = sum("password_fail");
      $("#kpiRate").textContent = sum("rate_limited");
      $("#kpiAnom").textContent = sum("session_anomaly");
    }

    async function loadChart(){
      const days = $("#days").value || "7";
      const r = await api("/api/security/hourly?days="+encodeURIComponent(days));
      if(out) out.textContent = JSON.stringify({ hourly:r }, null, 2);
      if(r.status!=="ok"){ $("#chart").textContent = "Failed: "+r.status; return; }
      const rows = r.data.rows || [];
      if(!window.ApexCharts){
        $("#chart").innerHTML = `<div class="small-muted">ApexCharts tidak ter-load. Rows: ${rows.length}</div>`;
        return;
      }
      const labels = rows.map(x=>new Date(Number(x.hour_epoch||0)*1000).toISOString().slice(0,13)+":00");
      const pw = rows.map(x=>Number(x.password_fail||0));
      const an = rows.map(x=>Number(x.session_anomaly||0));
      const ot = rows.map(x=>Number(x.otp_verify_fail||0));

      $("#chart").innerHTML = "";
      const chart = new ApexCharts($("#chart"), {
        chart: { type:"line", height: 320, toolbar:{ show:false } },
        series: [
          { name:"password_fail", data: pw },
          { name:"session_anomaly", data: an },
          { name:"otp_verify_fail", data: ot },
        ],
        xaxis: { categories: labels, labels: { show:false } },
        stroke: { width: 2 },
        dataLabels: { enabled:false },
        legend: { position:"top" }
      });
      chart.render();
    }

    async function loadTop(){
      const r = await api("/api/security/ip-activity?kind=password_fail&minutes=240&limit=20");
      if(out) out.textContent = JSON.stringify({ top:r }, null, 2);
      if(r.status!=="ok"){ $("#topTable").innerHTML = `<div class="small-muted">Failed: ${esc(r.status)}</div>`; return; }
      const rows=r.data.rows||[];
      $("#topTable").innerHTML = `
        <table class="table table-darkish table-sm align-middle">
          <thead><tr><th>IP Hash</th><th>Total</th><th>Last Seen</th></tr></thead>
          <tbody>
            ${rows.map(x=>`
              <tr>
                <td><code>${esc(x.ip_hash||"")}</code></td>
                <td><b>${esc(String(x.total||0))}</b></td>
                <td class="small-muted">${esc(String(x.last_seen_at||""))}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      `;
    }

    $("#btnLoad")?.addEventListener("click", async ()=>{ await loadMetrics(); await loadChart(); });
    $("#btnTop")?.addEventListener("click", loadTop);
    $("#days")?.addEventListener("change", async ()=>{ await loadMetrics(); await loadChart(); });

    await loadMetrics();
    await loadChart();
    await loadTop();
  }

  async function pageIpBlocks(){
    await bootAuthed("ipblocks");
    const out = $("#debugOut");

    async function load(){
      const r = await api("/api/ip-blocks?active=1&limit=100");
      if(out) out.textContent = JSON.stringify(r,null,2);
      if(r.status!=="ok"){ $("#blocksTable").innerHTML = `<div class="small-muted">Failed: ${esc(r.status)}</div>`; return; }
      const rows = r.data.blocks || [];
      $("#blocksTable").innerHTML = `
        <table class="table table-darkish table-sm align-middle">
          <thead><tr><th>Reason</th><th>Expires</th><th>IP Hash</th><th>Action</th></tr></thead>
          <tbody>
            ${rows.map(b=>`
              <tr>
                <td>${esc(b.reason||"")}</td>
                <td class="small-muted">${esc(String(b.expires_at||""))}</td>
                <td><code>${esc(b.ip_hash||"")}</code></td>
                <td><button class="orland-btn-ghost btnUnblock" data-id="${esc(b.id)}">Unblock</button></td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      `;
      $$(".btnUnblock").forEach(btn=>btn.onclick = async ()=>{
        const id = btn.getAttribute("data-id");
        const rr = await api("/api/ip-blocks/unblock", { method:"POST", body: JSON.stringify({ id }) });
        if(out) out.textContent = JSON.stringify(rr,null,2);
        toast(rr.status, rr.status==="ok"?"success":"error");
        if(rr.status==="ok") await load();
      });
    }

    $("#btnReload")?.addEventListener("click", load);
    $("#btnPurge")?.addEventListener("click", async ()=>{
      const rr = await api("/api/ip-blocks/purge", { method:"POST", body:"{}" });
      if(out) out.textContent = JSON.stringify(rr,null,2);
      toast("Purged: "+(rr.data?.revoked||0), "info");
      await load();
    });
    $("#btnBlock")?.addEventListener("click", async ()=>{
      const ip_hash = prompt("ip_hash:"); if(!ip_hash) return;
      const ttl_sec = Number(prompt("ttl_sec (default 3600):","3600")||"3600");
      const reason = prompt("reason:", "manual_block") || "manual_block";
      const rr = await api("/api/ip-blocks/block", { method:"POST", body: JSON.stringify({ ip_hash, ttl_sec, reason }) });
      if(out) out.textContent = JSON.stringify(rr,null,2);
      toast(rr.status, rr.status==="ok"?"success":"error");
      if(rr.status==="ok") await load();
    });

    await load();
  }

  async function pageAudit(){
    await bootAuthed("audit");
    const out = $("#debugOut");

    async function load(){
      const q = String($("#q")?.value||"").trim();
      const url = "/api/audit?limit=80" + (q?("&q="+encodeURIComponent(q)):"");
      const r = await api(url);
      if(out) out.textContent = JSON.stringify(r,null,2);
      if(r.status!=="ok"){ $("#auditTable").innerHTML = `<div class="small-muted">Failed: ${esc(r.status)}</div>`; return; }
      const rows = r.data.rows || [];
      $("#auditTable").innerHTML = `
        <table class="table table-darkish table-sm align-middle">
          <thead><tr><th>Action</th><th>Route</th><th>Status</th><th>Actor</th><th>At</th></tr></thead>
          <tbody>
            ${rows.map(x=>`
              <tr>
                <td><code>${esc(x.action||"")}</code></td>
                <td class="small-muted">${esc(x.route||x.target_id||"")}</td>
                <td>${esc(String(x.http_status||""))}</td>
                <td class="small-muted"><code>${esc(x.actor_user_id||"")}</code></td>
                <td class="small-muted">${esc(String(x.created_at||""))}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      `;
    }

    $("#btnReload")?.addEventListener("click", load);
    $("#q")?.addEventListener("keydown", (e)=>{ if(e.key==="Enter") load(); });
    await load();
  }

  async function pageOps(){
    await bootAuthed("ops");
    const out = $("#debugOut");

    async function load(){
      const r = await api("/api/ops/status");
      if(out) out.textContent = JSON.stringify(r,null,2);
      if(r.status!=="ok"){ $("#opsTable").innerHTML = `<div class="small-muted">Failed: ${esc(r.status)}</div>`; return; }
      const x = r.data;
      $("#opsTable").innerHTML = `
        <table class="table table-darkish table-sm align-middle">
          <tbody>
            <tr><td>users</td><td><b>${esc(x.users)}</b></td></tr>
            <tr><td>roles</td><td><b>${esc(x.roles)}</b></td></tr>
            <tr><td>menus</td><td><b>${esc(x.menus)}</b></td></tr>
            <tr><td>role_menus</td><td><b>${esc(x.role_menus)}</b></td></tr>
            <tr><td>incidents_open</td><td><b>${esc(x.incidents_open)}</b></td></tr>
            <tr><td>ip_blocks_active</td><td><b>${esc(x.ip_blocks_active)}</b></td></tr>
            <tr><td>now</td><td class="small-muted">${esc(String(x.now||""))}</td></tr>
          </tbody>
        </table>
      `;
    }

    $("#btnReload")?.addEventListener("click", load);
    await load();
  }

  // ---------- Boot ----------
  document.addEventListener("DOMContentLoaded", async ()=>{
    bindPasswordToggles();

    const dp = document.body.getAttribute("data-page") || "";
    if(dp==="login"){ await pageLogin(); return; }
    if(dp==="setup"){ await pageSetup(); return; }
    if(dp==="reset-request"){ await pageResetRequest(); return; }
    if(dp==="reset-confirm"){ await pageResetConfirm(); return; }

    // Authed multipage by window.__PAGE__
    const page = window.__PAGE__ || "";
    if(page==="overview") return pageOverview();
    if(page==="users") return pageUsers();
    if(page==="roles") return pageRoles();
    if(page==="menus") return pageMenus();
    if(page==="rbac") return pageRbac();
    if(page==="security") return pageSecurity();
    if(page==="ipblocks") return pageIpBlocks();
    if(page==="audit") return pageAudit();
    if(page==="ops") return pageOps();

    // fallback
    await bootAuthed("overview");
  });
})();