/* app.js — FINAL (single file)
 * Enterprise Login + Dashboard (Blogspot SPA)
 * Backend: Cloudflare Worker JSON API + D1 + KV
 *
 * Works with the FINAL worker.js I gave you:
 * - Setup bootstrap super_admin:
 *    GET  /setup/status
 *    POST /setup/bootstrap_superadmin
 * - Login:
 *    POST /auth/login/password        (OTP ONLY for client/talent -> action "user_login")
 *    POST /auth/challenge/otp/request
 *    POST /auth/challenge/otp/verify
 *    POST /auth/logout
 *    GET  /me
 * - Password reset (self-service):
 *    POST /auth/password/reset/request
 *    POST /auth/password/reset/confirm
 * - Admin:
 *    GET  /admin/roles
 *    GET  /admin/menus
 *    POST /admin/menus/upsert         (step-up rbac_write)
 *    POST /admin/role-menus/set       (step-up rbac_write)
 *    GET  /admin/audit
 *    GET  /admin/users
 *    POST /admin/users/reset_password (step-up rbac_write)  // super_admin
 *    GET  /admin/tasks
 *    POST /admin/tasks/enqueue        (step-up rbac_write)
 *    GET  /admin/dlq
 *    POST /admin/dlq/retry            (step-up rbac_write)
 *    POST /admin/maintenance/cleanup  (step-up rbac_write)
 *
 * IMPORTANT:
 * - Set window.API_BASE in theme.xml (or leave blank for same-origin)
 * - Mount: <div id="dashboard"></div>
 */
(() => {
  "use strict";

  // ==========================================================
  // CONFIG
  // ==========================================================
  const API_BASE = (window.API_BASE || "https://admin-enterprise-login.orlandmanagement.workers.dev"); // "" = same origin
  const TOKEN_KEY = "auth_token";
  const CHALLENGE_KEY = "challenge_token";

  const app = document.getElementById("dashboard");
  if (!app) return;

  // ==========================================================
  // UTILS
  // ==========================================================
  const U = {
    nowSec() { return Math.floor(Date.now() / 1000); },
    esc(s) { return String(s ?? "").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;"); },
    fmtTs(sec){
      try {
        const n = Number(sec);
        if (!n) return "";
        return new Date(n * 1000).toISOString();
      } catch { return String(sec); }
    },
    qs(sel, root){ return (root||document).querySelector(sel); },
    qsa(sel, root){ return Array.from((root||document).querySelectorAll(sel)); },
  };

  function injectStyles(css){
    const st = document.createElement("style");
    st.textContent = css;
    document.head.appendChild(st);
  }

  injectStyles(`
    :root{--b:#e9e9ef;--bg:#f6f7fb;--fg:#111;--mut:#6b7280;--card:#fff;}
    *{box-sizing:border-box}
    body{margin:0;background:var(--bg);color:var(--fg);font-family:Arial,sans-serif}
    a{color:inherit;text-decoration:none}
    code{font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace}
    .wrap{display:flex;min-height:100vh}
    .sidebar{width:260px;border-right:1px solid var(--b);padding:14px;background:var(--card)}
    .brand{font-weight:900;font-size:16px}
    .meta{margin-top:10px;padding:10px;border:1px solid var(--b);border-radius:14px}
    .u{font-weight:800}
    .r{opacity:.7;font-size:12px;margin-top:4px}
    .menu{margin-top:12px;display:grid;gap:8px}
    .nav{display:block;padding:10px;border:1px solid var(--b);border-radius:14px}
    .nav:hover{background:#fafafa}
    .footer{margin-top:12px}
    .main{flex:1;padding:14px}
    .btn{padding:10px 12px;border:1px solid #ddd;border-radius:14px;background:#111;color:#fff;cursor:pointer}
    .btn:disabled{opacity:.5;cursor:not-allowed}
    .btn.ghost{background:#fff;color:#111}
    .row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
    .card{border:1px solid var(--b);border-radius:14px;background:var(--card);padding:12px}
    .grid{display:grid;gap:10px}
    .grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:10px}
    input,select{padding:10px;border:1px solid #ddd;border-radius:12px}
    pre{white-space:pre-wrap;background:#f7f7f7;padding:10px;border-radius:12px;max-height:360px;overflow:auto}
    .small{opacity:.75;font-size:12px}
    @media(max-width:740px){.wrap{flex-direction:column}.sidebar{width:auto}}
  `);

  // ==========================================================
  // API CLIENT
  // ==========================================================
  const API = {
    getToken(){ return localStorage.getItem(TOKEN_KEY) || ""; },
    setToken(t){ if(t) localStorage.setItem(TOKEN_KEY,t); else localStorage.removeItem(TOKEN_KEY); },
    getChallenge(){ return localStorage.getItem(CHALLENGE_KEY) || ""; },
    setChallenge(t){ if(t) localStorage.setItem(CHALLENGE_KEY,t); else localStorage.removeItem(CHALLENGE_KEY); },

    async req(path, opt = {}) {
  const base = String(API_BASE || "");
  const url = base
    ? (base.replace(/\/+$/, "") + "/" + String(path || "").replace(/^\/+/, ""))
    : path;

  const headers = Object.assign({}, opt.headers || {});
  // hanya set content-type kalau memang ada body
  if (opt.body != null && !headers["content-type"]) headers["content-type"] = "application/json";

  const tok = API.getToken();
  if (tok) headers["authorization"] = "Bearer " + tok;

  if (opt.useChallenge) {
    const ch = API.getChallenge();
    if (ch) headers["x-challenge-token"] = ch;
  }

  try {
    const res = await fetch(url, {
      method: opt.method || "GET",
      headers,
      body: opt.body || undefined
    });

    // kalau bukan JSON, tetap balikin status+http supaya kebaca
    const ct = res.headers.get("content-type") || "";
    if (!ct.includes("application/json")) {
      const text = await res.text().catch(() => "");
      return { status: "server_error", data: { message: "non_json_response", http: res.status, body: text.slice(0, 300) } };
    }

    return await res.json();
  } catch (e) {
    // ini yang sekarang bikin "Uncaught Failed to fetch"
    return { status: "network_error", data: { message: String(e?.message || e), url } };
  }
}
  // ==========================================================
  // ROUTER
  // ==========================================================
  const Router = {
    routes: {},
    on(path, fn){ this.routes[path] = fn; },
    go(path){ location.hash = "#" + path; },
    cur(){ return (location.hash || "#/login").slice(1); },
    parse(){
      const h = Router.cur();
      const [p, qs] = h.split("?");
      const q = {};
      if(qs){
        qs.split("&").forEach(kv=>{
          const [k,v] = kv.split("=");
          q[decodeURIComponent(k)] = decodeURIComponent(v||"");
        });
      }
      return { path: p || "/login", q };
    },
    async render(){
      const { path, q } = Router.parse();
      const fn = Router.routes[path] || Router.routes["/404"];
      if(fn) await fn(q);
    }
  };
  window.addEventListener("hashchange", () => Router.render());

  // ==========================================================
  // UI CORE
  // ==========================================================
  const UI = {
    shell(me, menus){
      const name = (me?.display_name || me?.id || "User");
      const roles = (me?.roles || []).join(", ");
      const menuHtml = (menus||[]).map(m => `<a class="nav" href="#${m.path}">${U.esc(m.label)}</a>`).join("");
      return `
        <div class="wrap">
          <div class="sidebar">
            <div class="brand">Enterprise Dashboard</div>
            <div class="meta">
              <div class="u">${U.esc(name)}</div>
              <div class="r">${U.esc(roles || "-")}</div>
            </div>
            <div class="menu">${menuHtml || `<a class="nav" href="#/home">Home</a>`}</div>
            <div class="footer">
              <button class="btn ghost" id="logout">Logout</button>
            </div>
          </div>
          <div class="main"><div id="main"></div></div>
        </div>
      `;
    },

    async stepUpAuto(action, emailIfNeeded){
      // Request OTP
      const reqBody = (action === "user_login")
        ? { action, email: String(emailIfNeeded||"").trim().toLowerCase() }
        : { action };

      const r1 = await API.req("/auth/challenge/otp/request", { method:"POST", body: JSON.stringify(reqBody) });
      if (r1.status !== "ok") { alert("OTP request failed: " + r1.status); return false; }

      const otp_ref = r1.data?.otp_ref;
      const otp = prompt("Masukkan OTP 6 digit (cek email):");
      if (!otp) return false;

      const r2 = await API.req("/auth/challenge/otp/verify", {
        method:"POST",
        body: JSON.stringify({ action, otp, otp_ref, email: emailIfNeeded })
      });

      if (r2.status !== "ok") { alert("OTP verify failed: " + r2.status); return false; }

      if (r2.data?.token) { // user_login returns token
        API.setToken(r2.data.token);
        return true;
      }
      if (r2.data?.challenge_token) {
        API.setChallenge(r2.data.challenge_token);
        return true;
      }
      return true;
    }
  };

  // ==========================================================
  // AUTH + MENU LOADER
  // ==========================================================
  async function getMe(){
    const r = await API.req("/me", { method:"GET" });
    if (r.status !== "ok") return null;
    return r.data;
  }

  async function loadMenuForUser(me){
    const roles = me?.roles || [];

    // If super_admin, prefer menus from backend
    if (roles.includes("super_admin")) {
      const r = await API.req("/admin/menus", { method:"GET" });
      if (r.status === "ok") {
        return (r.data?.menus || []).map(m => ({ path: m.path, label: m.label }));
      }
    }

    // fallback menus (safe, only routes implemented in this app.js)
    const baseAdmin = [
      { path:"/home", label:"Home" },
      { path:"/users", label:"Users" },
      { path:"/audit", label:"Audit" },
      { path:"/rbac", label:"RBAC" },
      { path:"/tasks", label:"Tasks" },
      { path:"/dlq", label:"DLQ" },
      { path:"/maintenance", label:"Maintenance" },
      { path:"/about", label:"About" },
    ];

    const baseNonAdmin = [
      { path:"/home", label:"Home" },
      { path:"/about", label:"About" },
    ];

    if (roles.includes("super_admin") || roles.includes("admin") || roles.includes("staff")) return baseAdmin;
    return baseNonAdmin;
  }

  async function guarded(renderFn){
    const me = await getMe();
    if (!me) return Router.go("/login");

    const menus = await loadMenuForUser(me);
    app.innerHTML = UI.shell(me, menus);

    U.qs("#logout").onclick = async () => {
      await API.req("/auth/logout", { method:"POST", body:"{}" });
      API.setToken("");
      API.setChallenge("");
      Router.go("/login");
    };

    await renderFn(me);
  }

  // ==========================================================
  // PAGES
  // ==========================================================

  // --- SETUP (bootstrap super_admin) ---
  Router.on("/setup", async () => {
    const st = await API.req("/setup/status", { method:"GET" });
    if (st.status === "ok" && !st.data?.setup_required) {
      Router.go("/login");
      return;
    }

    app.innerHTML = `
      <div class="card" style="max-width:460px;margin:28px auto;padding:14px">
        <h2 style="margin:0 0 10px">Initial Setup</h2>
        <div class="small" style="margin-bottom:12px">
          Buat akun <b>Super Admin</b> pertama. Setelah dibuat, halaman ini otomatis nonaktif.
        </div>

        <input id="name" placeholder="display name (optional)" style="width:100%">
        <div style="height:8px"></div>
        <input id="email" placeholder="email" style="width:100%">
        <div style="height:8px"></div>
        <input id="pass" type="password" placeholder="password (min 10)" style="width:100%">
        <div style="height:12px"></div>

        <button class="btn" id="go" style="width:100%">Create Super Admin</button>
        <div class="small" style="margin-top:10px"><a href="#/login">Ke halaman login</a></div>
        <pre id="out" style="margin-top:12px"></pre>
      </div>
    `;

    const out = U.qs("#out");
    U.qs("#go").onclick = async () => {
      const display_name = String(U.qs("#name").value||"").trim();
      const email = String(U.qs("#email").value||"").trim().toLowerCase();
      const password = String(U.qs("#pass").value||"");

      const r = await API.req("/setup/bootstrap_superadmin", {
        method:"POST",
        body: JSON.stringify({ display_name, email, password })
      });
      out.textContent = JSON.stringify(r, null, 2);

      if (r.status === "ok" && r.data?.token) {
        API.setToken(r.data.token);
        Router.go("/home");
        return;
      }
      alert("Gagal: " + r.status);
    };
  });

  // --- LOGIN ---
  Router.on("/login", async () => {
    app.innerHTML = `
      <div class="card" style="max-width:420px;margin:28px auto;padding:14px">
        <h2 style="margin:0 0 10px">Login</h2>
        <div class="small" style="margin-bottom:12px">
          Login password. <b>Client/Talent</b> akan diminta OTP (cek email).
        </div>

        <input id="email" placeholder="email" style="width:100%">
        <div style="height:8px"></div>
        <input id="pass" type="password" placeholder="password" style="width:100%">
        <div style="height:12px"></div>

        <button class="btn" id="go" style="width:100%">Login</button>

        <div class="small" style="margin-top:10px">
          <a href="#/forgot">Lupa password?</a>
        </div>

        <details style="margin-top:10px">
          <summary class="small">Debug JSON</summary>
          <pre id="out"></pre>
        </details>
      </div>
    `;
    const out = U.qs("#out");

    U.qs("#go").onclick = async () => {
      const email = String(U.qs("#email").value||"").trim().toLowerCase();
      const password = String(U.qs("#pass").value||"");

      const r = await API.req("/auth/login/password", { method:"POST", body: JSON.stringify({ email, password }) });
      out.textContent = JSON.stringify(r, null, 2);

      if (r.status === "ok" && r.data?.token) {
        API.setToken(r.data.token);
        Router.go("/home");
        return;
      }

      if (r.status === "challenge_required" && r.data?.action === "user_login") {
        const ok = await UI.stepUpAuto("user_login", email);
        if (ok) Router.go("/home");
        return;
      }

      alert("Login failed: " + r.status);
    };
  });

  // --- FORGOT PASSWORD (B) ---
  Router.on("/forgot", async () => {
    app.innerHTML = `
      <div class="card" style="max-width:420px;margin:28px auto;padding:14px">
        <h2 style="margin:0 0 10px">Reset Password</h2>
        <div class="small" style="margin-bottom:12px">Masukkan email, kami kirim link reset.</div>
        <input id="email" placeholder="email" style="width:100%">
        <div style="height:12px"></div>
        <button class="btn" id="go" style="width:100%">Kirim Link</button>
        <div class="small" style="margin-top:10px"><a href="#/login">Kembali login</a></div>
        <pre id="out" style="margin-top:12px"></pre>
      </div>
    `;
    const out = U.qs("#out");
    U.qs("#go").onclick = async () => {
      const email = String(U.qs("#email").value||"").trim().toLowerCase();
      const r = await API.req("/auth/password/reset/request", { method:"POST", body: JSON.stringify({ email }) });
      out.textContent = JSON.stringify(r, null, 2);
      alert("Jika email terdaftar, link reset akan dikirim.");
    };
  });

  // --- RESET PASSWORD CONFIRM (B) ---
  Router.on("/reset", async (q) => {
    const token = q.token || "";
    app.innerHTML = `
      <div class="card" style="max-width:420px;margin:28px auto;padding:14px">
        <h2 style="margin:0 0 10px">Set Password Baru</h2>
        <div class="small" style="margin-bottom:12px">Password minimal 10 karakter.</div>
        <input id="p1" type="password" placeholder="password baru" style="width:100%">
        <div style="height:8px"></div>
        <input id="p2" type="password" placeholder="ulang password" style="width:100%">
        <div style="height:12px"></div>
        <button class="btn" id="go" style="width:100%">Update Password</button>
        <div class="small" style="margin-top:10px"><a href="#/login">Kembali login</a></div>
        <pre id="out" style="margin-top:12px"></pre>
      </div>
    `;
    const out = U.qs("#out");
    U.qs("#go").onclick = async () => {
      const p1 = String(U.qs("#p1").value||"");
      const p2 = String(U.qs("#p2").value||"");
      if (p1 !== p2) return alert("Password tidak sama");
      const r = await API.req("/auth/password/reset/confirm", { method:"POST", body: JSON.stringify({ token, new_password: p1 }) });
      out.textContent = JSON.stringify(r, null, 2);
      if (r.status === "ok") {
        alert("Password berhasil diubah. Silakan login.");
        Router.go("/login");
      } else {
        alert("Gagal: " + r.status);
      }
    };
  });

  // --- HOME ---
  Router.on("/home", async () => guarded(async (me) => {
    const main = U.qs("#main");
    main.innerHTML = `
      <h2 style="margin:0">Home</h2>
      <div class="small" style="margin-top:6px">Welcome, ${U.esc(me.display_name || me.id)}</div>
      <div class="row" style="margin-top:12px">
        <a class="btn" href="#/users">Users</a>
        <a class="btn" href="#/audit">Audit</a>
        <a class="btn" href="#/tasks">Tasks</a>
        <a class="btn" href="#/about">About</a>
      </div>
      <div class="small" style="margin-top:12px">API_BASE: <code>${U.esc(API_BASE || "(same-origin)")}</code></div>
    `;
  }));

  // --- AUDIT ---
  Router.on("/audit", async () => guarded(async () => {
    const main = U.qs("#main");
    main.innerHTML = `
      <h2>Audit Logs</h2>
      <div class="row">
        <input id="q" placeholder="filter action (auth., rbac., otp., tasks.)" style="flex:1;min-width:220px">
        <input id="since" inputmode="numeric" placeholder="since epoch sec (optional)" style="width:220px">
        <select id="limit">
          <option>20</option><option selected>50</option><option>100</option><option>200</option>
        </select>
        <button id="load" class="btn">Load</button>
      </div>

      <div id="list" class="grid" style="margin-top:12px"></div>
      <pre id="out" style="margin-top:12px"></pre>
    `;

    const out = U.qs("#out");
    const list = U.qs("#list");

    async function load(){
      const q = U.qs("#q").value.trim();
      const since = U.qs("#since").value.trim();
      const limit = U.qs("#limit").value;

      const url = `/admin/audit?limit=${encodeURIComponent(limit)}`
        + (q ? `&q=${encodeURIComponent(q)}` : "")
        + (since ? `&since=${encodeURIComponent(since)}` : "");

      const r = await API.req(url, { method:"GET" });
      out.textContent = JSON.stringify(r, null, 2);

      const rows = r.data?.rows || [];
      list.innerHTML = rows.map(x => `
        <div class="card">
          <div><b>${U.esc(x.action)}</b></div>
          <div class="small" style="margin-top:4px">${U.esc(U.fmtTs(x.created_at))} • actor: <code>${U.esc(x.actor_user_id||"")}</code></div>
          <div class="small">target: ${U.esc(x.target_type||"")} <code>${U.esc(x.target_id||"")}</code></div>
        </div>
      `).join("") || `<div class="small">No rows</div>`;
    }

    U.qs("#load").onclick = load;
    await load();
  }));

  // --- RBAC ---
  Router.on("/rbac", async () => guarded(async () => {
    const main = U.qs("#main");
    main.innerHTML = `
      <h2>RBAC Manager</h2>
      <div class="small">Super Admin only</div>

      <div class="card" style="margin-top:12px">
        <h3 style="margin:0 0 10px">Upsert Menu (step-up)</h3>
        <div class="row">
          <input id="mid" placeholder="id (optional)" style="flex:1;min-width:160px">
          <input id="mcode" placeholder="code" style="flex:1;min-width:160px">
          <input id="mlabel" placeholder="label" style="flex:1;min-width:160px">
          <input id="mpath" placeholder="/path" style="flex:1;min-width:160px">
          <input id="mparent" placeholder="parent_id (optional)" style="flex:1;min-width:160px">
          <input id="msort" inputmode="numeric" value="50" style="width:110px">
          <button id="mupsert" class="btn">Save</button>
        </div>
      </div>

      <div class="card" style="margin-top:12px">
        <h3 style="margin:0 0 10px">Assign Menus to Role (step-up)</h3>
        <div class="row">
          <select id="role" style="min-width:220px"></select>
          <button id="saveRoleMenus" class="btn">Save Role Menus</button>
          <button id="reload" class="btn">Reload</button>
        </div>
        <div id="menuChecks" class="grid2" style="margin-top:12px"></div>
      </div>

      <h3 style="margin-top:14px">Menus</h3>
      <div id="menus" class="grid" style="margin-top:10px"></div>

      <pre id="out" style="margin-top:12px"></pre>
    `;

    const out = U.qs("#out");
    const menusEl = U.qs("#menus");
    const roleSel = U.qs("#role");
    const checksEl = U.qs("#menuChecks");

    let allMenus = [];
    let roleMenus = [];
    let roles = [];

    async function loadAll(){
      const r1 = await API.req("/admin/menus", { method:"GET" });
      const r2 = await API.req("/admin/roles", { method:"GET" });
      out.textContent = JSON.stringify({ menus:r1, roles:r2 }, null, 2);
      if (r1.status!=="ok" || r2.status!=="ok") return;

      allMenus = (r1.data?.menus || []).map(m => ({ id:m.id, code:m.code, label:m.label, path:m.path, parent_id:m.parent_id, sort_order:m.sort_order }));
      roleMenus = r1.data?.role_menus || [];
      roles = r2.data?.roles || [];
      roleSel.innerHTML = roles.map(r => `<option value="${U.esc(r.id)}">${U.esc(r.name)}</option>`).join("");

      renderMenusList();
      renderCheckboxes();
    }

    function currentRoleId(){ return roleSel.value; }

    function renderMenusList(){
      menusEl.innerHTML = allMenus.map(m => `
        <div class="card" style="display:flex;justify-content:space-between;gap:10px;align-items:center">
          <div>
            <div><b>${U.esc(m.label)}</b> <span class="small">(${U.esc(m.code)})</span></div>
            <div class="small">${U.esc(m.path)} • id: <code>${U.esc(m.id)}</code></div>
            <div class="small">parent: <code>${U.esc(m.parent_id||"")}</code> • sort: ${U.esc(m.sort_order)}</div>
          </div>
          <button class="btn fill"
            data-id="${U.esc(m.id)}" data-code="${U.esc(m.code)}" data-label="${U.esc(m.label)}"
            data-path="${U.esc(m.path)}" data-parent="${U.esc(m.parent_id||"")}" data-sort="${U.esc(m.sort_order)}"
          >Edit</button>
        </div>
      `).join("") || `<div class="small">No menus</div>`;

      U.qsa(".fill", menusEl).forEach(b => {
        b.onclick = () => {
          U.qs("#mid").value = b.getAttribute("data-id")||"";
          U.qs("#mcode").value = b.getAttribute("data-code")||"";
          U.qs("#mlabel").value = b.getAttribute("data-label")||"";
          U.qs("#mpath").value = b.getAttribute("data-path")||"";
          U.qs("#mparent").value = b.getAttribute("data-parent")||"";
          U.qs("#msort").value = b.getAttribute("data-sort")||"50";
        };
      });
    }

    function renderCheckboxes(){
      const rid = currentRoleId();
      const set = new Set(roleMenus.filter(x => x.role_id===rid).map(x => x.menu_id));
      checksEl.innerHTML = allMenus.map(m => `
        <label class="card" style="display:flex;gap:10px;align-items:flex-start">
          <input type="checkbox" data-mid="${U.esc(m.id)}" ${set.has(m.id) ? "checked" : ""}>
          <div>
            <div style="font-weight:800">${U.esc(m.label)}</div>
            <div class="small">${U.esc(m.path)} • ${U.esc(m.code)}</div>
          </div>
        </label>
      `).join("");
    }

    roleSel.onchange = renderCheckboxes;
    U.qs("#reload").onclick = loadAll;

    U.qs("#mupsert").onclick = async () => {
      const ok = await UI.stepUpAuto("rbac_write");
      if (!ok) return;

      const payload = {
        id: U.qs("#mid").value.trim() || null,
        code: U.qs("#mcode").value.trim(),
        label: U.qs("#mlabel").value.trim(),
        path: U.qs("#mpath").value.trim(),
        parent_id: U.qs("#mparent").value.trim() || null,
        sort_order: Number(U.qs("#msort").value || "50")
      };
      const r = await API.req("/admin/menus/upsert", { method:"POST", body: JSON.stringify(payload), useChallenge:true });
      out.textContent = JSON.stringify(r, null, 2);
      await loadAll();
    };

    U.qs("#saveRoleMenus").onclick = async () => {
      const ok = await UI.stepUpAuto("rbac_write");
      if (!ok) return;

      const rid = currentRoleId();
      const menu_ids = U.qsa("input[type=checkbox]", checksEl).filter(x => x.checked).map(x => x.getAttribute("data-mid"));
      const r = await API.req("/admin/role-menus/set", { method:"POST", body: JSON.stringify({ role_id: rid, menu_ids }), useChallenge:true });
      out.textContent = JSON.stringify(r, null, 2);
      await loadAll();
    };

    await loadAll();
  }));

  // --- USERS (list + super_admin reset password A) ---
  Router.on("/users", async () => guarded(async (me) => {
    const main = U.qs("#main");
    main.innerHTML = `
      <h2>Users</h2>
      <div class="row">
        <input id="q" placeholder="search name/email" style="flex:1;min-width:220px">
        <button id="load" class="btn">Load</button>
      </div>

      <div id="list" class="grid" style="margin-top:12px"></div>

      <div class="card" style="margin-top:12px;max-width:980px">
        <h3 style="margin:0 0 10px">Reset Password User (Super Admin) (step-up)</h3>
        <div class="row">
          <input id="rp_uid" placeholder="user_id" style="flex:1;min-width:260px">
          <button id="rp_pick" class="btn">Use Picked</button>
          <button id="rp_gen" class="btn">Generate</button>
          <input id="rp_pass" placeholder="password baru (min 10)" style="flex:1;min-width:220px">
          <button id="rp_set" class="btn">Reset Password</button>
        </div>
        <div id="rp_info" class="small" style="margin-top:8px"></div>
        <div class="small" style="margin-top:6px">Catatan: gunakan channel aman untuk share password.</div>
      </div>

      <pre id="out" style="margin-top:12px"></pre>
    `;

    const out = U.qs("#out");
    const list = U.qs("#list");
    const rpInfo = U.qs("#rp_info");

    function genStrongPassword(len=14){
      const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%";
      let s = "";
      const arr = new Uint8Array(len);
      crypto.getRandomValues(arr);
      for (let i=0;i<len;i++) s += chars[arr[i] % chars.length];
      return s;
    }

    let pickedUserId = "";

    async function load(){
      const q = U.qs("#q").value.trim();
      const r = await API.req(`/admin/users?limit=50${q?`&q=${encodeURIComponent(q)}`:""}`, { method:"GET" });
      out.textContent = JSON.stringify(r, null, 2);

      const rows = r.data?.users || [];
      list.innerHTML = rows.map(u => `
        <div class="card" style="display:flex;justify-content:space-between;gap:10px;align-items:center">
          <div>
            <div><b>${U.esc(u.display_name||"")}</b> <span class="small">${U.esc(u.status||"")}</span></div>
            <div class="small">${U.esc(u.email_masked||"")}</div>
            <div class="small">id: <code>${U.esc(u.id)}</code></div>
          </div>
          <button class="btn pick" data-id="${U.esc(u.id)}">Pick</button>
        </div>
      `).join("") || `<div class="small">No users</div>`;

      U.qsa(".pick", list).forEach(b => {
        b.onclick = () => {
          const id = b.getAttribute("data-id") || "";
          pickedUserId = id;
          U.qs("#rp_uid").value = id;
          rpInfo.textContent = "Picked user_id diisi ke field reset.";
        };
      });
    }

    U.qs("#load").onclick = load;

    U.qs("#rp_pick").onclick = () => {
      if (pickedUserId) U.qs("#rp_uid").value = pickedUserId;
      rpInfo.textContent = pickedUserId ? "Use Picked OK." : "Belum ada user yang dipilih.";
    };

    U.qs("#rp_gen").onclick = () => {
      const pw = genStrongPassword(14);
      U.qs("#rp_pass").value = pw;
      rpInfo.textContent = "Password baru sudah digenerate. Copy sekarang (akan di-clear otomatis 30 detik).";
      setTimeout(()=>{ if (U.qs("#rp_pass").value === pw){ U.qs("#rp_pass").value=""; rpInfo.textContent="Password field cleared."; } }, 30000);
    };

    U.qs("#rp_set").onclick = async () => {
      // only super_admin should do this; backend enforces too
      if (!(me.roles||[]).includes("super_admin")) return alert("Hanya super_admin yang boleh reset password user.");

      const ok = await UI.stepUpAuto("rbac_write"); if(!ok) return;
      const user_id = U.qs("#rp_uid").value.trim();
      const new_password = U.qs("#rp_pass").value;

      if(!user_id || String(new_password).length < 10) return alert("user_id & password min 10 diperlukan");

      const r = await API.req("/admin/users/reset_password", {
        method:"POST",
        body: JSON.stringify({ user_id, new_password }),
        useChallenge:true
      });
      out.textContent = JSON.stringify(r, null, 2);

      if (r.status === "ok"){
        rpInfo.textContent = "Reset berhasil.";
        alert("Reset password berhasil.");
        // optional clear
        U.qs("#rp_pass").value = "";
      } else {
        rpInfo.textContent = "Gagal: " + r.status;
        alert("Gagal: " + r.status);
      }
    };

    await load();
  }));

  // --- TASKS ---
  Router.on("/tasks", async () => guarded(async () => {
    const main = U.qs("#main");
    main.innerHTML = `
      <h2>Tasks</h2>
      <div class="row">
        <select id="status">
          <option value="">all</option>
          <option value="queued">queued</option>
          <option value="processing">processing</option>
          <option value="done">done</option>
          <option value="dlq">dlq</option>
        </select>
        <select id="type">
          <option value="">all</option>
          <option value="cleanup">cleanup</option>
          <option value="send_otp">send_otp</option>
          <option value="custom">custom</option>
        </select>
        <button id="load" class="btn">Load</button>
        <a class="btn" href="#/dlq">DLQ</a>
        <button id="enqueueCleanup" class="btn">Enqueue Cleanup (step-up)</button>
      </div>

      <div id="list" class="grid" style="margin-top:12px"></div>
      <pre id="out" style="margin-top:12px"></pre>
    `;

    const out = U.qs("#out");
    const list = U.qs("#list");

    async function load(){
      const status = U.qs("#status").value;
      const type = U.qs("#type").value;
      let url = `/admin/tasks?limit=50`;
      if (status) url += `&status=${encodeURIComponent(status)}`;
      if (type) url += `&type=${encodeURIComponent(type)}`;
      const r = await API.req(url, { method:"GET" });
      out.textContent = JSON.stringify(r, null, 2);

      const rows = r.data?.tasks || [];
      list.innerHTML = rows.map(t => `
        <div class="card">
          <div><b>${U.esc(t.type)}</b> — <span class="small">${U.esc(t.status)}</span> • attempts: ${U.esc(t.attempts)}/${U.esc(t.max_attempts)}</div>
          <div class="small">run_at: ${U.esc(U.fmtTs(t.run_at))}</div>
          ${t.last_error ? `<div class="small">err: ${U.esc(t.last_error)}</div>` : ``}
          <div class="small">id: <code>${U.esc(t.id)}</code></div>
        </div>
      `).join("") || `<div class="small">No tasks</div>`;
    }

    U.qs("#load").onclick = load;

    U.qs("#enqueueCleanup").onclick = async () => {
      const ok = await UI.stepUpAuto("rbac_write");
      if (!ok) return;
      const r = await API.req("/admin/tasks/enqueue", { method:"POST", body: JSON.stringify({ type:"cleanup", payload:{}, delay_sec:0, max_attempts:3 }), useChallenge:true });
      out.textContent = JSON.stringify(r, null, 2);
      await load();
    };

    await load();
  }));

  // --- DLQ ---
  Router.on("/dlq", async () => guarded(async () => {
    const main = U.qs("#main");
    main.innerHTML = `
      <h2>DLQ</h2>
      <div class="row">
        <button id="load" class="btn">Load</button>
        <a class="btn" href="#/tasks">Tasks</a>
      </div>

      <div id="list" class="grid" style="margin-top:12px"></div>
      <pre id="out" style="margin-top:12px"></pre>
    `;

    const out = U.qs("#out");
    const list = U.qs("#list");

    async function load(){
      const r = await API.req(`/admin/dlq?limit=50`, { method:"GET" });
      out.textContent = JSON.stringify(r, null, 2);

      const rows = r.data?.dlq || [];
      list.innerHTML = rows.map(d => `
        <div class="card">
          <div class="row" style="justify-content:space-between">
            <div>
              <div><b>DLQ</b> • <span class="small">${U.esc(U.fmtTs(d.created_at))}</span></div>
              <div class="small">task_id: <code>${U.esc(d.task_id)}</code></div>
              <div class="small">reason: ${U.esc(d.reason||"")}</div>
              <div class="small">dlq_id: ${U.esc(d.id)}</div>
            </div>
            <button class="btn retry" data-id="${U.esc(d.id)}">Retry (step-up)</button>
          </div>
        </div>
      `).join("") || `<div class="small">No DLQ items</div>`;

      U.qsa(".retry", list).forEach(b => {
        b.onclick = async () => {
          const ok = await UI.stepUpAuto("rbac_write");
          if (!ok) return;
          const id = b.getAttribute("data-id");
          const r2 = await API.req("/admin/dlq/retry", { method:"POST", body: JSON.stringify({ id }), useChallenge:true });
          out.textContent = JSON.stringify(r2, null, 2);
          await load();
        };
      });
    }

    U.qs("#load").onclick = load;
    await load();
  }));

  // --- MAINTENANCE ---
  Router.on("/maintenance", async () => guarded(async () => {
    const main = U.qs("#main");
    main.innerHTML = `
      <h2>Maintenance</h2>
      <div class="row" style="margin-top:10px">
        <button id="cleanup" class="btn">Run Cleanup (step-up)</button>
      </div>
      <pre id="out" style="margin-top:12px"></pre>
    `;

    const out = U.qs("#out");

    U.qs("#cleanup").onclick = async () => {
      const ok = await UI.stepUpAuto("rbac_write"); if(!ok) return;
      const r = await API.req("/admin/maintenance/cleanup", { method:"POST", body:"{}", useChallenge:true });
      out.textContent = JSON.stringify(r, null, 2);
    };
  }));

  // --- ABOUT ---
  Router.on("/about", async () => guarded(async () => {
    const main = U.qs("#main");
    main.innerHTML = `
      <h2>About</h2>
      <div class="card" style="margin-top:12px">
        <div class="small">SPA frontend for Enterprise Login.</div>
        <div class="small" style="margin-top:6px">API_BASE: <code>${U.esc(API_BASE || "(same-origin)")}</code></div>
        <div style="margin-top:10px" class="row">
          <button id="health" class="btn">/health</button>
          <button id="setup" class="btn">/setup/status</button>
        </div>
      </div>
      <pre id="out" style="margin-top:12px"></pre>
    `;
    const out = U.qs("#out");
    U.qs("#health").onclick = async () => { out.textContent = JSON.stringify(await API.req("/health",{method:"GET"}), null, 2); };
    U.qs("#setup").onclick = async () => { out.textContent = JSON.stringify(await API.req("/setup/status",{method:"GET"}), null, 2); };
  }));

  // --- 404 ---
  Router.on("/404", async () => {
    app.innerHTML = `<div class="card" style="max-width:720px;margin:28px auto">
      <b>Not found</b> — <a href="#/home">Go Home</a>
    </div>`;
  });

  // ==========================================================
  // BOOT
  // ==========================================================
  (async () => {
    // If already logged in, go home
    if (API.getToken()) {
      Router.go("/home");
      await Router.render();
      return;
    }

    // If not logged in, check setup requirement
    const st = await API.req("/setup/status", { method:"GET" });
    if (st.status === "ok" && st.data?.setup_required) {
      Router.go("/setup");
      await Router.render();
      return;
    }

    await Router.render();
  })();
})();
