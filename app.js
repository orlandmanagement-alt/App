/* app.js — FINAL (single file)
 * Enterprise Login + Dashboard (Blogspot SPA)
 * Backend: Cloudflare Worker JSON API + D1 + KV
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
  const API_BASE = (window.API_BASE || ""); // "" = same origin
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
    fmtTs(sec){ try { return new Date(Number(sec)*1000).toISOString(); } catch { return String(sec); } },
    qs(sel, root){ return (root||document).querySelector(sel); },
    qsa(sel, root){ return Array.from((root||document).querySelectorAll(sel)); }
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
      const url = API_BASE ? (API_BASE + path) : path;

      const headers = Object.assign({ "content-type":"application/json" }, opt.headers || {});
      const tok = API.getToken();
      if (tok) headers["authorization"] = "Bearer " + tok;
      if (opt.useChallenge) {
        const ch = API.getChallenge();
        if (ch) headers["x-challenge-token"] = ch;
      }

      const res = await fetch(url, {
        method: opt.method || "GET",
        headers,
        body: opt.body || undefined
      });

      // Some endpoints return attachments; for UI we usually want JSON.
      let data = null;
      try { data = await res.json(); }
      catch { data = { status:"server_error", data:{ message:"non_json_response", http:res.status } }; }
      return data;
    }
  };

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
              <div class="r">${U.esc(roles)}</div>
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
      const reqBody = (action === "admin_login")
        ? { action, email: String(emailIfNeeded||"").trim().toLowerCase() }
        : { action };

      const r1 = await API.req("/auth/challenge/otp/request", { method:"POST", body: JSON.stringify(reqBody) });
      if (r1.status !== "ok") { alert("OTP request failed: " + r1.status); return false; }

      const otp_ref = r1.data?.otp_ref;
      const otp = prompt("Masukkan OTP 6 digit:");
      if (!otp) return false;

      const r2 = await API.req("/auth/challenge/otp/verify", {
        method:"POST",
        body: JSON.stringify({ action, otp, otp_ref, email: emailIfNeeded })
      });

      if (r2.status !== "ok") { alert("OTP verify failed: " + r2.status); return false; }

      if (r2.data?.token) { // admin_login returns token
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
    // If super_admin, load full menus list; else fallback safe list.
    const roles = me?.roles || [];
    if (roles.includes("super_admin")) {
      const r = await API.req("/admin/menus", { method:"GET" });
      if (r.status === "ok") {
        // Show admin pages (paths in our SPA)
        // Map menu path from backend to SPA route if needed.
        // Here we use the backend path as hash route path (e.g., "/users").
        return (r.data?.menus || []).map(m => ({ path: m.path, label: m.label }));
      }
    }

    // fallback menu (minimal)
    const base = [
      { path:"/home", label:"Home" },
      { path:"/security", label:"Security" },
      { path:"/audit", label:"Audit" },
      { path:"/incidents", label:"Incidents" },
      { path:"/projects", label:"Projects" },
      { path:"/users", label:"Users" },
      { path:"/tasks", label:"Tasks" },
      { path:"/backup", label:"Backups" },
      { path:"/maintenance", label:"Maintenance" },
      { path:"/about", label:"About" },
    ];
    if (roles.includes("admin")) return base;
    if (roles.includes("staff")) return base.filter(x => ["/home","/incidents","/projects","/audit","/about"].includes(x.path));
    if (roles.includes("talent")) return [{path:"/home",label:"Home"},{path:"/talent",label:"My Schedule"},{path:"/about",label:"About"}];
    if (roles.includes("client")) return [{path:"/home",label:"Home"},{path:"/projects",label:"Projects"},{path:"/about",label:"About"}];
    return [{path:"/home",label:"Home"}];
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

  // --- LOGIN ---
  Router.on("/login", async () => {
    app.innerHTML = `
      <div class="card" style="max-width:420px;margin:28px auto;padding:14px">
        <h2 style="margin:0 0 10px">Login</h2>
        <div style="opacity:.7;font-size:12px;margin-bottom:12px">Password login, admin requires OTP</div>
        <input id="email" placeholder="email" style="width:100%">
        <div style="height:8px"></div>
        <input id="pass" type="password" placeholder="password" style="width:100%">
        <div style="height:12px"></div>
        <button class="btn" id="go" style="width:100%">Login</button>
        <pre id="out" style="margin-top:12px"></pre>
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
      if (r.status === "challenge_required" && r.data?.action === "admin_login") {
        const ok = await UI.stepUpAuto("admin_login", email);
        if (ok) Router.go("/home");
        return;
      }
      alert("Login failed: " + r.status);
    };
  });

  // --- HOME ---
  Router.on("/home", async () => guarded(async (me) => {
    const main = U.qs("#main");
    main.innerHTML = `
      <h2 style="margin:0">Home</h2>
      <div style="opacity:.7;margin-top:6px">Welcome, ${U.esc(me.display_name || me.id)}</div>
      <div class="row" style="margin-top:12px">
        <a class="btn" href="#/security">Security</a>
        <a class="btn" href="#/audit">Audit</a>
        <a class="btn" href="#/incidents">Incidents</a>
        <a class="btn" href="#/projects">Projects</a>
      </div>
      <div style="margin-top:12px;opacity:.7;font-size:12px">API_BASE: ${U.esc(API_BASE || "(same-origin)")}</div>
    `;
  }));

  // --- SECURITY DASHBOARD ---
  Router.on("/security", async () => guarded(async () => {
    const main = U.qs("#main");
    main.innerHTML = `
      <div class="row" style="justify-content:space-between">
        <div>
          <h2 style="margin:0">Security Dashboard</h2>
          <div style="opacity:.7;font-size:12px;margin-top:6px">Metrics + recent incidents</div>
        </div>
        <div class="row">
          <select id="days">
            <option value="7" selected>Last 7 days</option>
            <option value="30">Last 30 days</option>
          </select>
          <button id="reload" class="btn">Reload</button>
        </div>
      </div>

      <div id="state" class="card" style="margin-top:12px;display:none"></div>
      <div id="cards" class="grid2" style="margin-top:12px"></div>

      <div class="card" style="margin-top:12px">
        <h3 style="margin:0 0 10px">Trend</h3>
        <div id="chart" style="opacity:.7">Loading…</div>
      </div>

      <div class="card" style="margin-top:12px">
        <div class="row" style="justify-content:space-between">
          <h3 style="margin:0">Recent Incidents</h3>
          <a class="btn" href="#/incidents">Open List</a>
        </div>
        <div id="incList" class="grid" style="margin-top:10px"></div>
      </div>

      <details style="margin-top:12px">
        <summary>Debug JSON</summary>
        <pre id="out"></pre>
      </details>
    `;

    const out = U.qs("#out");
    const state = U.qs("#state");
    const cards = U.qs("#cards");
    const incList = U.qs("#incList");

    function showError(msg){
      state.style.display = "block";
      state.innerHTML = `<b>Failed</b><div style="opacity:.85;margin-top:4px">${U.esc(msg||"unknown")}</div>`;
    }

    function buildCards(summary){
      const sev = summary.incidents_by_severity || [];
      const sevMap = {}; sev.forEach(x => sevMap[x.severity] = x.cnt);
      const series = summary.series || [];
      const sum = (k)=>series.reduce((a,r)=>a+Number(r[k]||0),0);
      cards.innerHTML = `
        <div class="card"><div style="opacity:.7;font-size:12px">Active IP Blocks</div><div style="font-size:26px;font-weight:900">${U.esc(summary.active_ip_blocks)}</div></div>
        <div class="card"><div style="opacity:.7;font-size:12px">Incidents (critical/high)</div><div style="font-size:26px;font-weight:900">${U.esc((sevMap.critical||0)+(sevMap.high||0))}</div><div style="opacity:.7;font-size:12px">critical: ${U.esc(sevMap.critical||0)} • high: ${U.esc(sevMap.high||0)}</div></div>
        <div class="card"><div style="opacity:.7;font-size:12px">Password fail total</div><div style="font-size:26px;font-weight:900">${U.esc(sum("password_fail"))}</div></div>
        <div class="card"><div style="opacity:.7;font-size:12px">OTP/anomaly total</div><div style="font-size:26px;font-weight:900">${U.esc(sum("otp_verify_fail")+sum("session_anomaly"))}</div></div>
      `;
    }

    function renderIncidents(incs){
      incList.innerHTML = (incs||[]).map(x => `
        <div class="card" style="display:flex;justify-content:space-between;gap:10px;align-items:center">
          <div>
            <div><b>${U.esc(x.severity)}</b> — ${U.esc(x.type)} — <span style="opacity:.7">${U.esc(x.status)}</span></div>
            <div style="opacity:.7;font-size:12px;margin-top:4px">${U.esc(x.summary||"")}</div>
            <div style="opacity:.6;font-size:12px">${U.esc(U.fmtTs(x.created_at))} • id: <code>${U.esc(x.id)}</code></div>
          </div>
          <a class="btn" href="#/incident?id=${encodeURIComponent(x.id)}">Open</a>
        </div>
      `).join("") || `<div style="opacity:.7">No incidents</div>`;
    }

    function renderChart(rows){
      const el = U.qs("#chart");
      if (!window.ApexCharts) { el.innerHTML = `<div style="opacity:.7">ApexCharts not loaded.</div>`; return; }
      el.innerHTML = "";
      const labels = rows.map(r => r.day_key);
      const pw = rows.map(r => Number(r.password_fail||0));
      const otp = rows.map(r => Number(r.otp_verify_fail||0));
      const anom = rows.map(r => Number(r.session_anomaly||0));
      const chart = new ApexCharts(el, {
        chart: { type:"line", height:280, toolbar:{ show:false } },
        series: [
          { name:"password_fail", data: pw },
          { name:"otp_verify_fail", data: otp },
          { name:"session_anomaly", data: anom },
        ],
        xaxis: { categories: labels },
        stroke: { width: 2 },
        dataLabels: { enabled:false },
        legend: { position:"top" }
      });
      chart.render();
    }

    async function load(){
      state.style.display = "none";
      cards.innerHTML = `<div class="card">Loading…</div>`.repeat(4);
      incList.innerHTML = `<div style="opacity:.7">Loading…</div>`;
      const days = U.qs("#days").value;

      const r1 = await API.req(`/admin/security/summary?days=${encodeURIComponent(days)}`, { method:"GET" });
      const r2 = await API.req(`/admin/security/incidents?limit=10`, { method:"GET" });

      out.textContent = JSON.stringify({ summary:r1, incidents:r2 }, null, 2);

      if (r1.status !== "ok") return showError(r1.status);
      if (r2.status !== "ok") return showError(r2.status);

      buildCards(r1.data);
      renderChart(r1.data.series || []);
      renderIncidents(r2.data.incidents || []);
    }

    U.qs("#reload").onclick = load;
    U.qs("#days").onchange = load;
    await load();
  }));

  // --- AUDIT ---
  Router.on("/audit", async () => guarded(async () => {
    const main = U.qs("#main");
    main.innerHTML = `
      <h2>Audit Logs</h2>
      <div class="row">
        <input id="q" placeholder="filter action (auth., rbac., ipblock., wa.)" style="flex:1;min-width:220px">
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
          <div style="opacity:.7;font-size:12px;margin-top:4px">${U.esc(U.fmtTs(x.created_at))} • actor: <code>${U.esc(x.actor_user_id||"")}</code></div>
          <div style="opacity:.7;font-size:12px">target: ${U.esc(x.target_type||"")} <code>${U.esc(x.target_id||"")}</code></div>
        </div>
      `).join("") || `<div style="opacity:.7">No rows</div>`;
    }

    U.qs("#load").onclick = load;
    await load();
  }));

  // --- RBAC ---
  Router.on("/rbac", async () => guarded(async () => {
    const main = U.qs("#main");
    main.innerHTML = `
      <h2>RBAC Manager</h2>
      <div style="opacity:.7">Super Admin only</div>

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
            <div><b>${U.esc(m.label)}</b> <span style="opacity:.7">(${U.esc(m.code)})</span></div>
            <div style="opacity:.7;font-size:12px">${U.esc(m.path)} • id: <code>${U.esc(m.id)}</code></div>
            <div style="opacity:.6;font-size:12px">parent: <code>${U.esc(m.parent_id||"")}</code> • sort: ${U.esc(m.sort_order)}</div>
          </div>
          <button class="btn fill"
            data-id="${U.esc(m.id)}" data-code="${U.esc(m.code)}" data-label="${U.esc(m.label)}"
            data-path="${U.esc(m.path)}" data-parent="${U.esc(m.parent_id||"")}" data-sort="${U.esc(m.sort_order)}"
          >Edit</button>
        </div>
      `).join("") || `<div style="opacity:.7">No menus</div>`;

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
            <div style="opacity:.7;font-size:12px">${U.esc(m.path)} • ${U.esc(m.code)}</div>
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

  // --- IPBLOCKS ---
  Router.on("/ipblocks", async () => guarded(async () => {
    const main = U.qs("#main");
    main.innerHTML = `
      <h2>IP Blocks</h2>
      <div class="row"><button id="load" class="btn">Load</button></div>

      <div class="card" style="margin-top:12px">
        <h3 style="margin:0 0 10px">Block by ip_hash (step-up)</h3>
        <div class="row">
          <input id="ip_hash" placeholder="ip_hash" style="flex:2;min-width:260px">
          <input id="ttl" inputmode="numeric" value="3600" style="width:140px">
          <button id="block" class="btn">Block</button>
        </div>
      </div>

      <div id="list" class="grid" style="margin-top:12px"></div>
      <pre id="out" style="margin-top:12px"></pre>
    `;

    const out = U.qs("#out");
    const list = U.qs("#list");

    async function load(){
      const r = await API.req("/admin/ipblocks", { method:"GET" });
      out.textContent = JSON.stringify(r, null, 2);

      const blocks = r.data?.blocks || [];
      list.innerHTML = blocks.map(b => `
        <div class="card" style="display:flex;justify-content:space-between;gap:10px;align-items:center">
          <div>
            <div><b>${U.esc(b.reason)}</b> • expires ${U.esc(U.fmtTs(b.expires_at))}</div>
            <div style="opacity:.7;font-size:12px">ip_hash: <code>${U.esc(b.ip_hash)}</code></div>
            <div style="opacity:.6;font-size:12px">id: ${U.esc(b.id)}</div>
          </div>
          <button class="btn unb" data-id="${U.esc(b.id)}">Unblock (step-up)</button>
        </div>
      `).join("") || `<div style="opacity:.7">No active blocks</div>`;

      U.qsa(".unb", list).forEach(btn => {
        btn.onclick = async () => {
          const ok = await UI.stepUpAuto("rbac_write");
          if (!ok) return;
          const id = btn.getAttribute("data-id");
          const r2 = await API.req("/admin/ipblocks/unblock", { method:"POST", body: JSON.stringify({ id }), useChallenge:true });
          out.textContent = JSON.stringify(r2, null, 2);
          await load();
        };
      });
    }

    U.qs("#load").onclick = load;

    U.qs("#block").onclick = async () => {
      const ok = await UI.stepUpAuto("rbac_write");
      if (!ok) return;
      const ip_hash = U.qs("#ip_hash").value.trim();
      const ttl_sec = Number(U.qs("#ttl").value || "3600");
      const r = await API.req("/admin/ipblocks/block", { method:"POST", body: JSON.stringify({ ip_hash, ttl_sec, reason:"manual_block" }), useChallenge:true });
      out.textContent = JSON.stringify(r, null, 2);
      await load();
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
          <option value="notify_incident">notify_incident</option>
          <option value="backup">backup</option>
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
          <div><b>${U.esc(t.type)}</b> — <span style="opacity:.7">${U.esc(t.status)}</span> • attempts: ${U.esc(t.attempts)}</div>
          <div style="opacity:.7;font-size:12px">next_run: ${U.esc(U.fmtTs(t.next_run_at))}</div>
          ${t.last_error ? `<div style="opacity:.7;font-size:12px">err: ${U.esc(t.last_error)}</div>` : ``}
          <div style="opacity:.6;font-size:12px">id: <code>${U.esc(t.id)}</code></div>
        </div>
      `).join("") || `<div style="opacity:.7">No tasks</div>`;
    }

    U.qs("#load").onclick = load;

    U.qs("#enqueueCleanup").onclick = async () => {
      const ok = await UI.stepUpAuto("rbac_write");
      if (!ok) return;
      const r = await API.req("/admin/tasks/enqueue", { method:"POST", body: JSON.stringify({ type:"cleanup", payload:{}, delay_sec:0 }), useChallenge:true });
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
              <div><b>${U.esc(d.type)}</b> • <span style="opacity:.7">${U.esc(U.fmtTs(d.created_at))}</span></div>
              <div style="opacity:.7;font-size:12px">task_id: <code>${U.esc(d.task_id)}</code></div>
              <div style="opacity:.7;font-size:12px">error: ${U.esc(d.error||"")}</div>
              <div style="opacity:.6;font-size:12px">dlq_id: ${U.esc(d.id)}</div>
            </div>
            <button class="btn retry" data-id="${U.esc(d.id)}">Retry (step-up)</button>
          </div>
        </div>
      `).join("") || `<div style="opacity:.7">No DLQ items</div>`;

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

  // --- BACKUPS ---
  Router.on("/backup", async () => guarded(async () => {
    const main = U.qs("#main");
    main.innerHTML = `
      <h2>Backups</h2>
      <div class="card" style="margin-top:12px">
        <h3 style="margin:0 0 10px">Create backup</h3>
        <div class="row">
          <select id="mode"><option value="redacted" selected>redacted</option><option value="full">full</option></select>
          <select id="dest"><option value="r2" selected>r2</option><option value="download">download</option></select>
          <button id="create" class="btn">Create (step-up)</button>
          <button id="create_dl" class="btn">Create & Download (GET)</button>
          <button id="purge" class="btn">Purge old (step-up)</button>
          <button id="reload" class="btn">Reload</button>
        </div>
      </div>

      <div id="list" class="grid" style="margin-top:12px"></div>
      <pre id="out" style="margin-top:12px"></pre>
    `;

    const out = U.qs("#out");
    const list = U.qs("#list");

    async function load(){
      const r = await API.req("/admin/backup/list", { method:"GET" });
      out.textContent = JSON.stringify(r, null, 2);

      const arr = r.data?.backups || [];
      list.innerHTML = arr.map(b => `
        <div class="card" style="display:flex;justify-content:space-between;gap:10px;align-items:center">
          <div>
            <div><b>${U.esc(b.mode)}</b> • ${U.esc(b.destination)} • ${U.esc(b.status)}</div>
            <div style="opacity:.7;font-size:12px">id: <code>${U.esc(b.id)}</code> • size: ${U.esc(b.size_bytes||"")}</div>
            <div style="opacity:.6;font-size:12px">sha256: ${U.esc(b.sha256||"")}</div>
          </div>
          <div class="row">
            <button class="btn dl" data-id="${U.esc(b.id)}" ${b.destination==="r2" ? "" : "disabled"}>Download (step-up)</button>
            <button class="btn ver" data-id="${U.esc(b.id)}" ${b.destination==="r2" ? "" : "disabled"}>Verify</button>
            <button class="btn chk" data-id="${U.esc(b.id)}" ${b.destination==="r2" ? "" : "disabled"}>Check</button>
          </div>
        </div>
      `).join("") || `<div style="opacity:.7">No backups</div>`;

      U.qsa(".dl", list).forEach(btn => {
        btn.onclick = async () => {
          const ok = await UI.stepUpAuto("rbac_write");
          if (!ok) return;
          const id = btn.getAttribute("data-id");
          window.open(`/admin/backup/download?id=${encodeURIComponent(id)}`, "_blank");
        };
      });

      U.qsa(".ver", list).forEach(btn => {
        btn.onclick = async () => {
          const ok = await UI.stepUpAuto("rbac_write");
          if (!ok) return;
          const id = btn.getAttribute("data-id");
          const r2 = await API.req(`/admin/backup/verify?id=${encodeURIComponent(id)}`, { method:"GET", useChallenge:true });
          out.textContent = JSON.stringify(r2, null, 2);
        };
      });

      U.qsa(".chk", list).forEach(btn => {
        btn.onclick = async () => {
          const ok = await UI.stepUpAuto("rbac_write");
          if (!ok) return;
          const id = btn.getAttribute("data-id");
          const r2 = await API.req(`/admin/backup/check?id=${encodeURIComponent(id)}`, { method:"GET", useChallenge:true });
          out.textContent = JSON.stringify(r2, null, 2);
        };
      });
    }

    U.qs("#reload").onclick = load;

    U.qs("#purge").onclick = async () => {
      const ok = await UI.stepUpAuto("rbac_write");
      if (!ok) return;
      const r = await API.req("/admin/backup/purge", { method:"POST", body:"{}", useChallenge:true });
      out.textContent = JSON.stringify(r, null, 2);
      await load();
    };

    U.qs("#create").onclick = async () => {
      const ok = await UI.stepUpAuto("rbac_write");
      if (!ok) return;
      const mode = U.qs("#mode").value;
      const destination = U.qs("#dest").value;
      const r = await API.req("/admin/backup/create", { method:"POST", body: JSON.stringify({ mode, destination }), useChallenge:true });
      out.textContent = JSON.stringify(r, null, 2);
      await load();
    };

    U.qs("#create_dl").onclick = async () => {
      const ok = await UI.stepUpAuto("rbac_write");
      if (!ok) return;
      const mode = U.qs("#mode").value;
      const ch = API.getChallenge();
      window.open(`/admin/backup/create_download?mode=${encodeURIComponent(mode)}&challenge_token=${encodeURIComponent(ch)}`, "_blank");
    };

    await load();
  }));

  // --- MAINTENANCE ---
  Router.on("/maintenance", async () => guarded(async () => {
    const main = U.qs("#main");
    main.innerHTML = `
      <h2>Maintenance</h2>
      <div class="row" style="margin-top:10px">
        <button id="smoke" class="btn">Run Smoke Check (step-up)</button>
        <button id="migrate" class="btn">Apply Missing Migrations (step-up)</button>
        <button id="cleanup" class="btn">Run Cleanup (step-up)</button>
      </div>
      <pre id="out" style="margin-top:12px"></pre>
    `;

    const out = U.qs("#out");

    U.qs("#smoke").onclick = async () => {
      const ok = await UI.stepUpAuto("rbac_write"); if(!ok) return;
      const r = await API.req("/admin/maintenance/smoke", { method:"GET", useChallenge:true });
      out.textContent = JSON.stringify(r, null, 2);
    };

    U.qs("#migrate").onclick = async () => {
      const ok = await UI.stepUpAuto("rbac_write"); if(!ok) return;
      const r = await API.req("/admin/maintenance/migrate_missing", { method:"POST", body:"{}", useChallenge:true });
      out.textContent = JSON.stringify(r, null, 2);
    };

    U.qs("#cleanup").onclick = async () => {
      const ok = await UI.stepUpAuto("rbac_write"); if(!ok) return;
      const r = await API.req("/admin/maintenance/cleanup", { method:"POST", body:"{}", useChallenge:true });
      out.textContent = JSON.stringify(r, null, 2);
    };
  }));

  // --- USERS (WA phone + token) ---
  Router.on("/users", async () => guarded(async () => {
    const main = U.qs("#main");
    main.innerHTML = `
      <h2>Users</h2>
      <div class="row">
        <input id="q" placeholder="search name/email" style="flex:1;min-width:220px">
        <button id="load" class="btn">Load</button>
      </div>

      <div id="list" class="grid" style="margin-top:12px"></div>

      <div class="card" style="margin-top:12px;max-width:980px">
        <h3 style="margin:0 0 10px">Set WhatsApp Phone (E.164) (step-up)</h3>
        <div class="row">
          <input id="uid" placeholder="user_id" style="flex:1;min-width:260px">
          <input id="phone" placeholder="+62812xxxx" style="flex:1;min-width:220px">
          <button id="savePhone" class="btn">Save</button>
        </div>
      </div>

      <div class="card" style="margin-top:12px;max-width:980px">
        <h3 style="margin:0 0 10px">WhatsApp Command Token (step-up)</h3>
        <div style="opacity:.7;font-size:12px;margin-bottom:8px">
          Commands: ACK/ASSIGN/CLOSE &lt;incident_id&gt; &lt;token&gt;
        </div>
        <div class="row">
          <input id="t_uid" placeholder="user_id" style="flex:1;min-width:260px">
          <button id="t_gen" class="btn">Generate</button>
          <input id="t_tok" placeholder="token (shown once)" style="flex:1;min-width:220px">
          <button id="t_set" class="btn">Set Token</button>
          <button id="t_rotate" class="btn">Rotate Token</button>
          <button id="t_status" class="btn">Check Status</button>
        </div>
        <div id="t_info" style="opacity:.8;font-size:12px;margin-top:8px"></div>
      </div>

      <pre id="out" style="margin-top:12px"></pre>
    `;

    const out = U.qs("#out");
    const list = U.qs("#list");
    const tInfo = U.qs("#t_info");

    function genToken(len=10){
      const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
      let s = "";
      const arr = new Uint8Array(len);
      crypto.getRandomValues(arr);
      for (let i=0;i<len;i++) s += chars[arr[i] % chars.length];
      return s;
    }

    async function load(){
      const q = U.qs("#q").value.trim();
      const r = await API.req(`/admin/users?limit=25${q?`&q=${encodeURIComponent(q)}`:""}`, { method:"GET" });
      out.textContent = JSON.stringify(r, null, 2);

      const rows = r.data?.users || [];
      list.innerHTML = rows.map(u => `
        <div class="card" style="display:flex;justify-content:space-between;gap:10px;align-items:center">
          <div>
            <div><b>${U.esc(u.display_name||"")}</b> <span style="opacity:.7">${U.esc(u.status||"")}</span></div>
            <div style="opacity:.7;font-size:12px">${U.esc(u.email_masked||"")}</div>
            <div style="opacity:.7;font-size:12px">WA: ${u.phone ? U.esc(u.phone) : "<span style='opacity:.6'>none</span>"}</div>
            <div style="opacity:.6;font-size:12px">id: <code>${U.esc(u.id)}</code></div>
          </div>
          <button class="btn pick" data-id="${U.esc(u.id)}">Pick</button>
        </div>
      `).join("") || `<div style="opacity:.7">No users</div>`;

      U.qsa(".pick", list).forEach(b => {
        b.onclick = () => {
          const id = b.getAttribute("data-id");
          U.qs("#uid").value = id;
          U.qs("#t_uid").value = id;
        };
      });
    }

    U.qs("#load").onclick = load;

    U.qs("#savePhone").onclick = async () => {
      const ok = await UI.stepUpAuto("rbac_write"); if(!ok) return;
      const user_id = U.qs("#uid").value.trim();
      const phone_e164 = U.qs("#phone").value.trim();
      const r = await API.req("/admin/users/phone/upsert", { method:"POST", body: JSON.stringify({ user_id, phone_e164 }), useChallenge:true });
      out.textContent = JSON.stringify(r, null, 2);
      await load();
    };

    U.qs("#t_gen").onclick = () => {
      U.qs("#t_tok").value = genToken(10);
      tInfo.textContent = "Token generated. Tap Set Token.";
    };

    U.qs("#t_set").onclick = async () => {
      const ok = await UI.stepUpAuto("rbac_write"); if(!ok) return;
      const user_id = U.qs("#t_uid").value.trim();
      const token_plain = U.qs("#t_tok").value.trim();
      if(!user_id || !token_plain) return alert("user_id & token required");
      const r = await API.req("/admin/wa/token/set", { method:"POST", body: JSON.stringify({ user_id, token_plain }), useChallenge:true });
      out.textContent = JSON.stringify(r, null, 2);
      if (r.status==="ok"){ U.qs("#t_tok").value=""; tInfo.textContent="Token saved. (Not shown again)"; }
    };

    U.qs("#t_rotate").onclick = async () => {
      const ok = await UI.stepUpAuto("rbac_write"); if(!ok) return;
      const user_id = U.qs("#t_uid").value.trim();
      if(!user_id) return alert("user_id required");
      const token_plain = genToken(10);
      const r = await API.req("/admin/wa/token/set", { method:"POST", body: JSON.stringify({ user_id, token_plain }), useChallenge:true });
      out.textContent = JSON.stringify(r, null, 2);
      if (r.status==="ok"){
        U.qs("#t_tok").value = token_plain;
        tInfo.textContent = "Token rotated. Copy now (will clear).";
        setTimeout(()=>{ if(U.qs("#t_tok").value===token_plain){ U.qs("#t_tok").value=""; tInfo.textContent="Token cleared."; } }, 30000);
      }
    };

    U.qs("#t_status").onclick = async () => {
      const user_id = U.qs("#t_uid").value.trim();
      if(!user_id) return alert("user_id required");
      const r = await API.req(`/admin/wa/token/status?user_id=${encodeURIComponent(user_id)}`, { method:"GET" });
      out.textContent = JSON.stringify(r, null, 2);
      if (r.status==="ok"){
        tInfo.textContent = r.data.has_token ? `Token exists. Updated at: ${r.data.updated_at}` : "No token set.";
      }
    };

    await load();
  }));

  // --- INCIDENTS LIST (REAL) ---
  Router.on("/incidents", async () => guarded(async () => {
    const main = U.qs("#main");
    main.innerHTML = `
      <h2>Incidents</h2>
      <div class="row">
        <input id="q" placeholder="search type/summary" style="flex:1;min-width:220px">
        <select id="limit"><option>10</option><option selected>20</option><option>50</option><option>100</option></select>
        <button id="load" class="btn">Load</button>
      </div>
      <div id="list" class="grid" style="margin-top:12px"></div>
      <pre id="out" style="margin-top:12px"></pre>
    `;

    const out = U.qs("#out");
    const list = U.qs("#list");

    async function load(){
      const q = U.qs("#q").value.trim();
      const limit = U.qs("#limit").value;
      const r = await API.req(`/admin/incidents?limit=${encodeURIComponent(limit)}${q?`&q=${encodeURIComponent(q)}`:""}`, { method:"GET" });
      out.textContent = JSON.stringify(r, null, 2);

      const rows = r.data?.incidents || [];
      list.innerHTML = rows.map(x => `
        <div class="card" style="display:flex;justify-content:space-between;gap:10px;align-items:center">
          <div>
            <div><b>${U.esc(x.severity)}</b> — ${U.esc(x.type)} — <span style="opacity:.7">${U.esc(x.status)}</span></div>
            <div style="opacity:.7;font-size:12px;margin-top:4px">${U.esc(x.summary||"")}</div>
            <div style="opacity:.6;font-size:12px">${U.esc(U.fmtTs(x.created_at))} • id: <code>${U.esc(x.id)}</code></div>
          </div>
          <a class="btn" href="#/incident?id=${encodeURIComponent(x.id)}">Open</a>
        </div>
      `).join("") || `<div style="opacity:.7">No incidents</div>`;
    }

    U.qs("#load").onclick = load;
    await load();
  }));

  // --- INCIDENT DETAIL + NOTIFY NOW ---
  Router.on("/incident", async (q) => guarded(async () => {
    const id = q.id || "";
    const main = U.qs("#main");
    main.innerHTML = `
      <div class="row" style="justify-content:space-between">
        <h2 style="margin:0">Incident Detail</h2>
        <div class="row">
          <a class="btn" href="#/incidents">Back</a>
          <button id="notifyNow" class="btn">Notify Oncall Now (step-up)</button>
          <button id="reload" class="btn">Reload</button>
        </div>
      </div>

      <div id="card" class="card" style="margin-top:12px"></div>
      <pre id="out" style="margin-top:12px"></pre>
    `;

    const out = U.qs("#out");
    const card = U.qs("#card");

    async function load(){
      const r = await API.req(`/admin/incidents/get?id=${encodeURIComponent(id)}`, { method:"GET" });
      out.textContent = JSON.stringify(r, null, 2);
      const inc = r.data?.incident;
      if (r.status !== "ok" || !inc){
        card.innerHTML = `<div style="opacity:.7">Not found / no access.</div>`;
        return;
      }
      card.innerHTML = `
        <div><b>${U.esc(inc.severity)}</b> — ${U.esc(inc.type)} — <span style="opacity:.7">${U.esc(inc.status)}</span></div>
        <div style="opacity:.7;margin-top:6px">${U.esc(inc.summary||"")}</div>
        <div style="opacity:.7;font-size:12px;margin-top:8px">created: ${U.esc(U.fmtTs(inc.created_at))} • updated: ${U.esc(U.fmtTs(inc.updated_at))}</div>
        <div style="opacity:.6;font-size:12px;margin-top:6px">owner: <code>${U.esc(inc.owner_user_id||"")}</code></div>
        <div style="opacity:.6;font-size:12px;margin-top:6px">id: <code>${U.esc(inc.id)}</code></div>
        ${inc.details_json ? `<details style="margin-top:10px"><summary>details_json</summary><pre>${U.esc(inc.details_json)}</pre></details>` : ""}
      `;
    }

    U.qs("#reload").onclick = load;

    U.qs("#notifyNow").onclick = async () => {
      const ok = await UI.stepUpAuto("incident_write");
      if (!ok) return;
      const r = await API.req("/admin/incidents/notify_now", { method:"POST", body: JSON.stringify({ incident_id: id }), useChallenge:true });
      out.textContent = JSON.stringify(r, null, 2);
    };

    await load();
  }));

  // --- TENANTS ---
  Router.on("/tenants", async () => guarded(async () => {
    const main = U.qs("#main");
    main.innerHTML = `
      <h2>Tenants</h2>
      <div class="row"><button id="load" class="btn">Load</button></div>

      <div class="card" style="margin-top:12px;max-width:980px">
        <h3 style="margin:0 0 10px">Create tenant (step-up)</h3>
        <div class="row">
          <input id="name" placeholder="tenant name" style="flex:1;min-width:260px">
          <button id="create" class="btn">Create</button>
        </div>
      </div>

      <div id="list" class="grid" style="margin-top:12px"></div>
      <pre id="out" style="margin-top:12px"></pre>
    `;

    const out = U.qs("#out");
    const list = U.qs("#list");

    async function load(){
      const r = await API.req("/admin/tenants", { method:"GET" });
      out.textContent = JSON.stringify(r, null, 2);
      const rows = r.data?.tenants || [];
      list.innerHTML = rows.map(t => `
        <div class="card">
          <div><b>${U.esc(t.name)}</b> <span style="opacity:.7">${U.esc(t.status||"")}</span></div>
          <div style="opacity:.6;font-size:12px">id: <code>${U.esc(t.id)}</code> • plan: <code>${U.esc(t.plan_id||"")}</code></div>
        </div>
      `).join("") || `<div style="opacity:.7">No tenants</div>`;
    }

    U.qs("#load").onclick = load;

    U.qs("#create").onclick = async () => {
      const ok = await UI.stepUpAuto("rbac_write"); if(!ok) return;
      const name = U.qs("#name").value.trim();
      const r = await API.req("/admin/tenants/create", { method:"POST", body: JSON.stringify({ name }), useChallenge:true });
      out.textContent = JSON.stringify(r, null, 2);
      await load();
    };

    await load();
  }));

  // --- PROJECTS ---
  Router.on("/projects", async () => guarded(async () => {
    const main = U.qs("#main");
    main.innerHTML = `
      <h2>Projects</h2>
      <div class="row">
        <input id="tenant_id" placeholder="tenant_id (optional)" style="flex:1;min-width:220px">
        <button id="load" class="btn">Load</button>
      </div>

      <div class="card" style="margin-top:12px;max-width:980px">
        <h3 style="margin:0 0 10px">Create project (step-up)</h3>
        <div class="row">
          <input id="p_tenant" placeholder="tenant_id" style="flex:1;min-width:220px">
          <input id="p_name" placeholder="project name" style="flex:1;min-width:260px">
          <button id="create" class="btn">Create</button>
        </div>
      </div>

      <div id="list" class="grid" style="margin-top:12px"></div>
      <pre id="out" style="margin-top:12px"></pre>
    `;

    const out = U.qs("#out");
    const list = U.qs("#list");

    async function load(){
      const tenant_id = U.qs("#tenant_id").value.trim();
      const r = await API.req(`/admin/projects${tenant_id?`?tenant_id=${encodeURIComponent(tenant_id)}`:""}`, { method:"GET" });
      out.textContent = JSON.stringify(r, null, 2);
      const rows = r.data?.projects || [];
      list.innerHTML = rows.map(p => `
        <div class="card" style="display:flex;justify-content:space-between;gap:10px;align-items:center">
          <div>
            <div><b>${U.esc(p.name)}</b> <span style="opacity:.7">${U.esc(p.status||"")}</span></div>
            <div style="opacity:.6;font-size:12px">id: <code>${U.esc(p.id)}</code> • tenant: <code>${U.esc(p.tenant_id)}</code></div>
          </div>
          <a class="btn" href="#/project?id=${encodeURIComponent(p.id)}">Open</a>
        </div>
      `).join("") || `<div style="opacity:.7">No projects</div>`;
    }

    U.qs("#load").onclick = load;

    U.qs("#create").onclick = async () => {
      const ok = await UI.stepUpAuto("rbac_write"); if(!ok) return;
      const tenant_id = U.qs("#p_tenant").value.trim();
      const name = U.qs("#p_name").value.trim();
      const r = await API.req("/admin/projects/create", { method:"POST", body: JSON.stringify({ tenant_id, name }), useChallenge:true });
      out.textContent = JSON.stringify(r, null, 2);
      await load();
    };

    await load();
  }));

  // --- PROJECT EVENTS (SCHEDULE) ---
  Router.on("/project", async (q) => guarded(async () => {
    const project_id = q.id || "";
    const main = U.qs("#main");
    main.innerHTML = `
      <div class="row" style="justify-content:space-between;align-items:flex-start">
        <div>
          <h2 style="margin:0">Project Schedule</h2>
          <div style="opacity:.7;font-size:12px">project_id: <code>${U.esc(project_id)}</code></div>
        </div>
        <div class="row">
          <a class="btn" href="#/projects">Back</a>
          <a class="btn" id="csv" target="_blank">Export CSV</a>
          <a class="btn" id="ics" target="_blank">Export ICS</a>
        </div>
      </div>

      <div class="card" style="margin-top:12px;max-width:980px">
        <h3 style="margin:0 0 10px">Create event (step-up)</h3>
        <div class="row">
          <input id="title" placeholder="title" style="flex:1;min-width:200px">
          <input id="talent" placeholder="talent_user_id (optional)" style="flex:1;min-width:220px">
          <input id="start" inputmode="numeric" placeholder="start_at epoch" style="width:200px">
          <input id="end" inputmode="numeric" placeholder="end_at epoch" style="width:200px">
          <button id="create" class="btn">Create</button>
        </div>
        <div style="opacity:.7;font-size:12px;margin-top:6px">epoch seconds (UTC). now: ${U.nowSec()}</div>
      </div>

      <div class="row" style="margin-top:12px">
        <input id="from" inputmode="numeric" placeholder="from epoch (optional)" style="width:220px">
        <input id="to" inputmode="numeric" placeholder="to epoch (optional)" style="width:220px">
        <button id="load" class="btn">Load events</button>
      </div>

      <div id="list" class="grid" style="margin-top:12px"></div>
      <pre id="out" style="margin-top:12px"></pre>
    `;

    const out = U.qs("#out");
    const list = U.qs("#list");

    // Optional export endpoints (if implemented in worker)
    U.qs("#csv").href = `/admin/projects/calendar.csv?project_id=${encodeURIComponent(project_id)}`;
    U.qs("#ics").href = `/admin/projects/calendar.ics?project_id=${encodeURIComponent(project_id)}`;

    async function load(){
      const from = U.qs("#from").value.trim();
      const to = U.qs("#to").value.trim();
      const qp = `project_id=${encodeURIComponent(project_id)}`
        + (from?`&from=${encodeURIComponent(from)}`:"")
        + (to?`&to=${encodeURIComponent(to)}`:"");

      const r = await API.req(`/admin/projects/events?${qp}`, { method:"GET" });
      out.textContent = JSON.stringify(r, null, 2);

      const rows = r.data?.events || [];
      list.innerHTML = rows.map(e => `
        <div class="card">
          <div><b>${U.esc(e.title)}</b></div>
          <div style="opacity:.7;font-size:12px">${U.esc(U.fmtTs(e.start_at))} → ${U.esc(U.fmtTs(e.end_at))}</div>
          <div style="opacity:.6;font-size:12px">talent: <code>${U.esc(e.talent_user_id||"")}</code> • id: <code>${U.esc(e.id)}</code></div>
          ${e.notes ? `<div style="opacity:.7;font-size:12px;margin-top:6px">${U.esc(e.notes)}</div>` : ``}
        </div>
      `).join("") || `<div style="opacity:.7">No events</div>`;
    }

    U.qs("#load").onclick = load;

    U.qs("#create").onclick = async () => {
      const ok = await UI.stepUpAuto("rbac_write"); if(!ok) return;
      const title = U.qs("#title").value.trim();
      const talent_user_id = U.qs("#talent").value.trim() || null;
      const start_at = Number(U.qs("#start").value || "0");
      const end_at = Number(U.qs("#end").value || "0");
      if (!title || !start_at || !end_at || end_at <= start_at) return alert("Invalid input");

      const r = await API.req("/admin/projects/events/create", {
        method:"POST",
        body: JSON.stringify({ project_id, title, talent_user_id, start_at, end_at }),
        useChallenge:true
      });
      out.textContent = JSON.stringify(r, null, 2);
      await load();
    };

    await load();
  }));

  // --- TALENT SCHEDULE ---
  Router.on("/talent", async () => guarded(async () => {
    const main = U.qs("#main");
    main.innerHTML = `
      <h2>My Schedule</h2>
      <div class="row" style="margin-top:10px">
        <input id="from" inputmode="numeric" placeholder="from epoch (optional)" style="width:220px">
        <input id="to" inputmode="numeric" placeholder="to epoch (optional)" style="width:220px">
        <button id="load" class="btn">Load</button>
      </div>
      <div id="list" class="grid" style="margin-top:12px"></div>
      <pre id="out" style="margin-top:12px"></pre>
    `;
    const out = U.qs("#out");
    const list = U.qs("#list");

    async function load(){
      const from = U.qs("#from").value.trim();
      const to = U.qs("#to").value.trim();
      const url = `/talent/schedule${from||to?`?from=${encodeURIComponent(from||"")}&to=${encodeURIComponent(to||"")}`:""}`;
      const r = await API.req(url, { method:"GET" });
      out.textContent = JSON.stringify(r, null, 2);

      const rows = r.data?.events || [];
      list.innerHTML = rows.map(e => `
        <div class="card">
          <div><b>${U.esc(e.title)}</b></div>
          <div style="opacity:.7;font-size:12px">${U.esc(U.fmtTs(e.start_at))} → ${U.esc(U.fmtTs(e.end_at))}</div>
          <div style="opacity:.6;font-size:12px">project: <code>${U.esc(e.project_id||"")}</code></div>
        </div>
      `).join("") || `<div style="opacity:.7">No events</div>`;
    }

    U.qs("#load").onclick = load;
    await load();
  }));

  // --- ABOUT ---
  Router.on("/about", async () => guarded(async () => {
    const main = U.qs("#main");
    main.innerHTML = `
      <h2>About</h2>
      <div class="card" style="margin-top:12px">
        <div style="opacity:.7;font-size:12px">This is the SPA frontend for Enterprise Login.</div>
        <div style="opacity:.7;font-size:12px;margin-top:6px">API_BASE: <code>${U.esc(API_BASE || "(same-origin)")}</code></div>
        <div style="margin-top:10px" class="row">
          <button id="health" class="btn">/health</button>
          <button id="version" class="btn">/version (optional)</button>
        </div>
      </div>
      <pre id="out" style="margin-top:12px"></pre>
    `;
    const out = U.qs("#out");
    U.qs("#health").onclick = async () => { out.textContent = JSON.stringify(await API.req("/health",{method:"GET"}), null, 2); };
    U.qs("#version").onclick = async () => { out.textContent = JSON.stringify(await API.req("/version",{method:"GET"}), null, 2); };
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
    if (API.getToken()) Router.go("/home");
    await Router.render();
  })();
})();