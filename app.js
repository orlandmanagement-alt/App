/* app.js — single file (localhost friendly)
 * SPA Frontend for Worker API
 *
 * IMPORTANT:
 * - Set window.API_BASE before this script runs:
 *   window.API_BASE = "https://your-worker-domain";
 */
(() => {
  "use strict";

  const API_BASE = (window.API_BASE || "");
  const TOKEN_KEY = "auth_token";

  const app = document.getElementById("dashboard");
  if (!app) return;

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

  const API = {
    getToken(){ return localStorage.getItem(TOKEN_KEY) || ""; },
    setToken(t){ if(t) localStorage.setItem(TOKEN_KEY,t); else localStorage.removeItem(TOKEN_KEY); },

    async req(path, opt = {}) {
      const url = API_BASE ? (API_BASE + path) : path;
      const headers = Object.assign({ "content-type":"application/json" }, opt.headers || {});
      const tok = API.getToken();
      if (tok) headers["authorization"] = "Bearer " + tok;

      const res = await fetch(url, {
        method: opt.method || "GET",
        headers,
        body: opt.body || undefined
      });

      let data = null;
      try { data = await res.json(); }
      catch { data = { status:"server_error", data:{ message:"non_json_response", http:res.status } }; }
      return data;
    }
  };

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
            <div class="menu">${menuHtml}</div>
            <div class="footer">
              <button class="btn ghost" id="logout">Logout</button>
            </div>
          </div>
          <div class="main"><div id="main"></div></div>
        </div>
      `;
    },

    async loginOtpFlow(email){
      // 1) request OTP
      const r1 = await API.req("/auth/challenge/otp/request", {
        method:"POST",
        body: JSON.stringify({ action:"user_login_otp", email })
      });
      if (r1.status !== "ok") { alert("OTP request failed: " + r1.status); return false; }

      // for local testing, worker may return otp_debug
      if (r1.data?.otp_debug) {
        alert("OTP (debug): " + r1.data.otp_debug);
      }

      const otp_ref = r1.data?.otp_ref;
      const otp = prompt("Masukkan OTP 6 digit:");
      if (!otp) return false;

      // 2) verify OTP -> returns token
      const r2 = await API.req("/auth/challenge/otp/verify", {
        method:"POST",
        body: JSON.stringify({ action:"user_login_otp", otp, otp_ref, email })
      });
      if (r2.status !== "ok") { alert("OTP verify failed: " + r2.status); return false; }

      if (r2.data?.token) {
        API.setToken(r2.data.token);
        return true;
      }
      alert("OTP verified but no token returned.");
      return false;
    }
  };

  async function getMe(){
    const r = await API.req("/me", { method:"GET" });
    if (r.status !== "ok") return null;
    return r.data;
  }

  function menuForRoles(roles){
    const r = roles || [];
    const base = [{ path:"/home", label:"Home" }, { path:"/users", label:"Users" }, { path:"/about", label:"About" }];
    if (r.includes("super_admin") || r.includes("admin")) return base;
    if (r.includes("staff")) return [{ path:"/home", label:"Home" }, { path:"/about", label:"About" }];
    if (r.includes("client")) return [{ path:"/home", label:"Home" }, { path:"/about", label:"About" }];
    if (r.includes("talent")) return [{ path:"/home", label:"Home" }, { path:"/about", label:"About" }];
    return [{ path:"/home", label:"Home" }, { path:"/about", label:"About" }];
  }

  async function guarded(renderFn){
    const me = await getMe();
    if (!me) return Router.go("/login");

    const menus = menuForRoles(me.roles);
    app.innerHTML = UI.shell(me, menus);

    U.qs("#logout").onclick = async () => {
      await API.req("/auth/logout", { method:"POST", body:"{}" });
      API.setToken("");
      Router.go("/login");
    };

    await renderFn(me);
  }

  // =========================
  // PAGES
  // =========================

  Router.on("/login", async () => {
    app.innerHTML = `
      <div class="card" style="max-width:420px;margin:28px auto;padding:14px">
        <h2 style="margin:0 0 10px">Login</h2>
        <div style="opacity:.7;font-size:12px;margin-bottom:12px">
          super_admin/admin/staff: password only • client/talent: password + OTP
        </div>
        <input id="email" placeholder="email" style="width:100%">
        <div style="height:8px"></div>
        <input id="pass" type="password" placeholder="password" style="width:100%">
        <div style="height:12px"></div>
        <button class="btn" id="go" style="width:100%">Login</button>
        <pre id="out" style="margin-top:12px"></pre>
        <div style="opacity:.7;font-size:12px;margin-top:10px">
          API_BASE: <code>${U.esc(API_BASE || "(same-origin)")}</code>
        </div>
      </div>
    `;

    const out = U.qs("#out");
    U.qs("#go").onclick = async () => {
      const email = String(U.qs("#email").value||"").trim().toLowerCase();
      const password = String(U.qs("#pass").value||"");

      const r = await API.req("/auth/login/password", {
        method:"POST",
        body: JSON.stringify({ email, password })
      });
      out.textContent = JSON.stringify(r, null, 2);

      if (r.status === "ok" && r.data?.token) {
        API.setToken(r.data.token);
        Router.go("/home");
        return;
      }

      if (r.status === "challenge_required" && r.data?.action === "user_login_otp") {
        const ok = await UI.loginOtpFlow(email);
        if (ok) Router.go("/home");
        return;
      }

      alert("Login failed: " + r.status);
    };
  });

  Router.on("/home", async () => guarded(async (me) => {
    const main = U.qs("#main");
    main.innerHTML = `
      <h2 style="margin:0">Home</h2>
      <div style="opacity:.7;margin-top:6px">Welcome, ${U.esc(me.display_name || me.id)}</div>
      <div style="margin-top:12px;opacity:.7;font-size:12px">Roles: ${U.esc((me.roles||[]).join(", "))}</div>
      <div style="margin-top:12px;opacity:.7;font-size:12px">API_BASE: ${U.esc(API_BASE || "(same-origin)")}</div>
    `;
  }));

  Router.on("/users", async () => guarded(async (me) => {
    const main = U.qs("#main");
    const roles = me.roles || [];
    const canAdmin = roles.includes("super_admin") || roles.includes("admin");

    main.innerHTML = `
      <h2>Users</h2>

      ${canAdmin ? `
      <div class="card" style="margin-top:12px;max-width:980px">
        <h3 style="margin:0 0 10px">Create User</h3>
        <div style="opacity:.7;font-size:12px;margin-bottom:10px">
          super_admin boleh create semua • admin tidak bisa create super_admin
        </div>
        <div class="row">
          <input id="c_email" placeholder="email" style="flex:1;min-width:220px">
          <input id="c_name" placeholder="display_name" style="flex:1;min-width:200px">
          <input id="c_pass" placeholder="password (min 8)" type="password" style="flex:1;min-width:200px">
          <select id="c_role" style="min-width:160px">
            <option value="staff">staff</option>
            <option value="client">client</option>
            <option value="talent">talent</option>
            <option value="admin">admin</option>
            <option value="super_admin">super_admin</option>
          </select>
          <button id="c_btn" class="btn">Create</button>
        </div>
      </div>
      ` : `
      <div class="card" style="margin-top:12px">
        <div style="opacity:.7">You don't have permission to manage users.</div>
      </div>
      `}

      <div class="row" style="margin-top:12px">
        <input id="q" placeholder="search name/email" style="flex:1;min-width:220px">
        <button id="load" class="btn">Load</button>
      </div>

      <div id="list" class="grid" style="margin-top:12px"></div>
      <pre id="out" style="margin-top:12px"></pre>
    `;

    const out = U.qs("#out");
    const list = U.qs("#list");

    async function load(){
      const q = U.qs("#q").value.trim();
      const r = await API.req(`/admin/users?limit=25${q?`&q=${encodeURIComponent(q)}`:""}`, { method:"GET" });
      out.textContent = JSON.stringify(r, null, 2);

      const rows = r.data?.users || [];
      list.innerHTML = rows.map(u => `
        <div class="card">
          <div><b>${U.esc(u.display_name||"")}</b> <span style="opacity:.7">${U.esc(u.status||"")}</span></div>
          <div style="opacity:.7;font-size:12px">${U.esc(u.email_masked||"")}</div>
          <div style="opacity:.6;font-size:12px">id: <code>${U.esc(u.id)}</code></div>
        </div>
      `).join("") || `<div style="opacity:.7">No users</div>`;
    }

    U.qs("#load").onclick = load;

    if (canAdmin) {
      U.qs("#c_btn").onclick = async () => {
        const email = U.qs("#c_email").value.trim().toLowerCase();
        const display_name = U.qs("#c_name").value.trim();
        const password = U.qs("#c_pass").value;
        const role = U.qs("#c_role").value;

        const r = await API.req("/admin/users/create", {
          method:"POST",
          body: JSON.stringify({ email, display_name, password, role })
        });
        out.textContent = JSON.stringify(r, null, 2);
        if (r.status === "ok") {
          U.qs("#c_email").value = "";
          U.qs("#c_name").value = "";
          U.qs("#c_pass").value = "";
          await load();
          alert("User created: " + r.data.user_id);
        } else {
          alert("Create failed: " + r.status);
        }
      };
    }

    await load();
  }));

  Router.on("/about", async () => guarded(async () => {
    const main = U.qs("#main");
    main.innerHTML = `
      <h2>About</h2>
      <div class="card" style="margin-top:12px">
        <div style="opacity:.7;font-size:12px">SPA frontend for Worker auth.</div>
        <div style="opacity:.7;font-size:12px;margin-top:6px">API_BASE: <code>${U.esc(API_BASE || "(same-origin)")}</code></div>
        <div style="margin-top:10px" class="row">
          <button id="health" class="btn">/health</button>
        </div>
      </div>
      <pre id="out" style="margin-top:12px"></pre>
    `;
    const out = U.qs("#out");
    U.qs("#health").onclick = async () => { out.textContent = JSON.stringify(await API.req("/health",{method:"GET"}), null, 2); };
  }));

  Router.on("/404", async () => {
    app.innerHTML = `<div class="card" style="max-width:720px;margin:28px auto">
      <b>Not found</b> — <a href="#/home">Go Home</a>
    </div>`;
  });

  (async () => {
    if (API.getToken()) Router.go("/home");
    await Router.render();
  })();
})();
