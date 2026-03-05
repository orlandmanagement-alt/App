/* public/js/app.js — FULL (single file)
 * Orland Dashboard (Cloudflare Pages + Pages Functions)
 * Same-origin: UI + API under dashboard.orlandmanagement.com
 *
 * Endpoints expected:
 *  - GET  /api/setup/status
 *  - POST /api/setup/bootstrap
 *  - POST /api/login
 *  - GET  /api/me
 *  - POST /api/logout
 *  - GET  /api/users
 *  - POST /api/users
 *  - PUT  /api/users      (actions: disable, reset_password, reset_request)
 *  - GET  /api/talents
 *  - POST /api/upload/init
 *  - POST /api/upload/commit
 *
 * Pages expected:
 *  - /index.html
 *  - /dashboard.html
 *  - /setup.html
 *  - /reset.html
 */

window.OrlandApp = (() => {
  // --------------------------
  // Core fetch helper (same-origin)
  // --------------------------
  async function api(path, opt = {}) {
    const headers = Object.assign({}, opt.headers || {});
    if (opt.body != null && !headers["content-type"]) headers["content-type"] = "application/json";

    try {
      const res = await fetch(path, {
        method: opt.method || "GET",
        headers,
        body: opt.body || undefined,
        credentials: "include", // use HttpOnly cookie session
      });

      const ct = res.headers.get("content-type") || "";
      if (!ct.includes("application/json")) {
        const text = await res.text().catch(() => "");
        return { status: "server_error", data: { http: res.status, body: text.slice(0, 300) } };
      }
      return await res.json();
    } catch (e) {
      return { status: "network_error", data: { message: String(e?.message || e) } };
    }
  }

  // --------------------------
  // Small DOM helpers
  // --------------------------
  const qs = (id) => document.getElementById(id);

  function escapeHtml(s) {
    return String(s ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;");
  }

  function pickFile() {
    return new Promise((resolve) => {
      const input = document.createElement("input");
      input.type = "file";
      input.accept = "image/*";
      input.onchange = () => resolve(input.files && input.files[0] ? input.files[0] : null);
      input.click();
    });
  }

  // ==========================================================
  // SETUP PAGE (/setup.html)
  // ==========================================================
  async function initSetup() {
    const out = qs("out");

    // 1) check setup status
    const st = await api("/api/setup/status");
    if (out) out.textContent = JSON.stringify(st, null, 2);

    if (st.status !== "ok") {
      alert("Gagal cek setup: " + st.status);
      return;
    }

    // 2) if not required, go login
    if (!st.data?.setup_required) {
      location.href = "/index.html";
      return;
    }

    // 3) submit bootstrap
    const btn = qs("go");
    if (!btn) return;

    btn.onclick = async () => {
      const display_name = String(qs("name")?.value || "").trim();
      const email = String(qs("email")?.value || "").trim().toLowerCase();
      const password = String(qs("pass")?.value || "");

      if (!email.includes("@") || password.length < 10) {
        alert("Email tidak valid / password minimal 10 karakter.");
        return;
      }

      const r = await api("/api/setup/bootstrap", {
        method: "POST",
        body: JSON.stringify({ display_name, email, password }),
      });

      if (out) out.textContent = JSON.stringify(r, null, 2);

      if (r.status === "ok") {
        alert("Super Admin berhasil dibuat. Silakan login.");
        location.href = "/index.html";
      } else {
        alert("Gagal: " + r.status);
      }
    };
  }

  // ==========================================================
  // LOGIN PAGE (/index.html)
  // ==========================================================
  async function initLogin() {
    const out = qs("out");

    // Auto-redirect to setup if needed
    const st = await api("/api/setup/status");
    if (out) out.textContent = JSON.stringify(st, null, 2);

    if (st.status === "ok" && st.data?.setup_required) {
      location.href = "/setup.html";
      return;
    }

    const btn = qs("login");
    if (!btn) return;

    btn.onclick = async () => {
      const email = String(qs("email")?.value || "").trim().toLowerCase();
      const password = String(qs("pass")?.value || "");

      const r = await api("/api/login", {
        method: "POST",
        body: JSON.stringify({ email, password }),
      });

      if (out) out.textContent = JSON.stringify(r, null, 2);

      if (r.status === "ok") location.href = "/dashboard.html";
      else alert("Gagal: " + r.status);
    };
  }

  // ==========================================================
  // RESET REQUEST PAGE (/reset.html) — placeholder (opsional)
  // ==========================================================
  async function initResetRequest() {
    const out = qs("out");
    const btn = qs("go");
    if (!btn) return;

    btn.onclick = async () => {
      const email = String(qs("email")?.value || "").trim().toLowerCase();
      const r = await api("/api/users", {
        method: "PUT",
        body: JSON.stringify({ action: "reset_request", email }),
      });
      if (out) out.textContent = JSON.stringify(r, null, 2);
      alert("Request dicatat. (Self-service email reset bisa diaktifkan nanti)");
    };
  }

  // ==========================================================
  // DASHBOARD PAGE (/dashboard.html)
  // ==========================================================
  async function initDashboard() {
    const out = qs("out");
    const meEl = qs("me");
    const panel = qs("panel");

    // 1) check session
    const me = await api("/api/me");
    if (out) out.textContent = JSON.stringify(me, null, 2);

    if (me.status !== "ok") {
      location.href = "/index.html";
      return;
    }

    const roles = (me.data.roles || []).join(", ");
    if (meEl) meEl.textContent = `Hi ${me.data.display_name || me.data.id} — roles: ${roles}`;

    // 2) logout
    const logoutBtn = qs("logout");
    if (logoutBtn) {
      logoutBtn.onclick = async () => {
        await api("/api/logout", { method: "POST", body: "{}" });
        location.href = "/index.html";
      };
    }

    // 3) tabs
    const tabUsers = qs("tabUsers");
    const tabTalents = qs("tabTalents");
    const tabUpload = qs("tabUpload");

    if (tabUsers) tabUsers.onclick = showUsers;
    if (tabTalents) tabTalents.onclick = showTalents;
    if (tabUpload) tabUpload.onclick = showUpload;

    // default view
    await showUsers();

    // --------------------------
    // Users panel
    // --------------------------
              
async function showUsers() {
  if (!panel) return;

  // UI skeleton
  panel.innerHTML = `
    <div class="row" style="justify-content:space-between;align-items:flex-end">
      <div>
        <b>Users (Admin Module)</b>
        <div class="small" style="margin-top:4px">Hanya user: super_admin, admin, staff</div>
      </div>
      <button id="reloadUsers">Reload</button>
    </div>

    <div class="row" style="margin-top:10px">
      <input id="q" placeholder="search email/name" style="flex:1;min-width:220px">
      <select id="role" style="width:180px">
        <option value="">all roles</option>
        <option value="super_admin">super_admin</option>
        <option value="admin">admin</option>
        <option value="staff">staff</option>
      </select>
      <select id="status" style="width:160px">
        <option value="">all status</option>
        <option value="active">active</option>
        <option value="disabled">disabled</option>
      </select>
      <button id="search">Search</button>
    </div>

    <hr class="hr" />

    <div class="card" style="padding:12px">
      <div class="row" style="justify-content:space-between">
        <b id="formTitle">Create User</b>
        <button id="clearForm">Clear</button>
      </div>

      <div class="row" style="margin-top:10px">
        <input id="uid" placeholder="user_id (auto)" disabled style="flex:1;min-width:240px">
        <select id="f_role" style="width:200px">
          <option value="staff">staff</option>
          <option value="admin">admin</option>
          <option value="super_admin">super_admin</option>
        </select>
        <select id="f_status" style="width:160px">
          <option value="active">active</option>
          <option value="disabled">disabled</option>
        </select>
      </div>

      <div class="row" style="margin-top:10px">
        <input id="f_email" placeholder="email" style="flex:1;min-width:240px">
        <input id="f_name" placeholder="display name" style="flex:1;min-width:220px">
      </div>

      <div class="row" style="margin-top:10px">
        <div style="flex:1;min-width:240px;position:relative">
          <input id="f_password" type="password" placeholder="password (min 10)" style="width:100%;padding-right:42px">
          <button id="togglePw" type="button"
            style="position:absolute;right:6px;top:6px;height:34px;width:34px;border-radius:10px;border:1px solid #ddd;background:#fff;color:#111;cursor:pointer">
            👁️
          </button>
        </div>
        <button id="saveUser" style="min-width:160px">Save</button>
        <button id="resetPw" style="min-width:160px">Reset Password</button>
        <button id="disableBtn" style="min-width:140px">Disable</button>
        <button id="enableBtn" style="min-width:140px">Enable</button>
        <button id="deleteBtn" style="min-width:140px">Delete</button>
      </div>

      <div class="small" style="margin-top:8px">
        Catatan: Reset password & Delete hanya super_admin.
      </div>
    </div>

    <div style="height:12px"></div>
    <div id="list"></div>
  `;

  const listEl = panel.querySelector("#list");

  // eye toggle
  const pwInput = panel.querySelector("#f_password");
  panel.querySelector("#togglePw").onclick = () => {
    pwInput.type = pwInput.type === "password" ? "text" : "password";
  };

  // form helpers
  function clearForm() {
    panel.querySelector("#formTitle").textContent = "Create User";
    panel.querySelector("#uid").value = "";
    panel.querySelector("#f_email").value = "";
    panel.querySelector("#f_name").value = "";
    panel.querySelector("#f_password").value = "";
    panel.querySelector("#f_role").value = "staff";
    panel.querySelector("#f_status").value = "active";
  }
  panel.querySelector("#clearForm").onclick = clearForm;

  function fillForm(u) {
    panel.querySelector("#formTitle").textContent = "Edit User";
    panel.querySelector("#uid").value = u.id;
    panel.querySelector("#f_email").value = u.email_norm;
    panel.querySelector("#f_name").value = u.display_name || "";
    panel.querySelector("#f_password").value = "";
    panel.querySelector("#f_status").value = u.status || "active";
    panel.querySelector("#f_role").value = (u.roles && u.roles[0]) ? u.roles[0] : "staff";
  }

  // load + render
  async function load() {
    const q = panel.querySelector("#q").value.trim();
    const role = panel.querySelector("#role").value;
    const status = panel.querySelector("#status").value;

    let url = `/api/users?limit=100`;
    if (q) url += `&q=${encodeURIComponent(q)}`;
    if (role) url += `&role=${encodeURIComponent(role)}`;
    if (status) url += `&status=${encodeURIComponent(status)}`;

    const r = await api(url);
    if (out) out.textContent = JSON.stringify(r, null, 2);

    if (r.status !== "ok") {
      listEl.innerHTML = `<div class="small">Gagal load users: ${escapeHtml(r.status)}</div>`;
      return;
    }

    const users = r.data?.users || [];
    listEl.innerHTML = `
      <table class="table">
        <thead>
          <tr>
            <th>Email</th><th>Name</th><th>Status</th><th>Roles</th><th>Updated</th><th>Action</th>
          </tr>
        </thead>
        <tbody>
          ${users.map(u => `
            <tr>
              <td>${escapeHtml(u.email_norm)}</td>
              <td>${escapeHtml(u.display_name || "")}</td>
              <td>${escapeHtml(u.status || "")}</td>
              <td>${escapeHtml((u.roles||[]).join(","))}</td>
              <td>${escapeHtml(String(u.updated_at||""))}</td>
              <td><button class="pick" data-id="${escapeHtml(u.id)}">Edit</button></td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    `;

    // attach pick
    listEl.querySelectorAll(".pick").forEach(btn => {
      btn.onclick = () => {
        const id = btn.getAttribute("data-id");
        const u = users.find(x => x.id === id);
        if (u) fillForm(u);
      };
    });
  }

  panel.querySelector("#reloadUsers").onclick = load;
  panel.querySelector("#search").onclick = load;

  // Save user (create or update)
  panel.querySelector("#saveUser").onclick = async () => {
    const user_id = panel.querySelector("#uid").value.trim();
    const email = panel.querySelector("#f_email").value.trim().toLowerCase();
    const display_name = panel.querySelector("#f_name").value.trim();
    const password = panel.querySelector("#f_password").value;
    const role = panel.querySelector("#f_role").value;
    const status = panel.querySelector("#f_status").value;

    if (!user_id) {
      // create
      if (!email.includes("@")) return alert("Email invalid");
      if (!password || password.length < 10) return alert("Password minimal 10");
      const r = await api("/api/users", {
        method: "POST",
        body: JSON.stringify({ email, display_name, password, roles: [role] }),
      });
      if (out) out.textContent = JSON.stringify(r, null, 2);
      if (r.status !== "ok") return alert("Gagal: " + r.status);
      clearForm();
      await load();
      return;
    }

    // update basic + role set (2 calls biar simple)
    const r1 = await api("/api/users", {
      method: "PUT",
      body: JSON.stringify({ action: "update", user_id, display_name, status }),
    });
    if (out) out.textContent = JSON.stringify(r1, null, 2);
    if (r1.status !== "ok") return alert("Gagal update: " + r1.status);

    const r2 = await api("/api/users", {
      method: "PUT",
      body: JSON.stringify({ action: "set_roles", user_id, roles: [role] }),
    });
    if (out) out.textContent = JSON.stringify({ r1, r2 }, null, 2);
    if (r2.status !== "ok") return alert("Gagal set role: " + r2.status);

    await load();
  };

  // Reset password (super_admin only)
  panel.querySelector("#resetPw").onclick = async () => {
    const user_id = panel.querySelector("#uid").value.trim();
    if (!user_id) return alert("Pilih user dulu (Edit).");
    const new_password = panel.querySelector("#f_password").value;
    if (!new_password || new_password.length < 10) return alert("Password minimal 10 (isi field password)");
    const r = await api("/api/users", {
      method: "PUT",
      body: JSON.stringify({ action: "reset_password", user_id, new_password }),
    });
    if (out) out.textContent = JSON.stringify(r, null, 2);
    alert(r.status);
    panel.querySelector("#f_password").value = "";
  };

  panel.querySelector("#disableBtn").onclick = async () => {
    const user_id = panel.querySelector("#uid").value.trim();
    if (!user_id) return alert("Pilih user dulu (Edit).");
    const r = await api("/api/users", { method: "PUT", body: JSON.stringify({ action: "disable", user_id }) });
    if (out) out.textContent = JSON.stringify(r, null, 2);
    if (r.status === "ok") await load();
    else alert(r.status);
  };

  panel.querySelector("#enableBtn").onclick = async () => {
    const user_id = panel.querySelector("#uid").value.trim();
    if (!user_id) return alert("Pilih user dulu (Edit).");
    const r = await api("/api/users", { method: "PUT", body: JSON.stringify({ action: "enable", user_id }) });
    if (out) out.textContent = JSON.stringify(r, null, 2);
    if (r.status === "ok") await load();
    else alert(r.status);
  };

  // Hard delete (super_admin only)
  panel.querySelector("#deleteBtn").onclick = async () => {
    const user_id = panel.querySelector("#uid").value.trim();
    if (!user_id) return alert("Pilih user dulu (Edit).");
    if (!confirm("Hapus permanen user ini? (super_admin only)")) return;
    const r = await api(`/api/users?id=${encodeURIComponent(user_id)}`, { method: "DELETE" });
    if (out) out.textContent = JSON.stringify(r, null, 2);
    if (r.status === "ok") {
      clearForm();
      await load();
    } else {
      alert(r.status);
    }
  };

  await load();
}
    // --------------------------
    // Talents panel
    // --------------------------
    async function showTalents() {
      if (!panel) return;

      const r = await api("/api/talents");
      if (out) out.textContent = JSON.stringify(r, null, 2);
      if (r.status !== "ok") {
        panel.innerHTML = `<div class="small">Gagal load talents: ${escapeHtml(r.status)}</div>`;
        return;
      }

      const talents = r.data?.talents || [];

      panel.innerHTML = `
        <div class="row" style="justify-content:space-between">
          <b>Talents</b>
          <button id="createTalent">Create Talent User</button>
        </div>

        <table class="table" style="margin-top:10px">
          <thead><tr><th>Email</th><th>Name</th><th>Status</th><th>Avatar</th></tr></thead>
          <tbody>
            ${talents.map(u => `
              <tr>
                <td>${escapeHtml(u.email_norm)}</td>
                <td>${escapeHtml(u.display_name || "")}</td>
                <td>${escapeHtml(u.status)}</td>
                <td>${u.photo_url ? `<a href="${u.photo_url}" target="_blank">view</a>` : "-"}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      `;

      panel.querySelector("#createTalent").onclick = async () => {
        const email = prompt("Email talent:");
        if (!email) return;

        const name = prompt("Display name:");
        const password = prompt("Password (min 10):");
        if (!password || password.length < 10) return alert("Password minimal 10 karakter.");

        const rr = await api("/api/users", {
          method: "POST",
          body: JSON.stringify({ email, display_name: name, role: "talent", password }),
        });
        if (out) out.textContent = JSON.stringify(rr, null, 2);
        if (rr.status === "ok") await showTalents();
        else alert("Gagal: " + rr.status);
      };
    }

    // --------------------------
    // Upload panel (R2 signed URL)
    // --------------------------
    async function showUpload() {
      if (!panel) return;

      panel.innerHTML = `
        <b>Upload Avatar (R2)</b>
        <div class="small" style="margin-top:6px">Upload foto untuk user kamu sendiri.</div>
        <div class="row" style="margin-top:10px">
          <button id="pick">Pilih Foto</button>
        </div>
      `;

      panel.querySelector("#pick").onclick = async () => {
        const f = await pickFile();
        if (!f) return;

        // init signed url
        const init = await api("/api/upload/init", {
          method: "POST",
          body: JSON.stringify({
            filename: f.name,
            content_type: f.type || "application/octet-stream",
          }),
        });
        if (out) out.textContent = JSON.stringify(init, null, 2);
        if (init.status !== "ok") return alert("Init failed: " + init.status);

        // PUT to signed URL
        const put = await fetch(init.data.upload_url, {
          method: "PUT",
          body: f,
          headers: { "content-type": f.type || "application/octet-stream" },
        });
        if (!put.ok) {
          alert("Upload gagal: " + put.status);
          return;
        }

        // commit
        const commit = await api("/api/upload/commit", {
          method: "POST",
          body: JSON.stringify({ object_key: init.data.object_key }),
        });
        if (out) out.textContent = JSON.stringify({ init, commit }, null, 2);
        alert(commit.status);
      };
    }
  }

  // export
  return {
    api,
    initSetup,
    initLogin,
    initResetRequest,
    initDashboard,
  };
})();
