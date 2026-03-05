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

      const r = await api("/api/users");
      if (out) out.textContent = JSON.stringify(r, null, 2);
      if (r.status !== "ok") {
        panel.innerHTML = `<div class="small">Gagal load users: ${escapeHtml(r.status)}</div>`;
        return;
      }

      const users = r.data?.users || [];

      panel.innerHTML = `
        <div class="row" style="justify-content:space-between">
          <b>Users</b>
          <button id="createUser">Create</button>
        </div>

        <div class="small" style="margin-top:6px">
          Actions: reset password (super_admin), disable (admin/super_admin)
        </div>

        <table class="table" style="margin-top:10px">
          <thead>
            <tr><th>Email</th><th>Name</th><th>Status</th><th>Roles</th><th>Action</th></tr>
          </thead>
          <tbody>
            ${users.map(u => `
              <tr>
                <td>${escapeHtml(u.email_norm)}</td>
                <td>${escapeHtml(u.display_name || "")}</td>
                <td>${escapeHtml(u.status)}</td>
                <td>${escapeHtml((u.roles || []).join(","))}</td>
                <td>
                  <button class="btnReset" data-id="${escapeHtml(u.id)}">Reset Pw</button>
                  <button class="btnDisable" data-id="${escapeHtml(u.id)}">Disable</button>
                </td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      `;

      // Create user
      panel.querySelector("#createUser").onclick = async () => {
        const email = prompt("Email user:");
        if (!email) return;

        const name = prompt("Display name:");
        const role = prompt("Role (admin/staff/client/talent):", "staff");
        const password = prompt("Password (min 10):");
        if (!password || password.length < 10) return alert("Password minimal 10 karakter.");

        const rr = await api("/api/users", {
          method: "POST",
          body: JSON.stringify({ email, display_name: name, role, password }),
        });
        if (out) out.textContent = JSON.stringify(rr, null, 2);
        if (rr.status === "ok") await showUsers();
        else alert("Gagal: " + rr.status);
      };

      // Reset password
      panel.querySelectorAll(".btnReset").forEach((btn) => {
        btn.onclick = async () => {
          const uid = btn.getAttribute("data-id");
          const pw = prompt("Password baru (min 10):");
          if (!pw || pw.length < 10) return alert("Password minimal 10 karakter.");

          const rr = await api("/api/users", {
            method: "PUT",
            body: JSON.stringify({ action: "reset_password", user_id: uid, new_password: pw }),
          });
          if (out) out.textContent = JSON.stringify(rr, null, 2);
          alert(rr.status);
        };
      });

      // Disable user
      panel.querySelectorAll(".btnDisable").forEach((btn) => {
        btn.onclick = async () => {
          const uid = btn.getAttribute("data-id");
          if (!confirm("Disable user ini?")) return;

          const rr = await api("/api/users", {
            method: "PUT",
            body: JSON.stringify({ action: "disable", user_id: uid }),
          });
          if (out) out.textContent = JSON.stringify(rr, null, 2);
          if (rr.status === "ok") await showUsers();
          else alert("Gagal: " + rr.status);
        };
      });
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
