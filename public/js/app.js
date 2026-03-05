window.OrlandApp = (() => {

  async function initSetup() {
  const out = document.getElementById("out");

  // cek status setup
  const st = await api("/api/setup/status");
  if (out) out.textContent = JSON.stringify(st, null, 2);

  if (st.status !== "ok") {
    alert("Gagal cek setup: " + st.status);
    return;
  }

  // jika tidak perlu setup, balik ke login
  if (!st.data?.setup_required) {
    location.href = "/index.html";
    return;
  }

  document.getElementById("go").onclick = async () => {
    const display_name = String(document.getElementById("name").value || "").trim();
    const email = String(document.getElementById("email").value || "").trim().toLowerCase();
    const password = String(document.getElementById("pass").value || "");

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

  
  async function api(path, opt = {}) {
    const headers = Object.assign({}, opt.headers || {});
    if (opt.body != null && !headers["content-type"]) headers["content-type"] = "application/json";

    try {
      const res = await fetch(path, {
        method: opt.method || "GET",
        headers,
        body: opt.body || undefined,
        credentials: "include", // cookie session same-origin
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

  const qs = (id) => document.getElementById(id);

  function pickFile() {
    return new Promise((resolve) => {
      const input = document.createElement("input");
      input.type = "file";
      input.accept = "image/*";
      input.onchange = () => resolve(input.files && input.files[0] ? input.files[0] : null);
      input.click();
    });
  }

  async function initLogin() {
    const out = qs("out");
    qs("login").onclick = async () => {
      const email = String(qs("email").value || "").trim().toLowerCase();
      const password = String(qs("pass").value || "");
      const r = await api("/api/login", { method: "POST", body: JSON.stringify({ email, password }) });
      if (out) out.textContent = JSON.stringify(r, null, 2);
      if (r.status === "ok") location.href = "/dashboard.html";
      else alert("Gagal: " + r.status);
    };
  }

  async function initDashboard() {
    const out = qs("out");
    const meEl = qs("me");
    const panel = qs("panel");

    const me = await api("/api/me");
    out.textContent = JSON.stringify(me, null, 2);
    if (me.status !== "ok") {
      location.href = "/index.html";
      return;
    }
    const roles = (me.data.roles || []).join(", ");
    meEl.textContent = `Hi ${me.data.display_name || me.data.id} — roles: ${roles}`;

    qs("logout").onclick = async () => {
      await api("/api/logout", { method: "POST", body: "{}" });
      location.href = "/index.html";
    };

    async function showUsers() {
      const r = await api("/api/users");
      out.textContent = JSON.stringify(r, null, 2);
      if (r.status !== "ok") return alert("Gagal: " + r.status);

      panel.innerHTML = `
        <div class="row" style="justify-content:space-between">
          <b>Users</b>
          <button id="createUser">Create</button>
        </div>
        <table class="table" style="margin-top:10px">
          <thead><tr><th>Email</th><th>Name</th><th>Status</th><th>Roles</th><th>Action</th></tr></thead>
          <tbody>
            ${(r.data.users || []).map(u => `
              <tr>
                <td>${escapeHtml(u.email_norm)}</td>
                <td>${escapeHtml(u.display_name || "")}</td>
                <td>${escapeHtml(u.status)}</td>
                <td>${escapeHtml((u.roles||[]).join(","))}</td>
                <td>
                  <button data-id="${u.id}" class="btnReset">Reset Pw</button>
                  <button data-id="${u.id}" class="btnDisable">Disable</button>
                </td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      `;

      panel.querySelector("#createUser").onclick = async () => {
        const email = prompt("Email user:");
        if (!email) return;
        const name = prompt("Display name:");
        const role = prompt("Role (admin/staff/client/talent) :", "staff");
        const password = prompt("Password (min 10):");
        const rr = await api("/api/users", {
          method:"POST",
          body: JSON.stringify({ email, display_name: name, role, password })
        });
        out.textContent = JSON.stringify(rr, null, 2);
        if (rr.status === "ok") await showUsers(); else alert(rr.status);
      };

      panel.querySelectorAll(".btnReset").forEach(btn => {
        btn.onclick = async () => {
          const uid = btn.getAttribute("data-id");
          const pw = prompt("Password baru (min 10):");
          if (!pw) return;
          const rr = await api("/api/users", { method:"PUT", body: JSON.stringify({ action:"reset_password", user_id: uid, new_password: pw }) });
          out.textContent = JSON.stringify(rr, null, 2);
          alert(rr.status);
        };
      });

      panel.querySelectorAll(".btnDisable").forEach(btn => {
        btn.onclick = async () => {
          const uid = btn.getAttribute("data-id");
          const rr = await api("/api/users", { method:"PUT", body: JSON.stringify({ action:"disable", user_id: uid }) });
          out.textContent = JSON.stringify(rr, null, 2);
          if (rr.status === "ok") await showUsers(); else alert(rr.status);
        };
      });
    }

    async function showTalents() {
      const r = await api("/api/talents");
      out.textContent = JSON.stringify(r, null, 2);
      if (r.status !== "ok") return alert("Gagal: " + r.status);

      panel.innerHTML = `
        <div class="row" style="justify-content:space-between">
          <b>Talents</b>
          <button id="createTalent">Create Talent User</button>
        </div>
        <table class="table" style="margin-top:10px">
          <thead><tr><th>Email</th><th>Name</th><th>Status</th><th>Avatar</th></tr></thead>
          <tbody>
            ${(r.data.talents || []).map(u => `
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
        const rr = await api("/api/users", {
          method:"POST",
          body: JSON.stringify({ email, display_name: name, role: "talent", password })
        });
        out.textContent = JSON.stringify(rr, null, 2);
        if (rr.status === "ok") await showTalents(); else alert(rr.status);
      };
    }

    async function showUpload() {
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

        const init = await api("/api/upload/init", { method:"POST", body: JSON.stringify({ filename: f.name, content_type: f.type || "application/octet-stream" }) });
        out.textContent = JSON.stringify(init, null, 2);
        if (init.status !== "ok") return alert("Init failed: " + init.status);

        const put = await fetch(init.data.upload_url, {
          method: "PUT",
          body: f,
          headers: { "content-type": f.type || "application/octet-stream" }
        });
        if (!put.ok) return alert("Upload gagal: " + put.status);

        const commit = await api("/api/upload/commit", { method:"POST", body: JSON.stringify({ object_key: init.data.object_key }) });
        out.textContent = JSON.stringify({ init, commit }, null, 2);
        alert(commit.status);
      };
    }

    qs("tabUsers").onclick = showUsers;
    qs("tabTalents").onclick = showTalents;
    qs("tabUpload").onclick = showUpload;

    await showUsers();
  }

  async function initResetRequest() {
    const out = qs("out");
    qs("go").onclick = async () => {
      const email = String(qs("email").value || "").trim().toLowerCase();
      // sementara belum implement email reset; kita log request saja
      const r = await api("/api/users", { method:"PUT", body: JSON.stringify({ action:"reset_request", email }) });
      out.textContent = JSON.stringify(r, null, 2);
      alert("Request dicatat. (Self-service email bisa diaktifkan nanti)");
    };
  }

  function escapeHtml(s){
    return String(s ?? "").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;");
  }

  return { initLogin, initDashboard, initResetRequest };
})();
