window.OrlandApp = (() => {
  async function api(path, opt = {}) {
    const res = await fetch(path, {
      method: opt.method || "GET",
      headers: opt.headers || { "content-type": "application/json" },
      body: opt.body || undefined,
      credentials: "include", // penting kalau session pakai cookie
    });

    const ct = res.headers.get("content-type") || "";
    if (!ct.includes("application/json")) {
      const text = await res.text().catch(() => "");
      return { status: "server_error", data: { http: res.status, body: text.slice(0, 200) } };
    }
    return await res.json();
  }

  function qs(id){ return document.getElementById(id); }

  async function initLogin(){
    const out = qs("out");
    qs("login").onclick = async () => {
      const email = String(qs("email").value||"").trim().toLowerCase();
      const password = String(qs("pass").value||"");
      const r = await api("/api/login", { method:"POST", body: JSON.stringify({ email, password }) });
      if (out) out.textContent = JSON.stringify(r, null, 2);

      if (r.status === "ok") location.href = "/dashboard.html";
      else alert("Gagal: " + r.status);
    };
  }

  async function initDashboard(){
    const out = qs("out");
    const meEl = qs("me");

    const me = await api("/api/me");
    if (me.status !== "ok") {
      location.href = "/index.html";
      return;
    }
    meEl.textContent = `Hi ${me.data.display_name || me.data.id} — roles: ${(me.data.roles||[]).join(", ")}`;

    qs("logout").onclick = async () => {
      await api("/api/logout", { method:"POST", body:"{}" });
      location.href = "/index.html";
    };

    qs("loadTalents").onclick = async () => {
      const r = await api("/api/talents");
      out.textContent = JSON.stringify(r, null, 2);
    };

    qs("createTalent").onclick = async () => {
      const name = prompt("Nama talent:");
      if (!name) return;
      const r = await api("/api/talents", { method:"POST", body: JSON.stringify({ name }) });
      out.textContent = JSON.stringify(r, null, 2);
    };

    qs("uploadAvatar").onclick = async () => {
      const f = await pickFile();
      if (!f) return;

      // 1) init signed URL
      const init = await api("/api/upload/init", { method:"POST", body: JSON.stringify({ filename: f.name, content_type: f.type || "application/octet-stream" }) });
      if (init.status !== "ok") { out.textContent = JSON.stringify(init, null, 2); return; }

      // 2) PUT to R2 signed url
      const put = await fetch(init.data.upload_url, { method:"PUT", body: f, headers: { "content-type": f.type || "application/octet-stream" } });
      if (!put.ok) { out.textContent = "Upload failed: " + put.status; return; }

      // 3) commit save key to profile
      const commit = await api("/api/upload/commit", { method:"POST", body: JSON.stringify({ object_key: init.data.object_key }) });
      out.textContent = JSON.stringify({ init, commit }, null, 2);
    };
  }

  async function initResetRequest(){
    const out = qs("out");
    qs("go").onclick = async () => {
      const email = String(qs("email").value||"").trim().toLowerCase();
      const r = await api("/api/auth/password/reset/request", { method:"POST", body: JSON.stringify({ email }) });
      out.textContent = JSON.stringify(r, null, 2);
      alert("Jika email terdaftar, link reset akan dikirim.");
    };
  }

  function pickFile(){
    return new Promise((resolve) => {
      const input = document.createElement("input");
      input.type = "file";
      input.accept = "image/*";
      input.onchange = () => resolve(input.files && input.files[0] ? input.files[0] : null);
      input.click();
    });
  }

  return { initLogin, initDashboard, initResetRequest };
})();
