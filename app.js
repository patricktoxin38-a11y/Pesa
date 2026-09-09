async function api(url, opt = {}) {
  const r = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...opt
  });

  let d = {};
  try {
    d = await r.json();
  } catch {}

  if (!r.ok) throw Error(d.error || "Request failed");
  return d;
}

function formHandler(id, url, redirect) {
  document.getElementById(id).onsubmit = async e => {
    e.preventDefault();

    const f = new FormData(e.target);

    try {
      await api(url, {
        method: "POST",
        body: JSON.stringify(Object.fromEntries(f))
      });

      location.href = redirect;
    } catch (x) {
      document.getElementById("msg").textContent = x.message;
    }
  };
}

async function logout() {
  await fetch("/api/logout", { method: "POST" });
  location.href = "/";
}

function esc(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function loadDashboard() {
  try {
    const me = await api("/api/me");

    if (me.role === "admin") {
      location.href = "/admin.html";
      return;
    }

    document.getElementById("name").textContent = "Welcome, " + me.name;
    document.getElementById("balance").textContent = "KSh " + me.balance;

    const tasks = await api("/api/tasks");

    document.getElementById("tasks").innerHTML = tasks.map(t => `
      <article class="card">
        <h3>${esc(t.title)}</h3>
        <p>${esc(t.description)}</p>
        <b>KSh ${t.reward}</b>

        ${
          t.submission_id
            ? `<p>Status: ${esc(t.submission_status)}</p>`
            : `
              <form onsubmit="submitTask(event, ${t.id})">
                <textarea
                  name="proof"
                  placeholder="Paste your proof here"
                  required
                ></textarea>
                <button class="btn">Submit proof</button>
              </form>
            `
        }
      </article>
    `).join("");

    document.getElementById("wf").onsubmit = async e => {
      e.preventDefault();

      try {
        const f = new FormData(e.target);

        await api("/api/withdraw", {
          method: "POST",
          body: JSON.stringify(Object.fromEntries(f))
        });

        document.getElementById("wmsg").textContent =
          "Request submitted.";

        e.target.reset();
      } catch (x) {
        document.getElementById("wmsg").textContent = x.message;
      }
    };

  } catch (e) {
    location.href = "/login.html";
  }
}

async function submitTask(e, id) {
  e.preventDefault();

  try {
    await api("/api/tasks/" + id + "/submit", {
      method: "POST",
      body: JSON.stringify({
        proof: new FormData(e.target).get("proof")
      })
    });

    loadDashboard();
  } catch (x) {
    alert(x.message);
  }
}

async function loadAdmin() {
  try {
    const me = await api("/api/me");

    if (me.role !== "admin") {
      return location.href = "/dashboard.html";
    }

    const s = await api("/api/admin/overview");

    document.getElementById("stats").innerHTML =
      Object.entries(s).map(([k, v]) => `
        <div class="card">
          <small>${esc(k)}</small>
          <h2>${esc(v)}</h2>
        </div>
      `).join("");

    document.getElementById("tf").onsubmit = async e => {
      e.preventDefault();

      try {
        const f = new FormData(e.target);

        await api("/api/admin/tasks", {
          method: "POST",
          body: JSON.stringify(Object.fromEntries(f))
        });

        document.getElementById("tmsg").textContent =
          "Task created.";

        e.target.reset();
      } catch (x) {
        document.getElementById("tmsg").textContent = x.message;
      }
    };

  } catch (e) {
    location.href = "/login.html";
  }
}
