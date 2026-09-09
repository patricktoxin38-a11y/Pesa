async function api(url, opt = {}) {
  const r = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...opt
  });

  let d = {};
  try {
    d = await r.json();
  } catch {}

  if (!r.ok) {
    throw new Error(d.error || "Request failed");
  }

  return d;
}

function formHandler(id, url, redirect) {
  const form = document.getElementById(id);
  const msg = document.getElementById("msg");

  if (!form) return;

  form.onsubmit = async (e) => {
    e.preventDefault();

    if (msg) {
      msg.textContent = "Creating account...";
    }

    const data = Object.fromEntries(
      new FormData(form).entries()
    );

    try {
      await api(url, {
        method: "POST",
        body: JSON.stringify(data)
      });

      if (msg) {
        msg.textContent = "Account created successfully!";
      }

      window.location.href = redirect;
    } catch (err) {
      if (msg) {
        msg.textContent = err.message;
      }
    }
  };
}
