async function main() {
  const statusRes = await fetch("/api/auth/status");
  const status = await statusRes.json();

  if (status.authenticated) {
    window.location.href = "/";
    return;
  }

  const setupMode = status.setup_required;
  const title = document.getElementById("auth-title");
  const hint = document.getElementById("auth-hint");
  const submit = document.getElementById("auth-submit");
  const passwordInput = document.getElementById("password");

  if (setupMode) {
    title.textContent = "Create the admin account";
    hint.textContent = "No admin account exists yet. Choose a username and password to finish setup.";
    submit.textContent = "Create account";
    passwordInput.autocomplete = "new-password";
    passwordInput.minLength = 8;
  }

  document.getElementById("auth-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const errorEl = document.getElementById("auth-error");
    errorEl.textContent = "";

    const username = document.getElementById("username").value.trim();
    const password = passwordInput.value;

    try {
      const res = await fetch(setupMode ? "/api/auth/setup" : "/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.error || `${res.status}`);
      }
      window.location.href = "/";
    } catch (err) {
      errorEl.textContent = err.message;
    }
  });
}

main();
