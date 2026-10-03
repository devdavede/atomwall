function bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let str = "";
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlToBuffer(base64url) {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = base64.length % 4 === 0 ? "" : "=".repeat(4 - (base64.length % 4));
  const str = atob(base64 + pad);
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
  return bytes.buffer;
}

function credentialToJson(assertion) {
  return {
    id: bufferToBase64url(assertion.rawId),
    response: {
      clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
      authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
      signature: bufferToBase64url(assertion.response.signature),
    },
  };
}

async function performPasskeyLogin(optionsPath, verifyPath) {
  const optionsRes = await fetch(optionsPath);
  const options = await optionsRes.json();
  if (!optionsRes.ok) {
    throw new Error(options.error || "failed to start passkey sign-in");
  }
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: base64urlToBuffer(options.challenge),
      rpId: options.rpId,
      timeout: options.timeout,
      userVerification: options.userVerification,
      allowCredentials: (options.allowCredentials || []).map((c) => ({
        type: c.type,
        id: base64urlToBuffer(c.id),
      })),
    },
  });
  const verifyRes = await fetch(verifyPath, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ credential: credentialToJson(assertion) }),
  });
  const data = await verifyRes.json().catch(() => ({}));
  if (!verifyRes.ok) {
    throw new Error(data.error || "passkey sign-in failed");
  }
}

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
  const passkeySigninBtn = document.getElementById("passkey-signin-btn");

  if (setupMode) {
    title.textContent = "Create the admin account";
    hint.textContent = "No admin account exists yet. Choose a username and password to finish setup.";
    submit.textContent = "Create account";
    passwordInput.autocomplete = "new-password";
    passwordInput.minLength = 8;
    // No account/passkey can exist yet — passwordless sign-in has nothing to authenticate against.
    passkeySigninBtn.style.display = "none";
  }

  const authForm = document.getElementById("auth-form");
  const authError = document.getElementById("auth-error");
  const mfaForm = document.getElementById("mfa-form");
  const mfaLabel = document.getElementById("mfa-label");
  const mfaCodeInput = document.getElementById("mfa-code");
  const mfaError = document.getElementById("mfa-error");
  const mfaUseBackupLink = document.getElementById("mfa-use-backup-code");
  const mfaUsePasskeyRow = document.getElementById("mfa-use-passkey-row");
  const mfaUsePasskeyLink = document.getElementById("mfa-use-passkey");
  let usingBackupCode = false;

  function showMfaStep(methods) {
    authForm.style.display = "none";
    passkeySigninBtn.style.display = "none";
    title.textContent = "Two-factor authentication";
    hint.textContent = "Enter the 6-digit code from your authenticator app.";
    mfaForm.style.display = "";
    mfaUsePasskeyRow.style.display = methods.includes("webauthn") ? "" : "none";
    mfaCodeInput.value = "";
    mfaCodeInput.focus();
  }

  passkeySigninBtn.addEventListener("click", async () => {
    authError.textContent = "";
    try {
      await performPasskeyLogin("/api/auth/webauthn/login/options", "/api/auth/webauthn/login/verify");
      window.location.href = "/";
    } catch (err) {
      authError.textContent = err.message;
    }
  });

  mfaUsePasskeyLink.addEventListener("click", async (event) => {
    event.preventDefault();
    mfaError.textContent = "";
    try {
      await performPasskeyLogin("/api/auth/webauthn/2fa/options", "/api/auth/webauthn/2fa/verify");
      window.location.href = "/";
    } catch (err) {
      mfaError.textContent = err.message;
    }
  });

  mfaUseBackupLink.addEventListener("click", (event) => {
    event.preventDefault();
    usingBackupCode = !usingBackupCode;
    if (usingBackupCode) {
      mfaLabel.textContent = "Backup code";
      mfaCodeInput.setAttribute("autocomplete", "off");
      mfaUseBackupLink.textContent = "Use your authenticator app instead";
      hint.textContent = "Enter one of your one-time backup codes.";
    } else {
      mfaLabel.textContent = "Authenticator code";
      mfaCodeInput.setAttribute("autocomplete", "one-time-code");
      mfaUseBackupLink.textContent = "Use a backup code instead";
      hint.textContent = "Enter the 6-digit code from your authenticator app.";
    }
    mfaCodeInput.value = "";
    mfaError.textContent = "";
    mfaCodeInput.focus();
  });

  authForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    authError.textContent = "";

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
      if (data.mfa_required) {
        showMfaStep(data.methods || []);
        return;
      }
      window.location.href = "/";
    } catch (err) {
      authError.textContent = err.message;
    }
  });

  mfaForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    mfaError.textContent = "";
    const code = mfaCodeInput.value.trim();
    const path = usingBackupCode ? "/api/auth/2fa/backup-code/verify" : "/api/auth/2fa/totp/verify";

    try {
      const res = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.error || `${res.status}`);
      }
      window.location.href = "/";
    } catch (err) {
      mfaError.textContent = err.message;
    }
  });
}

main();
