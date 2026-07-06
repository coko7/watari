// Watari client-side behavior. Non-crypto UI glue uses HTMX; password
// encryption (watari.md §9) is native fetch() because htmx's
// `htmx:configRequest` event isn't awaitable and WebCrypto is async.

const RPEN_MAGIC = new Uint8Array([0x52, 0x50, 0x45, 0x4e]);
const RPEN_VERSION = 1;

// --- Theme toggle (persisted in localStorage; falls back to OS preference) ---
const THEME_KEY = "watari-theme";

function systemTheme() {
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
}

applyTheme(localStorage.getItem(THEME_KEY) || systemTheme());

document.getElementById("theme-toggle")?.addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  localStorage.setItem(THEME_KEY, next);
  applyTheme(next);
});

function pbkdf2Iterations() {
  const meta = document.querySelector('meta[name="pbkdf2-iterations"]');
  return parseInt(meta?.content ?? "310000", 10);
}

function csrfToken() {
  return document.querySelector('meta[name="csrf-token"]')?.content ?? "";
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return `${value.toFixed(1)} ${units[i]}`;
}

async function deriveKey(password, salt, iterations, usages) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    usages,
  );
}

// Envelope: magic(4) | version(1) | salt(16) | iv(12) | ciphertext+tag
async function encryptEnvelope(password, plaintext, iterations) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt, iterations, ["encrypt"]);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext));

  const envelope = new Uint8Array(RPEN_MAGIC.length + 1 + salt.length + iv.length + ciphertext.length);
  let offset = 0;
  envelope.set(RPEN_MAGIC, offset); offset += RPEN_MAGIC.length;
  envelope[offset] = RPEN_VERSION; offset += 1;
  envelope.set(salt, offset); offset += salt.length;
  envelope.set(iv, offset); offset += iv.length;
  envelope.set(ciphertext, offset);
  return envelope;
}

async function decryptEnvelope(password, envelope) {
  if (envelope.length < 33 || !RPEN_MAGIC.every((b, i) => envelope[i] === b)) {
    throw new Error("not a Watari encrypted payload");
  }
  const version = envelope[4];
  if (version !== RPEN_VERSION) {
    throw new Error(`unsupported envelope version ${version}`);
  }
  const salt = envelope.slice(5, 21);
  const iv = envelope.slice(21, 33);
  const ciphertext = envelope.slice(33);
  const key = await deriveKey(password, salt, pbkdf2Iterations(), ["decrypt"]);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return new Uint8Array(plaintext);
}

// --- Highlight the active sidebar link ---
document.querySelectorAll(".sidebar-nav a").forEach((a) => {
  if (new URL(a.href).pathname === location.pathname) a.classList.add("active");
});

// --- Copy-to-clipboard (dashboard rows + post-upload flash) ---
document.addEventListener("click", (e) => {
  const btn = e.target.closest(".copy-btn");
  if (!btn) return;
  const text = btn.dataset.copy;
  if (text) navigator.clipboard?.writeText(text);
});

// --- Drag-and-drop file input (upload page) ---
function updateDropzoneFile(dropzone) {
  const input = dropzone.querySelector('input[type="file"]');
  const label = dropzone.querySelector(".dropzone-file");
  const file = input?.files?.[0];
  if (!label) return;
  if (file) {
    label.textContent = `${file.name} (${formatBytes(file.size)})`;
    label.hidden = false;
  } else {
    label.hidden = true;
  }
}

document.querySelectorAll(".dropzone").forEach((dropzone) => {
  const input = dropzone.querySelector('input[type="file"]');
  input?.addEventListener("change", () => updateDropzoneFile(dropzone));

  ["dragenter", "dragover"].forEach((evt) =>
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.add("dropzone-active");
    }),
  );
  ["dragleave", "dragend", "drop"].forEach((evt) =>
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.remove("dropzone-active");
    }),
  );
  dropzone.addEventListener("drop", (e) => {
    const file = e.dataTransfer?.files?.[0];
    if (file && input) {
      input.files = e.dataTransfer.files;
      updateDropzoneFile(dropzone);
    }
  });
});

// --- Reveal password fields when "password-protect" is checked ---
document.addEventListener("change", (e) => {
  if (e.target.id !== "encrypt-toggle") return;
  const fields = e.target.closest("form")?.querySelector(".encrypt-fields");
  if (fields) fields.hidden = !e.target.checked;
});

// --- Encrypted upload/paste/shorten submission (bypasses HTMX for these) ---
const ENCRYPTABLE_FORM_IDS = ["upload-form", "paste-form", "shorten-form"];

async function readPlaintext(form) {
  if (form.id === "upload-form") {
    const file = form.querySelector("#file")?.files?.[0];
    if (!file) throw new Error("choose a file first");
    const name = form.querySelector("#filename")?.value?.trim() || file.name;
    return { bytes: new Uint8Array(await file.arrayBuffer()), filename: name };
  }
  if (form.id === "paste-form") {
    const content = form.querySelector("#content")?.value ?? "";
    const name = form.querySelector("#filename")?.value?.trim() || "paste.txt";
    return { bytes: new TextEncoder().encode(content), filename: name };
  }
  if (form.id === "shorten-form") {
    const url = form.querySelector("#url")?.value ?? "";
    if (!url) throw new Error("enter a URL first");
    return { bytes: new TextEncoder().encode(url), filename: "shortened-url.txt" };
  }
  throw new Error("unknown form");
}

function renderFlash(container, ok, message, url) {
  const div = document.createElement("div");
  div.className = `flash ${ok ? "flash-ok" : "flash-error"}`;
  const p = document.createElement("p");
  p.textContent = message;
  div.appendChild(p);
  if (url) {
    const wrap = document.createElement("div");
    wrap.className = "flash-url";
    const input = document.createElement("input");
    input.type = "text";
    input.readOnly = true;
    input.value = url;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "copy-btn";
    btn.dataset.copy = url;
    btn.textContent = "Copy";
    wrap.append(input, btn);
    div.appendChild(wrap);
  }
  container.replaceChildren(div);
}

async function submitEncrypted(form) {
  const resultEl = form.parentElement.querySelector("#result");
  const password = form.querySelector("#password")?.value ?? "";
  const confirmPassword = form.querySelector("#password-confirm")?.value ?? "";

  if (!password || password !== confirmPassword) {
    if (resultEl) renderFlash(resultEl, false, "Passwords do not match.");
    return;
  }

  let plaintext, filename;
  try {
    ({ bytes: plaintext, filename } = await readPlaintext(form));
  } catch (err) {
    if (resultEl) renderFlash(resultEl, false, err.message);
    return;
  }

  const envelope = await encryptEnvelope(password, plaintext, pbkdf2Iterations());
  const blob = new Blob([envelope], { type: "application/octet-stream" });

  const fd = new FormData();
  fd.append("file", blob, `${filename}.enc`);
  const expire = form.querySelector("#expire")?.value;
  if (expire) fd.append("expire", expire);
  if (form.querySelector('input[name="oneshot"]')?.checked) fd.append("oneshot", "true");

  const endpoint = form.getAttribute("hx-post");
  try {
    const resp = await fetch(endpoint, {
      method: "POST",
      headers: { "X-CSRF-Token": csrfToken() },
      body: fd,
    });
    const html = await resp.text();
    if (resultEl) resultEl.innerHTML = html;
  } catch (err) {
    if (resultEl) renderFlash(resultEl, false, `Upload failed: ${err.message}`);
  }
}

document.addEventListener(
  "submit",
  (e) => {
    const form = e.target;
    if (!ENCRYPTABLE_FORM_IDS.includes(form.id)) return;
    if (!form.querySelector("#encrypt-toggle")?.checked) return;
    // Capture-phase + stopPropagation so HTMX's own (bubble-phase) submit
    // handler on this same form never runs for the encrypted path.
    e.preventDefault();
    e.stopPropagation();
    submitEncrypted(form);
  },
  true,
);

// --- Decrypt page ---
document.addEventListener("submit", async (e) => {
  const form = e.target;
  if (form.id !== "decrypt-form") return;
  e.preventDefault();

  const appEl = document.getElementById("decrypt-app");
  const resultEl = document.getElementById("decrypt-result");
  const password = form.querySelector("#decrypt-password")?.value ?? "";
  if (resultEl) resultEl.textContent = "Decrypting…";

  try {
    const resp = await fetch(appEl.dataset.fetchUrl);
    if (!resp.ok) throw new Error(`could not fetch the paste (${resp.status})`);
    const envelope = new Uint8Array(await resp.arrayBuffer());
    const plaintext = await decryptEnvelope(password, envelope);
    renderDecrypted(resultEl, plaintext);
  } catch {
    if (resultEl) {
      resultEl.innerHTML =
        '<div class="flash flash-error"><p>Decryption failed: wrong password, or this isn\'t a Watari encrypted link.</p></div>';
    }
  }
});

function renderDecrypted(container, bytes) {
  if (!container) return;
  container.replaceChildren();

  let text = null;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    // Not valid UTF-8 text; treat as binary.
  }

  if (text !== null) {
    const pre = document.createElement("pre");
    pre.textContent = text;
    container.appendChild(pre);
  } else {
    const blob = new Blob([bytes]);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "decrypted-file";
    a.textContent = "Download decrypted file";
    container.appendChild(a);
  }
}
