const CATEGORIES = ["routes", "fake_routes", "countries", "isps", "user_agents", "referrers", "body_patterns"];
const TRAFFIC_WINDOW_SECONDS = 60;
let requestsPageSize = 100; // user-selectable via #requests-page-size, see wireRequestsPageSize()
let requestEvents = []; // newest first, mirrors what's rendered in the table
let lastRequestCheckboxRow = null; // for shift-click range-select in the Requests table

// Blacklist panels (the 7 CATEGORIES above, plus "ips" and "whitelist") are
// all loaded in full from the server in one shot — there's no server-side
// offset/limit for these. Pagination is a client-side display cap: the full
// list is cached here so changing the page size just re-renders from cache
// instead of re-fetching, same "Show N" pattern as requestsPageSize above.
const blacklistPageSizes = Object.fromEntries([...CATEGORIES, "ips", "whitelist"].map((c) => [c, 100]));
const blacklistEntriesCache = {};
let trafficBuckets = new Array(TRAFFIC_WINDOW_SECONDS).fill(0); // bytes/sec, oldest first
let currentSecondBytes = 0;
let currentSecondStart = Math.floor(Date.now() / 1000);

function showToast(message, kind) {
  const toast = document.getElementById("toast");
  toast.textContent = message;
  toast.className = "toast show " + (kind || "");
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => {
    toast.className = "toast";
  }, 2500);
}

function escapeHtml(text) {
  // Escapes quotes too (not just &/</>) since this is used inside HTML attribute
  // values (e.g. title="...") as well as text content — attacker-controlled
  // fields (User-Agent, path, block reason) go through this before innerHTML.
  return String(text ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[ch]);
}

async function apiGet(path) {
  const res = await fetch(path);
  if (res.status === 401) {
    window.location.href = "/login.html";
    throw new Error("unauthorized");
  }
  if (!res.ok) throw new Error(`GET ${path} -> ${res.status}`);
  return res.json();
}

async function apiSend(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (res.status === 401) {
    window.location.href = "/login.html";
    throw new Error("unauthorized");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || `${method} ${path} -> ${res.status}`);
  }
  return data;
}

// "whitelist" isn't a blacklist category server-side (see admin_server.cpp) —
// it's one fixed resource at /api/whitelist, not /api/blacklist/whitelist.
// Every generic list-panel helper below (clear/import/import-url) shares this
// so the whitelist panel can reuse them exactly like any other category.
function blacklistBasePath(category) {
  return category === "whitelist" ? "/api/whitelist" : `/api/blacklist/${category}`;
}

async function apiMutate(method, category, value) {
  return apiSend(method, blacklistBasePath(category), { value });
}

// Only clears the permanent (YAML-backed) list for `category` — for "ips"
// that's ip_exact/ip_cidrs. Temporary/score-triggered IP blocks are a
// separate in-memory tracker and are unaffected, same scoping as the server
// side (see admin/admin_server.cpp handle_blacklist_clear).
async function apiClearCategory(category) {
  const path = `${blacklistBasePath(category)}/clear`;
  const res = await fetch(path, { method: "DELETE" });
  if (res.status === 401) {
    window.location.href = "/login.html";
    throw new Error("unauthorized");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || `DELETE ${path} -> ${res.status}`);
  }
  return data;
}

// Sends the raw .list file text as the body (not JSON) — the server splits it
// one entry per line. Reuses the same 401-redirect / error-unwrapping as apiSend.
async function apiImport(category, text) {
  const path = `${blacklistBasePath(category)}/import`;
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "text/plain" },
    body: text,
  });
  if (res.status === 401) {
    window.location.href = "/login.html";
    throw new Error("unauthorized");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || `POST ${path} -> ${res.status}`);
  }
  return data;
}

// Fetches the list server-side (atomwall itself downloads the URL, subject
// to its own SSRF guard — see url_fetch.cpp) and imports it the same way as
// a file upload. Reuses the same 401-redirect / error-unwrapping as apiSend.
async function apiImportUrl(category, url) {
  const path = `${blacklistBasePath(category)}/import-url`;
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  if (res.status === 401) {
    window.location.href = "/login.html";
    throw new Error("unauthorized");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || `POST ${path} -> ${res.status}`);
  }
  return data;
}

// --- generic string-list blacklist categories (routes, countries, isps, user_agents, body_patterns) ---

// yyyy-mm-dd hh:ii:ss in the viewer's local time, from an ISO 8601 UTC timestamp.
function formatAddedAt(iso) {
  const d = new Date(iso);
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
         `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

// Small trash-bin icon used on every remove button in the blacklist/IP-block
// tables — see buildRemoveButton().
const TRASH_ICON_SVG = `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"></path><path d="M10 11v6"></path><path d="M14 11v6"></path><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"></path></svg>`;

function buildRemoveButton(title, onClick) {
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "row-remove-btn";
  btn.title = title;
  btn.setAttribute("aria-label", title);
  btn.innerHTML = TRASH_ICON_SVG;
  btn.addEventListener("click", onClick);
  return btn;
}

// "score" (server-side auto-ban source, IP blocks only) displays as "auto" —
// keeps the CSS class ("source-pill score") stable while reading better next
// to "manual"/"list" everywhere else. See buildSourcePill().
function sourceLabel(source) {
  return source === "score" ? "auto" : source;
}

function buildSourcePill(source) {
  const span = document.createElement("span");
  span.className = `source-pill ${source}`;
  span.textContent = sourceLabel(source);
  return span;
}

// Every blacklist category renders as a table row: value / source / added / expires / remove.
// Generic categories (routes, user_agents, ...) are permanent-only — there's
// no per-entry TTL, so Expires always reads "permanent" (mirrors the ips
// table's own permanent rows, see renderIpBlocks()).
function buildBlacklistRow(category, entry) {
  const tr = document.createElement("tr");
  tr.dataset.value = entry.value.toLowerCase();
  tr.innerHTML = `
    <td>${escapeHtml(entry.value)}</td>
    <td></td>
    <td>${escapeHtml(formatAddedAt(entry.created_at))}</td>
    <td>permanent</td>
    <td></td>
  `;
  tr.children[1].appendChild(buildSourcePill(entry.source || "manual"));
  tr.lastElementChild.appendChild(buildRemoveButton("Remove", () => onRemove(category, entry.value)));
  return tr;
}

function renderList(category, entries) {
  blacklistEntriesCache[category] = entries;
  const container = document.getElementById(`list-${category}`);
  container.innerHTML = "";
  const pageSize = blacklistPageSizes[category] ?? 100;
  for (const entry of entries.slice(0, pageSize)) {
    container.appendChild(buildBlacklistRow(category, entry));
  }
  updateListCount(category, entries.length);
  applyListFilter(category);
}

function updateListCount(category, total) {
  const el = document.getElementById(`count-${category}`);
  if (!el) return;
  const shown = Math.min(blacklistPageSizes[category] ?? 100, total);
  el.textContent = total > shown ? `Showing ${shown} of ${total}` : `${total} entr${total === 1 ? "y" : "ies"}`;
}

// --- blacklist search/filter ---

function applyListFilter(category) {
  const input = document.querySelector(`.filter-input[data-category="${category}"]`);
  const query = input ? input.value.trim().toLowerCase() : "";
  const container = document.getElementById(`list-${category}`);
  if (!container) return;
  for (const row of container.children) {
    row.classList.toggle("filtered-out", query.length > 0 && !row.dataset.value.includes(query));
  }
}

function applyIpBlockFilter() {
  const input = document.getElementById("ip-filter");
  const query = input ? input.value.trim().toLowerCase() : "";
  const tbody = document.getElementById("ip-blocks-body");
  if (!tbody) return;
  for (const row of tbody.children) {
    row.classList.toggle("filtered-out", query.length > 0 && !row.dataset.value.includes(query));
  }
}

function wireBlacklistPageSizes() {
  document.querySelectorAll(".page-size-select[data-category]").forEach((select) => {
    select.addEventListener("change", (e) => {
      const category = e.target.dataset.category;
      blacklistPageSizes[category] = Number(e.target.value);
      const cached = blacklistEntriesCache[category] || [];
      if (category === "ips") {
        renderIpBlocks(cached);
      } else {
        renderList(category, cached);
      }
    });
  });
}

function wireFilterInputs() {
  document.querySelectorAll(".filter-input[data-category]").forEach((input) => {
    input.addEventListener("input", () => applyListFilter(input.dataset.category));
  });
  const ipFilter = document.getElementById("ip-filter");
  if (ipFilter) {
    ipFilter.addEventListener("input", applyIpBlockFilter);
  }
}

// --- confirmation dialog (native <dialog>, reused for any yes/no prompt) ---

function confirmAction(message, confirmLabel) {
  const dialog = document.getElementById("confirm-dialog");
  document.getElementById("confirm-dialog-message").textContent = message;
  const confirmBtn = document.getElementById("confirm-dialog-confirm");
  confirmBtn.textContent = confirmLabel || "Clear all";
  dialog.showModal();
  return new Promise((resolve) => {
    const cancelBtn = document.getElementById("confirm-dialog-cancel");
    const cleanup = (result) => {
      cancelBtn.removeEventListener("click", onCancel);
      confirmBtn.removeEventListener("click", onConfirm);
      dialog.removeEventListener("cancel", onCancel);
      dialog.close();
      resolve(result);
    };
    const onCancel = (event) => {
      event.preventDefault?.();
      cleanup(false);
    };
    const onConfirm = () => cleanup(true);
    cancelBtn.addEventListener("click", onCancel);
    confirmBtn.addEventListener("click", onConfirm);
    dialog.addEventListener("cancel", onCancel);
  });
}

function wireClearAllButtons() {
  document.querySelectorAll(".clear-all-btn[data-category]").forEach((button) => {
    button.addEventListener("click", async () => {
      const category = button.dataset.category;
      const label = category === "ips" ? "IP / CIDR" : category.replace(/_/g, " ");
      const ok = await confirmAction(
        category === "whitelist"
          ? "Clear the entire whitelist? This removes every stored entry and can't be undone."
          : `Clear the entire ${label} blacklist? This removes every stored entry and can't be undone.`
      );
      if (!ok) return;
      try {
        await apiClearCategory(category);
        if (category === "ips") {
          await loadIpBlocks();
        } else {
          renderList(category, []);
        }
        showToast(category === "whitelist" ? "Cleared whitelist" : `Cleared ${label} blacklist`, "ok");
      } catch (err) {
        if (err.message !== "unauthorized") showToast(err.message, "error");
      }
    });
  });
}

async function onRemove(category, value) {
  try {
    const updated = await apiMutate("DELETE", category, value);
    renderList(category, updated);
    showToast(`Removed from ${category}`, "ok");
  } catch (err) {
    if (err.message !== "unauthorized") showToast(err.message, "error");
  }
}

function wireForms() {
  document.querySelectorAll(".add-form").forEach((form) => {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const category = form.dataset.category;
      const input = form.querySelector("input");
      const value = input.value.trim();
      if (!value) return;
      try {
        const updated = await apiMutate("POST", category, value);
        renderList(category, updated);
        input.value = "";
        showToast(`Added to ${category}`, "ok");
      } catch (err) {
        if (err.message !== "unauthorized") showToast(err.message, "error");
      }
    });
  });
}

// IPs use loadIpBlocks() to re-render (unified permanent+temporary view); every
// other category re-renders from the entries the import response already carries,
// avoiding a redundant GET.
function wireImportForms() {
  document.querySelectorAll(".import-input").forEach((input) => {
    input.addEventListener("change", async () => {
      const file = input.files[0];
      if (!file) return;
      const category = input.dataset.category;
      try {
        const text = await file.text();
        const result = await apiImport(category, text);
        if (category === "ips") {
          await loadIpBlocks();
        } else {
          renderList(category, result.entries);
        }
        const suffix = result.skipped ? `, skipped ${result.skipped} invalid line(s)` : "";
        showToast(`Imported ${result.added} to ${category}${suffix}`, "ok");
      } catch (err) {
        if (err.message !== "unauthorized") showToast(err.message, "error");
      } finally {
        input.value = "";
      }
    });
  });
}

// IPs use loadIpBlocks() to re-render (unified permanent+temporary view); every
// other category re-renders from the entries the import response already carries,
// avoiding a redundant GET — same pattern as wireImportForms above.
function wireImportUrlForms() {
  document.querySelectorAll(".import-url-form").forEach((form) => {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const category = form.dataset.category;
      const input = form.querySelector("input");
      const url = input.value.trim();
      if (!url) return;
      try {
        const result = await apiImportUrl(category, url);
        if (category === "ips") {
          await loadIpBlocks();
        } else {
          renderList(category, result.entries);
        }
        const suffix = result.skipped ? `, skipped ${result.skipped} invalid line(s)` : "";
        showToast(`Imported ${result.added} to ${category}${suffix}`, "ok");
        input.value = "";
      } catch (err) {
        if (err.message !== "unauthorized") showToast(err.message, "error");
      }
    });
  });
}

// --- overview ---

function renderOverview(config) {
  const grid = document.getElementById("overview-grid");
  const items = [
    ["HTTP listener", `${config.http.bind}:${config.http.port}${config.http.enabled ? "" : " (disabled)"}`],
    ["HTTPS listener", `${config.https.bind}:${config.https.port}${config.https.enabled ? "" : " (disabled)"}`],
    ["Upstream", `${config.upstream.host}:${config.upstream.port}`],
    ["Max body size", `${(config.limits.max_body_bytes / 1024 / 1024).toFixed(1)} MB`],
  ];
  grid.innerHTML = "";
  for (const [label, value] of items) {
    const div = document.createElement("div");
    div.className = "overview-item";
    div.innerHTML = `<div class="label">${label}</div><div class="value">${value}</div>`;
    grid.appendChild(div);
  }

  document.getElementById("status").textContent =
    `listening on ${config.http.bind}:${config.http.port} / ${config.https.bind}:${config.https.port} → ${config.upstream.host}:${config.upstream.port}`;
}

async function refreshAll() {
  const config = await apiGet("/api/config");
  renderOverview(config);
  for (const category of CATEGORIES) {
    renderList(category, config.blacklist[category]);
  }
  renderList("whitelist", config.whitelist);
}

// --- requests table / live view / stats ---

function formatTime(iso) {
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
}

function truncate(text, max) {
  if (!text) return "";
  return text.length > max ? text.slice(0, max - 1) + "…" : text;
}

async function onBlockIpFromRow(ip, button) {
  try {
    await apiMutate("POST", "ips", ip);
    showToast(`Blocked ${ip}`, "ok");
    button.textContent = "blocked";
    button.disabled = true;
    loadIpBlocks().catch(() => {});
  } catch (err) {
    if (err.message !== "unauthorized") showToast(err.message, "error");
  }
}

async function onBlockIspFromRow(isp, button) {
  try {
    const updated = await apiMutate("POST", "isps", isp);
    renderList("isps", updated);
    showToast(`Blocked ISP ${isp}`, "ok");
    button.textContent = "blocked";
    button.disabled = true;
  } catch (err) {
    if (err.message !== "unauthorized") showToast(err.message, "error");
  }
}

async function onWhitelistIpFromRow(ip, button) {
  try {
    const updated = await apiMutate("POST", "whitelist", ip);
    renderList("whitelist", updated);
    showToast(`Whitelisted ${ip}`, "ok");
    button.textContent = "whitelisted";
    button.disabled = true;
  } catch (err) {
    if (err.message !== "unauthorized") showToast(err.message, "error");
  }
}

function buildRequestRow(event) {
  const tr = document.createElement("tr");
  tr.className = event.blocked ? "blocked" : "";
  tr.dataset.seq = event.seq;
  tr.dataset.blocked = event.blocked ? "blocked" : "allowed";
  tr.dataset.status = String(event.status_code || "");
  tr.dataset.ip = event.client_ip;
  tr.dataset.domain = event.domain || "";
  tr.dataset.country = event.country || "";
  tr.dataset.isp = event.isp;
  tr.dataset.method = event.method || "";
  tr.dataset.path = event.path;
  tr.dataset.userAgent = event.user_agent || "";

  const statusPill = `<span class="status-pill ${event.blocked ? "blocked" : "allowed"}" title="${event.blocked ? escapeHtml(event.block_reason) : ""}">${event.blocked ? "blocked" : "allowed"}</span>`;

  tr.innerHTML = `
    <td><input type="checkbox" class="row-select" data-seq="${event.seq}"></td>
    <td>${formatTime(event.timestamp)}</td>
    <td>${statusPill}</td>
    <td>${event.status_code || ""}</td>
    <td>${escapeHtml(event.client_ip)}</td>
    <td title="${escapeHtml(event.domain)}">${escapeHtml(truncate(event.domain, 30))}</td>
    <td>${escapeHtml(event.country)}</td>
    <td>${escapeHtml(event.isp)}</td>
    <td>${escapeHtml(event.method)}</td>
    <td title="${escapeHtml(event.path)}">${escapeHtml(truncate(event.path, 40))}</td>
    <td title="${escapeHtml(event.user_agent)}">${escapeHtml(truncate(event.user_agent, 40))}</td>
    <td></td>
  `;

  const actionCell = tr.lastElementChild;
  const blockBtn = document.createElement("button");
  blockBtn.type = "button";
  blockBtn.className = "row-block-btn";
  blockBtn.textContent = "block IP";
  blockBtn.addEventListener("click", () => onBlockIpFromRow(event.client_ip, blockBtn));
  actionCell.appendChild(blockBtn);

  const blockIspBtn = document.createElement("button");
  blockIspBtn.type = "button";
  blockIspBtn.className = "row-block-btn";
  blockIspBtn.textContent = "block ISP";
  if (!event.isp || event.isp === "unknown") {
    blockIspBtn.disabled = true;
    blockIspBtn.title = "ISP unknown for this request";
  } else {
    blockIspBtn.addEventListener("click", () => onBlockIspFromRow(event.isp, blockIspBtn));
  }
  actionCell.appendChild(blockIspBtn);

  const whitelistBtn = document.createElement("button");
  whitelistBtn.type = "button";
  whitelistBtn.className = "row-block-btn";
  whitelistBtn.textContent = "Add to Whitelist";
  whitelistBtn.addEventListener("click", () => onWhitelistIpFromRow(event.client_ip, whitelistBtn));
  actionCell.appendChild(whitelistBtn);

  const rowCheckbox = tr.querySelector(".row-select");
  rowCheckbox.addEventListener("click", (e) => {
    if (e.shiftKey && lastRequestCheckboxRow) {
      const rows = visibleRequestRows();
      const from = rows.indexOf(lastRequestCheckboxRow);
      const to = rows.indexOf(tr);
      if (from !== -1 && to !== -1) {
        const [start, end] = from < to ? [from, to] : [to, from];
        for (let i = start; i <= end; i++) {
          rows[i].querySelector(".row-select").checked = rowCheckbox.checked;
        }
      }
    }
    lastRequestCheckboxRow = tr;
  });
  rowCheckbox.addEventListener("change", updateRequestsBulkActions);

  return tr;
}

function updateStats() {
  const total = requestEvents.length;
  const blocked = requestEvents.filter((e) => e.blocked).length;
  const allowed = total - blocked;
  const rate = total > 0 ? Math.round((blocked / total) * 100) : 0;

  document.getElementById("stat-total").textContent = total;
  document.getElementById("stat-allowed").textContent = allowed;
  document.getElementById("stat-blocked").textContent = blocked;
  document.getElementById("stat-rate").textContent = `${rate}%`;

  const reasonCounts = new Map();
  for (const e of requestEvents) {
    if (!e.blocked) continue;
    const check = e.block_reason.split(":")[0] || "unknown";
    reasonCounts.set(check, (reasonCounts.get(check) || 0) + 1);
  }
  let topReason = "—";
  let topCount = 0;
  for (const [reason, count] of reasonCounts) {
    if (count > topCount) {
      topReason = reason;
      topCount = count;
    }
  }
  document.getElementById("stat-top-reason").textContent =
    topCount > 0 ? `${topReason} (${topCount})` : "—";

  const uniqueIps = new Set(requestEvents.map((e) => e.client_ip)).size;
  document.getElementById("stat-unique-ips").textContent = total > 0 ? uniqueIps : "—";
}

function prependRequestRow(event) {
  requestEvents.unshift(event);
  if (requestEvents.length > requestsPageSize) {
    requestEvents.length = requestsPageSize;
  }
  updateStats();
  addTrafficBytes(event.bytes_transferred || 0);

  if (requestsSort.key) {
    // A custom sort order means the new row doesn't necessarily belong at the top —
    // re-render in sorted order instead of the fast prepend path below.
    renderRequestsTable();
    return;
  }

  const tbody = document.getElementById("requests-body");
  tbody.prepend(buildRequestRow(event));
  while (tbody.children.length > requestsPageSize) {
    tbody.removeChild(tbody.lastElementChild);
  }
  applyRequestsFilters();
}

async function loadRequestHistory() {
  const events = await apiGet(`/api/requests?limit=${requestsPageSize}`);
  requestEvents = events.slice().reverse();
  updateStats();
  renderRequestsTable();
}

// --- requests: column sort ---

let requestsSort = { key: null, dir: 1 }; // dir: 1 = ascending, -1 = descending

const REQUEST_SORT_ACCESSORS = {
  time: (e) => e.timestamp,
  status: (e) => (e.blocked ? 1 : 0),
  code: (e) => e.status_code || 0,
  ip: (e) => e.client_ip || "",
  domain: (e) => e.domain || "",
  country: (e) => e.country || "",
  isp: (e) => e.isp || "",
  method: (e) => e.method || "",
  path: (e) => e.path || "",
  user_agent: (e) => e.user_agent || "",
};

function sortedRequestEvents() {
  if (!requestsSort.key) return requestEvents;
  const accessor = REQUEST_SORT_ACCESSORS[requestsSort.key];
  return [...requestEvents].sort((a, b) => {
    const av = accessor(a);
    const bv = accessor(b);
    if (av < bv) return -requestsSort.dir;
    if (av > bv) return requestsSort.dir;
    return 0;
  });
}

function renderRequestsTable() {
  const tbody = document.getElementById("requests-body");
  tbody.innerHTML = "";
  for (const event of sortedRequestEvents()) {
    tbody.appendChild(buildRequestRow(event));
  }
  applyRequestsFilters();
}

function updateRequestsSortIndicators(headers) {
  for (const th of headers) {
    const active = requestsSort.key === th.dataset.sortKey;
    th.classList.toggle("sorted-asc", active && requestsSort.dir === 1);
    th.classList.toggle("sorted-desc", active && requestsSort.dir === -1);
  }
}

function wireRequestsSort() {
  const headers = document.querySelectorAll(".requests-table th[data-sort-key]");
  for (const th of headers) {
    th.addEventListener("click", () => {
      if (requestsSort.key === th.dataset.sortKey) {
        requestsSort.dir *= -1;
      } else {
        requestsSort.key = th.dataset.sortKey;
        requestsSort.dir = 1;
      }
      updateRequestsSortIndicators(headers);
      renderRequestsTable();
    });
  }
  updateRequestsSortIndicators(headers);
}

// --- requests: multi-field filter, multi-select bulk actions, export ---

const REQUESTS_FILTER_FIELDS = [
  { id: "requests-filter-status", dataset: "blocked", mode: "exact" },
  { id: "requests-filter-code", dataset: "status", mode: "prefix" },
  { id: "requests-filter-ip", dataset: "ip", mode: "substring" },
  { id: "requests-filter-domain", dataset: "domain", mode: "substring" },
  { id: "requests-filter-country", dataset: "country", mode: "substring" },
  { id: "requests-filter-isp", dataset: "isp", mode: "substring" },
  { id: "requests-filter-method", dataset: "method", mode: "substring" },
  { id: "requests-filter-path", dataset: "path", mode: "substring" },
  { id: "requests-filter-ua", dataset: "userAgent", mode: "substring" },
];

function applyRequestsFilters() {
  const filters = REQUESTS_FILTER_FIELDS.map((f) => ({
    ...f,
    query: document.getElementById(f.id).value.trim().toLowerCase(),
  })).filter((f) => f.query.length > 0);

  const tbody = document.getElementById("requests-body");
  for (const row of tbody.children) {
    const matches = filters.every(({ dataset, mode, query }) => {
      const value = (row.dataset[dataset] || "").toLowerCase();
      return mode === "exact" ? value === query
        : mode === "prefix" ? value.startsWith(query)
        : value.includes(query);
    });
    row.classList.toggle("filtered-out", !matches);
  }
  updateRequestsBulkActions();
}

function wireRequestsFilters() {
  for (const { id } of REQUESTS_FILTER_FIELDS) {
    const el = document.getElementById(id);
    el.addEventListener("input", applyRequestsFilters);
    el.addEventListener("change", applyRequestsFilters);
  }
}

function visibleRequestRows() {
  return [...document.getElementById("requests-body").children].filter(
    (row) => !row.classList.contains("filtered-out")
  );
}

function selectedRequestRows() {
  return visibleRequestRows().filter((row) => row.querySelector(".row-select").checked);
}

function updateRequestsBulkActions() {
  const selected = selectedRequestRows();
  const panel = document.getElementById("requests-bulk-actions");
  panel.hidden = selected.length === 0;
  document.getElementById("requests-selected-count").textContent =
    `${selected.length} selected`;
  const selectAll = document.getElementById("requests-select-all");
  const visible = visibleRequestRows();
  selectAll.checked = visible.length > 0 && selected.length === visible.length;
  selectAll.indeterminate = selected.length > 0 && selected.length < visible.length;
}

function wireRequestsSelectAll() {
  document.getElementById("requests-select-all").addEventListener("change", (e) => {
    for (const row of visibleRequestRows()) {
      row.querySelector(".row-select").checked = e.target.checked;
    }
    updateRequestsBulkActions();
  });
}

function wireRequestsBulkActions() {
  document.getElementById("requests-block-ips").addEventListener("click", async () => {
    const ips = [...new Set(selectedRequestRows().map((row) => row.dataset.ip))];
    if (ips.length === 0) return;
    const ok = await confirmAction(`Block ${ips.length} IP(s)?`);
    if (!ok) return;
    let blocked = 0;
    for (const ip of ips) {
      try {
        await apiMutate("POST", "ips", ip);
        blocked++;
      } catch (err) {
        if (err.message !== "unauthorized") showToast(`Failed to block ${ip}: ${err.message}`, "error");
      }
    }
    showToast(`Blocked ${blocked} of ${ips.length} IP(s)`, "ok");
    loadIpBlocks().catch(() => {});
  });

  document.getElementById("requests-block-isps").addEventListener("click", async () => {
    const isps = [...new Set(selectedRequestRows().map((row) => row.dataset.isp))].filter(
      (isp) => isp && isp !== "unknown"
    );
    if (isps.length === 0) return;
    const ok = await confirmAction(`Block ${isps.length} ISP(s)?`);
    if (!ok) return;
    let blocked = 0;
    let lastResult = [];
    for (const isp of isps) {
      try {
        lastResult = await apiMutate("POST", "isps", isp);
        blocked++;
      } catch (err) {
        if (err.message !== "unauthorized") showToast(`Failed to block ${isp}: ${err.message}`, "error");
      }
    }
    if (blocked > 0) renderList("isps", lastResult);
    showToast(`Blocked ${blocked} of ${isps.length} ISP(s)`, "ok");
  });

  document.getElementById("requests-block-routes").addEventListener("click", async () => {
    const routes = [...new Set(selectedRequestRows().map((row) => row.dataset.path.split("?")[0]))];
    if (routes.length === 0) return;
    const ok = await confirmAction(`Block ${routes.length} route(s)?`);
    if (!ok) return;
    let blocked = 0;
    let lastResult = [];
    for (const route of routes) {
      try {
        lastResult = await apiMutate("POST", "routes", route);
        blocked++;
      } catch (err) {
        if (err.message !== "unauthorized") showToast(`Failed to block ${route}: ${err.message}`, "error");
      }
    }
    if (blocked > 0) renderList("routes", lastResult);
    showToast(`Blocked ${blocked} of ${routes.length} route(s)`, "ok");
  });
}

function downloadFile(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function csvEscape(value) {
  const s = String(value ?? "");
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

const REQUEST_EXPORT_COLUMNS = [
  "timestamp", "status_code", "blocked", "block_reason", "client_ip", "domain",
  "country", "isp", "method", "path", "user_agent", "listener", "bytes_transferred",
];

function exportRequestsCsv() {
  const rows = [REQUEST_EXPORT_COLUMNS.join(",")];
  for (const e of requestEvents) {
    rows.push(REQUEST_EXPORT_COLUMNS.map((col) => csvEscape(e[col])).join(","));
  }
  downloadFile("atomwall-requests.csv", rows.join("\n"), "text/csv");
}

function xmlEscape(value) {
  return String(value ?? "").replace(/[<>&'"]/g, (c) => ({
    "<": "&lt;", ">": "&gt;", "&": "&amp;", "'": "&apos;", '"': "&quot;",
  }[c]));
}

function exportRequestsXml() {
  const items = requestEvents.map((e) => {
    const fields = REQUEST_EXPORT_COLUMNS.map(
      (col) => `    <${col}>${xmlEscape(e[col])}</${col}>`
    ).join("\n");
    return `  <request>\n${fields}\n  </request>`;
  }).join("\n");
  const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<requests>\n${items}\n</requests>\n`;
  downloadFile("atomwall-requests.xml", xml, "application/xml");
}

function wireRequestsExport() {
  document.getElementById("requests-export-csv").addEventListener("click", exportRequestsCsv);
  document.getElementById("requests-export-xml").addEventListener("click", exportRequestsXml);
}

function wireRequestsPageSize() {
  document.getElementById("requests-page-size").addEventListener("change", (e) => {
    requestsPageSize = Number(e.target.value);
    loadRequestHistory().catch((err) => {
      if (err.message !== "unauthorized") showToast(err.message, "error");
    });
  });
}

function setLiveIndicator(state) {
  const el = document.getElementById("live-indicator");
  const label = { connecting: "connecting…", connected: "live", error: "reconnecting…" }[state];
  el.className = "live-indicator" + (state === "connected" ? " connected" : "");
  el.innerHTML = `<span class="live-dot"></span>${label}`;
}

function connectLiveRequests() {
  const source = new EventSource("/api/requests/stream");
  setLiveIndicator("connecting");
  source.onopen = () => setLiveIndicator("connected");
  source.onerror = () => setLiveIndicator("error");
  source.onmessage = (message) => {
    try {
      prependRequestRow(JSON.parse(message.data));
    } catch (err) {
      console.error("failed to parse live request event", err);
    }
  };
}

// --- traffic graph (canvas, live-scrolling, single series) ---

function addTrafficBytes(bytes) {
  const nowSecond = Math.floor(Date.now() / 1000);
  if (nowSecond !== currentSecondStart) {
    const gap = Math.min(nowSecond - currentSecondStart, TRAFFIC_WINDOW_SECONDS);
    trafficBuckets.push(currentSecondBytes);
    for (let i = 1; i < gap; i++) trafficBuckets.push(0);
    trafficBuckets = trafficBuckets.slice(-TRAFFIC_WINDOW_SECONDS);
    currentSecondBytes = 0;
    currentSecondStart = nowSecond;
  }
  currentSecondBytes += bytes;
}

function drawTrafficGraph() {
  const canvas = document.getElementById("traffic-canvas");
  if (!canvas) return;
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  if (rect.width === 0) return;
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  const w = rect.width;
  const h = rect.height;
  ctx.clearRect(0, 0, w, h);

  const series = trafficBuckets.concat([currentSecondBytes]).slice(-TRAFFIC_WINDOW_SECONDS);
  const maxVal = Math.max(...series, 64 * 1024); // 64KB floor so idle traffic isn't a jittery flat line
  const stepX = w / (TRAFFIC_WINDOW_SECONDS - 1);
  const topPad = 8;

  const pointY = (v) => h - (v / maxVal) * (h - topPad);

  ctx.strokeStyle = "#262b38";
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(0, h - 0.5);
  ctx.lineTo(w, h - 0.5);
  ctx.stroke();

  ctx.beginPath();
  series.forEach((v, i) => {
    const x = i * stepX;
    const y = pointY(v);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.lineTo(w, h);
  ctx.lineTo(0, h);
  ctx.closePath();
  ctx.fillStyle = "rgba(79, 140, 255, 0.1)";
  ctx.fill();

  ctx.beginPath();
  series.forEach((v, i) => {
    const x = i * stepX;
    const y = pointY(v);
    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = "#4f8cff";
  ctx.lineWidth = 2;
  ctx.lineJoin = "round";
  ctx.lineCap = "round";
  ctx.stroke();

  const currentMBps = (currentSecondBytes / 1024 / 1024).toFixed(2);
  const label = document.getElementById("traffic-current");
  if (label) label.textContent = `${currentMBps} MB/s`;
}

// --- IP / CIDR blocks (unified permanent + temporary) ---

async function loadIpBlocks() {
  const blocks = await apiGet("/api/ip-blocks");
  renderIpBlocks(blocks);
}

function renderIpBlocks(blocks) {
  blacklistEntriesCache.ips = blocks;
  const tbody = document.getElementById("ip-blocks-body");
  tbody.innerHTML = "";
  for (const block of blocks.slice(0, blacklistPageSizes.ips)) {
    const tr = document.createElement("tr");
    tr.dataset.value = block.text.toLowerCase();
    const expires = block.permanent ? "permanent" : new Date(block.expires_at).toLocaleString();
    tr.innerHTML = `
      <td>${escapeHtml(block.text)}</td>
      <td></td>
      <td>${escapeHtml(formatAddedAt(block.created_at))}</td>
      <td>${escapeHtml(expires)}</td>
      <td></td>
    `;
    tr.children[1].appendChild(buildSourcePill(block.source));
    tr.lastElementChild.appendChild(buildRemoveButton("Remove", () => onRemoveIpBlock(block.text)));
    tbody.appendChild(tr);
  }
  updateListCount("ips", blocks.length);
  applyIpBlockFilter();
}

async function onRemoveIpBlock(text) {
  try {
    await apiSend("DELETE", "/api/blacklist/ips", { value: text });
    await loadIpBlocks();
    showToast(`Removed ${text}`, "ok");
  } catch (err) {
    if (err.message !== "unauthorized") showToast(err.message, "error");
  }
}

function wireIpAddForm() {
  document.getElementById("ip-add-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const valueInput = document.getElementById("ip-add-value");
    const hoursInput = document.getElementById("ip-add-hours");
    const value = valueInput.value.trim();
    const hours = hoursInput.value.trim();
    if (!value) return;
    const body = { value };
    if (hours) body.duration_hours = Number(hours);
    try {
      await apiSend("POST", "/api/blacklist/ips", body);
      await loadIpBlocks();
      valueInput.value = "";
      hoursInput.value = "";
      showToast(hours ? `Blocked ${value} for ${hours}h` : `Blocked ${value} permanently`, "ok");
    } catch (err) {
      if (err.message !== "unauthorized") showToast(err.message, "error");
    }
  });
}

// --- sites (multi-domain) ---

async function loadSites() {
  const data = await apiGet("/api/sites");

  const summary = document.getElementById("sites-default-summary");
  summary.textContent =
    `Default site (unmatched Host/SNI falls back here): ${data.default_site.upstream_host}:${data.default_site.upstream_port}`;

  const tbody = document.getElementById("sites-body");
  tbody.innerHTML = "";
  for (const site of data.sites) {
    const tr = document.createElement("tr");
    const certLabel = site.cert_file ? escapeHtml(site.cert_file) : "(none)";
    tr.innerHTML = `
      <td>${escapeHtml(site.domain)}</td>
      <td>${escapeHtml(site.upstream_host)}:${site.upstream_port}</td>
      <td>${certLabel}</td>
      <td></td>
      <td></td>
    `;

    const enabledCell = tr.children[3];
    const toggle = document.createElement("input");
    toggle.type = "checkbox";
    toggle.checked = site.enabled;
    toggle.addEventListener("change", () => onToggleSite(site.domain, toggle));
    enabledCell.appendChild(toggle);

    const actionCell = tr.lastElementChild;
    const removeBtn = document.createElement("button");
    removeBtn.type = "button";
    removeBtn.className = "row-block-btn";
    removeBtn.textContent = "remove";
    removeBtn.addEventListener("click", () => onRemoveSite(site.domain));
    actionCell.appendChild(removeBtn);

    tbody.appendChild(tr);
  }
}

async function onToggleSite(domain, toggle) {
  try {
    await apiSend("PUT", `/api/sites/${encodeURIComponent(domain)}`, { enabled: toggle.checked });
    showToast(`${toggle.checked ? "Enabled" : "Disabled"} ${domain}`, "ok");
  } catch (err) {
    toggle.checked = !toggle.checked; // revert on failure
    if (err.message !== "unauthorized") showToast(err.message, "error");
  }
}

async function onRemoveSite(domain) {
  try {
    await apiSend("DELETE", `/api/sites/${encodeURIComponent(domain)}`, {});
    await loadSites();
    showToast(`Removed ${domain}`, "ok");
  } catch (err) {
    if (err.message !== "unauthorized") showToast(err.message, "error");
  }
}

function wireSiteAddForm() {
  document.getElementById("site-add-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const domainInput = document.getElementById("site-add-domain");
    const hostInput = document.getElementById("site-add-upstream-host");
    const portInput = document.getElementById("site-add-upstream-port");
    const certInput = document.getElementById("site-add-cert-file");
    const keyInput = document.getElementById("site-add-key-file");

    const domain = domainInput.value.trim();
    const upstream_host = hostInput.value.trim();
    const upstream_port = Number(portInput.value);
    if (!domain || !upstream_host || !upstream_port) return;

    try {
      await apiSend("POST", "/api/sites", {
        domain,
        upstream_host,
        upstream_port,
        cert_file: certInput.value.trim(),
        key_file: keyInput.value.trim(),
      });
      await loadSites();
      domainInput.value = "";
      portInput.value = "";
      certInput.value = "";
      keyInput.value = "";
      showToast(`Added ${domain}`, "ok");
    } catch (err) {
      if (err.message !== "unauthorized") showToast(err.message, "error");
    }
  });
}

// --- ban & scoring ---

async function loadBanConfig() {
  const ban = await apiGet("/api/ban-config");
  document.getElementById("ban-enabled").checked = ban.enabled;
  document.getElementById("ban-threshold").value = ban.threshold;
  document.getElementById("ban-duration").value = ban.ban_duration_hours;

  const grid = document.getElementById("ban-scores-grid");
  grid.innerHTML = "";
  for (const [check, points] of Object.entries(ban.scores)) {
    const div = document.createElement("div");
    div.className = "settings-field";
    div.innerHTML = `<label>${escapeHtml(check)}</label><input type="number" min="0" data-check="${escapeHtml(check)}" value="${points}">`;
    grid.appendChild(div);
  }
}

function wireBanSave() {
  document.getElementById("ban-save-btn").addEventListener("click", async () => {
    const scores = {};
    document.querySelectorAll("#ban-scores-grid input").forEach((input) => {
      scores[input.dataset.check] = Number(input.value);
    });
    const body = {
      enabled: document.getElementById("ban-enabled").checked,
      threshold: Number(document.getElementById("ban-threshold").value),
      ban_duration_hours: Number(document.getElementById("ban-duration").value),
      scores,
    };
    try {
      await apiSend("PUT", "/api/ban-config", body);
      showToast("Ban settings saved", "ok");
    } catch (err) {
      if (err.message !== "unauthorized") showToast(err.message, "error");
    }
  });
}

// --- speed check ---

async function loadSpeedCheck() {
  const speed = await apiGet("/api/speed-check");
  document.getElementById("speed-enabled").checked = speed.enabled;
  document.getElementById("speed-max-requests").value = speed.max_requests;
  document.getElementById("speed-window-seconds").value = speed.window_seconds;
}

function wireSpeedSave() {
  document.getElementById("speed-save-btn").addEventListener("click", async () => {
    const body = {
      enabled: document.getElementById("speed-enabled").checked,
      max_requests: Number(document.getElementById("speed-max-requests").value),
      window_seconds: Number(document.getElementById("speed-window-seconds").value),
    };
    try {
      await apiSend("PUT", "/api/speed-check", body);
      showToast("Speed check settings saved", "ok");
    } catch (err) {
      if (err.message !== "unauthorized") showToast(err.message, "error");
    }
  });
}

// --- request log CSV persistence ---

async function loadRequestLogConfig() {
  const config = await apiGet("/api/request-log-config");
  document.getElementById("request-log-persist-enabled").checked = config.enabled;
  document.getElementById("request-log-csv-path").value = config.csv_path;
}

function wireRequestLogSave() {
  document.getElementById("request-log-save-btn").addEventListener("click", async () => {
    const body = {
      enabled: document.getElementById("request-log-persist-enabled").checked,
      csv_path: document.getElementById("request-log-csv-path").value,
    };
    try {
      await apiSend("PUT", "/api/request-log-config", body);
      showToast("Request log persistence settings saved (restart to apply)", "ok");
    } catch (err) {
      if (err.message !== "unauthorized") showToast(err.message, "error");
    }
  });
}

// --- limits (body size) ---

async function loadLimits() {
  const config = await apiGet("/api/config");
  document.getElementById("body-size-limit").value =
    (config.blacklist.max_body_size_bytes / 1024 / 1024).toFixed(2);
}

function wireLimitsSave() {
  document.getElementById("limits-save-btn").addEventListener("click", async () => {
    const mb = Number(document.getElementById("body-size-limit").value);
    try {
      await apiSend("PUT", "/api/body-size-limit", { max_bytes: Math.round(mb * 1024 * 1024) });
      showToast("Body size limit saved", "ok");
    } catch (err) {
      if (err.message !== "unauthorized") showToast(err.message, "error");
    }
  });
}

// --- response pages ---

async function loadPages() {
  const pages = await apiGet("/api/pages");
  document.getElementById("blocked-html").value = pages.blocked_html;
  document.getElementById("banned-html").value = pages.banned_html;
  renderStatusPages(pages.status_pages || []);
}

function wirePagesSave() {
  document.getElementById("pages-save-btn").addEventListener("click", async () => {
    const body = {
      blocked_html: document.getElementById("blocked-html").value,
      banned_html: document.getElementById("banned-html").value,
    };
    try {
      await apiSend("PUT", "/api/pages", body);
      showToast("Response pages saved", "ok");
    } catch (err) {
      if (err.message !== "unauthorized") showToast(err.message, "error");
    }
  });
}

// --- status code page overrides ---
// Listed/added/edited/deleted the same way as a blacklist category, but each
// entry carries a status code + full HTML rather than a single string value
// (see config/status_page_ops.hpp) — so it gets its own small table + a
// dedicated add/edit <dialog> (status-page-dialog) instead of reusing the
// generic add-form used by the string-list blacklist panels.

function renderStatusPages(entries) {
  const tbody = document.getElementById("list-status_pages");
  tbody.innerHTML = "";
  for (const entry of entries) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${entry.code}</td>
      <td>${escapeHtml(formatAddedAt(entry.created_at))}</td>
      <td></td>
    `;
    const actionCell = tr.lastElementChild;

    const editBtn = document.createElement("button");
    editBtn.type = "button";
    editBtn.className = "row-block-btn";
    editBtn.textContent = "edit";
    editBtn.addEventListener("click", () => openStatusPageDialog("edit", entry));
    actionCell.appendChild(editBtn);

    actionCell.appendChild(
      buildRemoveButton("Remove", () => onRemoveStatusPage(entry.code))
    );

    tbody.appendChild(tr);
  }
  const el = document.getElementById("count-status_pages");
  if (el) el.textContent = `${entries.length} entr${entries.length === 1 ? "y" : "ies"}`;
}

// mode: "add" (code editable, starts blank) or "edit" (code fixed to `entry`,
// pre-filled) — editing a code means deleting and re-adding, since the server
// side keys entries by code (see update_status_page in status_page_ops.hpp).
function openStatusPageDialog(mode, entry) {
  const dialog = document.getElementById("status-page-dialog");
  const codeInput = document.getElementById("status-page-code");
  const htmlInput = document.getElementById("status-page-html");
  document.getElementById("status-page-dialog-title").textContent =
    mode === "edit" ? `Edit status ${entry.code} page` : "Add status page";
  codeInput.value = mode === "edit" ? entry.code : "";
  codeInput.disabled = mode === "edit";
  htmlInput.value = mode === "edit" ? entry.html : "";
  dialog.dataset.mode = mode;
  dialog.dataset.code = mode === "edit" ? entry.code : "";
  dialog.showModal();
  htmlInput.focus();
}

function wireStatusPageDialog() {
  document.getElementById("status-page-add-btn").addEventListener("click", () => {
    openStatusPageDialog("add");
  });

  const dialog = document.getElementById("status-page-dialog");
  document.getElementById("status-page-dialog-cancel").addEventListener("click", () => dialog.close());

  document.getElementById("status-page-dialog-save").addEventListener("click", async () => {
    const codeInput = document.getElementById("status-page-code");
    const html = document.getElementById("status-page-html").value;
    const mode = dialog.dataset.mode;
    try {
      let pages;
      if (mode === "edit") {
        pages = await apiSend("PUT", `/api/pages/status/${encodeURIComponent(dialog.dataset.code)}`, { html });
      } else {
        const code = Number(codeInput.value);
        if (!code) {
          showToast("Enter a status code", "error");
          return;
        }
        pages = await apiSend("POST", "/api/pages/status", { code, html });
      }
      renderStatusPages(pages.status_pages || []);
      dialog.close();
      showToast(mode === "edit" ? "Status page updated" : "Status page added", "ok");
    } catch (err) {
      if (err.message !== "unauthorized") showToast(err.message, "error");
    }
  });
}

async function onRemoveStatusPage(code) {
  const ok = await confirmAction(`Remove the custom page for status ${code}?`, "Remove");
  if (!ok) return;
  try {
    const pages = await apiSend("DELETE", `/api/pages/status/${encodeURIComponent(code)}`, {});
    renderStatusPages(pages.status_pages || []);
    showToast(`Removed status ${code} page`, "ok");
  } catch (err) {
    if (err.message !== "unauthorized") showToast(err.message, "error");
  }
}

// --- live globe ---

let globeInstance = null;

function updateGlobeEmbedSnippet(globeConfig) {
  const snippetEl = document.getElementById("globe-embed-snippet");
  if (!globeConfig.public_enabled) {
    snippetEl.value = "Enable the public embed listener below, save, then restart atomwall to get an embed snippet.";
    return;
  }
  const scheme = globeConfig.public_tls_cert_file && globeConfig.public_tls_key_file ? "https" : "http";
  const host = window.location.hostname;
  snippetEl.value =
    `<script src="${scheme}://${host}:${globeConfig.public_port}/globe.js" async data-atomwall-globe></scr` +
    `ipt>`;
}

function mmdbStatusText(path, loaded, emptyMessage) {
  if (!path) return emptyMessage;
  return loaded ? `loaded (${path})` : `configured but not loaded — check ${path} exists`;
}

async function loadGlobeConfig() {
  const [geoip, globe] = await Promise.all([apiGet("/api/geoip-config"), apiGet("/api/globe-config")]);

  document.getElementById("globe-geoip-status").textContent = mmdbStatusText(
    geoip.mmdb_path, geoip.loaded, "not configured — Country column and globe arcs will stay empty"
  );
  document.getElementById("geoip-mmdb-path").value = geoip.mmdb_path;
  document.getElementById("globe-asn-status").textContent = mmdbStatusText(
    geoip.asn_mmdb_path, geoip.asn_loaded, "not configured — ISP column will stay \"unknown\""
  );
  document.getElementById("asn-mmdb-path").value = geoip.asn_mmdb_path;

  document.getElementById("globe-server-lat").value = globe.server_lat ?? "";
  document.getElementById("globe-server-lon").value = globe.server_lon ?? "";
  document.getElementById("globe-public-enabled").checked = globe.public_enabled;
  document.getElementById("globe-public-bind").value = globe.public_bind;
  document.getElementById("globe-public-port").value = globe.public_port;
  document.getElementById("globe-public-tls-cert").value = globe.public_tls_cert_file;
  document.getElementById("globe-public-tls-key").value = globe.public_tls_key_file;
  document.getElementById("globe-public-fields").hidden = !globe.public_enabled;
  updateGlobeEmbedSnippet(globe);
}

async function loadGlobeServerLocation() {
  const snapshot = await apiGet("/api/globe/snapshot?limit=1");
  const el = document.getElementById("globe-server-location");
  if (snapshot.server_location) {
    el.textContent = `${snapshot.server_location.lat.toFixed(3)}, ${snapshot.server_location.lon.toFixed(3)}`;
  } else {
    el.textContent = "not yet resolved (set manually above, or wait for startup auto-detect)";
  }
  if (globeInstance) globeInstance.setServerLocation(snapshot.server_location);
}

function wireGeoipSave() {
  document.getElementById("geoip-save-btn").addEventListener("click", async () => {
    const mmdb_path = document.getElementById("geoip-mmdb-path").value.trim();
    const asn_mmdb_path = document.getElementById("asn-mmdb-path").value.trim();
    try {
      const geoip = await apiSend("PUT", "/api/geoip-config", { mmdb_path, asn_mmdb_path });
      document.getElementById("globe-geoip-status").textContent = mmdbStatusText(
        geoip.mmdb_path, geoip.loaded, "not configured — Country column and globe arcs will stay empty"
      );
      document.getElementById("globe-asn-status").textContent = mmdbStatusText(
        geoip.asn_mmdb_path, geoip.asn_loaded, "not configured — ISP column will stay \"unknown\""
      );
      showToast("GeoIP paths saved (restart atomwall to load any changes)", "ok");
    } catch (err) {
      if (err.message !== "unauthorized") showToast(err.message, "error");
    }
  });
}

function uploadMmdb(inputId, statusId, pathId, endpoint, label) {
  document.getElementById(inputId).addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const statusEl = document.getElementById(statusId);
    statusEl.textContent = `Uploading ${file.name} (${(file.size / 1024 / 1024).toFixed(1)} MB)…`;
    try {
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/octet-stream" },
        body: file,
      });
      if (res.status === 401) {
        window.location.href = "/login.html";
        return;
      }
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(data.error || `upload failed -> ${res.status}`);
      }
      document.getElementById(pathId).value = data.mmdb_path;
      statusEl.textContent = `Uploaded ${(data.bytes / 1024 / 1024).toFixed(1)} MB to ${data.mmdb_path} — restart atomwall to load it`;
      showToast(`${label} uploaded (restart atomwall to load it)`, "ok");
    } catch (err) {
      statusEl.textContent = "";
      showToast(err.message, "error");
    } finally {
      e.target.value = "";
    }
  });
}

function wireGeoipUpload() {
  uploadMmdb("geoip-upload-input", "geoip-upload-status", "geoip-mmdb-path", "/api/geoip-upload",
             "GeoIP database");
}

function wireAsnUpload() {
  uploadMmdb("asn-upload-input", "geoip-upload-status", "asn-mmdb-path", "/api/asn-upload",
             "ASN database");
}

function wireGlobeSave() {
  document.getElementById("globe-public-enabled").addEventListener("change", (e) => {
    document.getElementById("globe-public-fields").hidden = !e.target.checked;
  });
  document.getElementById("globe-save-btn").addEventListener("click", async () => {
    const lat = document.getElementById("globe-server-lat").value;
    const lon = document.getElementById("globe-server-lon").value;
    const body = {
      server_lat: lat === "" ? null : Number(lat),
      server_lon: lon === "" ? null : Number(lon),
      public_enabled: document.getElementById("globe-public-enabled").checked,
      public_bind: document.getElementById("globe-public-bind").value,
      public_port: Number(document.getElementById("globe-public-port").value),
      public_tls_cert_file: document.getElementById("globe-public-tls-cert").value,
      public_tls_key_file: document.getElementById("globe-public-tls-key").value,
    };
    try {
      const globe = await apiSend("PUT", "/api/globe-config", body);
      updateGlobeEmbedSnippet(globe);
      showToast("Globe settings saved (public listener changes need a restart)", "ok");
    } catch (err) {
      if (err.message !== "unauthorized") showToast(err.message, "error");
    }
  });
}

function mountGlobe() {
  const container = document.getElementById("globe-canvas-wrap");
  if (!container || !window.AtomwallGlobe) return;
  globeInstance = window.AtomwallGlobe.mount(container, {
    snapshotUrl: "/api/globe/snapshot",
    streamUrl: "/api/globe/stream",
  });
}

// --- users ---

async function loadUsers() {
  const users = await apiGet("/api/users");
  const table = document.getElementById("users-table");
  table.innerHTML = "";
  for (const user of users) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${escapeHtml(user.username)}</td><td>${escapeHtml(new Date(user.created_at).toLocaleString())}</td><td></td>`;
    const cell = tr.lastElementChild;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "row-block-btn";
    btn.textContent = "delete";
    btn.addEventListener("click", () => onDeleteUser(user.username));
    cell.appendChild(btn);
    table.appendChild(tr);
  }
}

async function onDeleteUser(username) {
  try {
    await apiSend("DELETE", `/api/users/${encodeURIComponent(username)}`, {});
    await loadUsers();
    showToast(`Deleted ${username}`, "ok");
  } catch (err) {
    if (err.message !== "unauthorized") showToast(err.message, "error");
  }
}

function wireUserAddForm() {
  document.getElementById("user-add-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const usernameInput = document.getElementById("user-add-username");
    const passwordInput = document.getElementById("user-add-password");
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    if (!username || !password) return;
    try {
      await apiSend("POST", "/api/users", { username, password });
      await loadUsers();
      usernameInput.value = "";
      passwordInput.value = "";
      showToast(`Added ${username}`, "ok");
    } catch (err) {
      if (err.message !== "unauthorized") showToast(err.message, "error");
    }
  });
}

// --- login history ---

async function loadLoginHistory() {
  const events = await apiGet("/api/login-history");
  const tbody = document.getElementById("login-history-body");
  tbody.innerHTML = "";
  // Server returns oldest first (same convention as requests/globe history);
  // newest-first reads better for "who logged in most recently".
  for (const event of events.slice().reverse()) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(event.username)}</td>
      <td>${escapeHtml(event.client_ip)}</td>
      <td>${escapeHtml(formatAddedAt(event.timestamp))}</td>
    `;
    tbody.appendChild(tr);
  }
}

// --- live visitors ---

async function refreshLiveVisitors() {
  try {
    const data = await apiGet("/api/live-visitors");
    document.getElementById("stat-live-visitors").textContent = data.count;
  } catch (err) {
    // transient — next poll will retry
  }
}

// --- logout ---

function wireLogout() {
  document.getElementById("logout-btn").addEventListener("click", async () => {
    await fetch("/api/auth/logout", { method: "POST" });
    window.location.href = "/login.html";
  });
}

// --- nav scroll-spy ---

function wireNavScrollSpy() {
  const links = document.querySelectorAll(".side-nav a[data-nav]");
  const linkByTargetId = new Map(
    Array.from(links).map((link) => [link.getAttribute("href").slice(1), link])
  );
  const sections = Array.from(linkByTargetId.keys())
    .map((id) => document.getElementById(id))
    .filter(Boolean);

  // Intersection-band matching (an element counts as "current" only while it overlaps a
  // narrow band of the viewport) breaks down for short sections and for the first/last
  // section — a section shorter than the band, or one that can never scroll into it (top
  // of page, or bottom of page when the doc can't scroll further), never gets picked, so
  // the previously-active link (often the neighboring section) is left highlighted.
  // Instead: the active section is the last one (in document order) whose top has
  // scrolled up past a fixed activation line just below the sticky topbar — the same
  // "closest section at or above this line" rule scrollspy implementations commonly use,
  // and it naturally degrades to the first section at the top of the page and the last
  // section once the page is scrolled to its bottom.
  function activationLine() {
    const topbar = document.querySelector(".topbar");
    return (topbar ? topbar.getBoundingClientRect().height : 0) + 24;
  }

  function updateActive() {
    const line = activationLine();
    const atBottom =
      window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 2;
    let current = sections[0];
    for (const section of sections) {
      if (section.getBoundingClientRect().top - line <= 0) current = section;
    }
    if (atBottom) current = sections[sections.length - 1];
    if (!current) return;
    const link = linkByTargetId.get(current.id);
    links.forEach((l) => l.classList.remove("active"));
    if (link) link.classList.add("active");
  }

  let ticking = false;
  function onScroll() {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(() => {
      updateActive();
      ticking = false;
    });
  }

  window.addEventListener("scroll", onScroll, { passive: true });
  window.addEventListener("resize", onScroll);
  updateActive();
}

// --- init ---

async function main() {
  const status = await fetch("/api/auth/status").then((r) => r.json());
  if (!status.authenticated) {
    window.location.href = "/login.html";
    return;
  }

  wireForms();
  wireImportForms();
  wireImportUrlForms();
  wireFilterInputs();
  wireClearAllButtons();
  wireNavScrollSpy();
  wireIpAddForm();
  wireSiteAddForm();
  wireBanSave();
  wireSpeedSave();
  wireLimitsSave();
  wirePagesSave();
  wireStatusPageDialog();
  wireGlobeSave();
  wireGeoipSave();
  wireGeoipUpload();
  wireAsnUpload();
  wireUserAddForm();
  wireLogout();
  wireRequestsPageSize();
  wireBlacklistPageSizes();
  wireRequestsFilters();
  wireRequestsSort();
  wireRequestsSelectAll();
  wireRequestsBulkActions();
  wireRequestsExport();
  wireRequestLogSave();

  refreshAll().catch((err) => {
    document.getElementById("status").textContent = "failed to load config";
    if (err.message !== "unauthorized") showToast(err.message, "error");
  });
  loadRequestHistory().catch((err) => {
    if (err.message !== "unauthorized") showToast(err.message, "error");
  });
  loadRequestLogConfig().catch((err) => {
    if (err.message !== "unauthorized") showToast(err.message, "error");
  });
  loadIpBlocks().catch((err) => {
    if (err.message !== "unauthorized") showToast(err.message, "error");
  });
  loadSites().catch((err) => {
    if (err.message !== "unauthorized") showToast(err.message, "error");
  });
  loadBanConfig().catch((err) => {
    if (err.message !== "unauthorized") showToast(err.message, "error");
  });
  loadSpeedCheck().catch((err) => {
    if (err.message !== "unauthorized") showToast(err.message, "error");
  });
  loadLimits().catch((err) => {
    if (err.message !== "unauthorized") showToast(err.message, "error");
  });
  loadPages().catch((err) => {
    if (err.message !== "unauthorized") showToast(err.message, "error");
  });
  loadUsers().catch((err) => {
    if (err.message !== "unauthorized") showToast(err.message, "error");
  });
  loadLoginHistory().catch((err) => {
    if (err.message !== "unauthorized") showToast(err.message, "error");
  });
  loadGlobeConfig().catch((err) => {
    if (err.message !== "unauthorized") showToast(err.message, "error");
  });
  loadGlobeServerLocation().catch(() => {});
  setTimeout(() => loadGlobeServerLocation().catch(() => {}), 4000);
  mountGlobe();

  connectLiveRequests();
  refreshLiveVisitors();
  setInterval(refreshLiveVisitors, 10000);
  setInterval(drawTrafficGraph, 1000);
  drawTrafficGraph();
}

main();
