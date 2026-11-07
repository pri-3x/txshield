/* TxShield options page. */
(function () {
  "use strict";
  const lib = globalThis.TxShieldLib;
  const $ = (id) => document.getElementById(id);
  const status = (text, cls) => {
    $("status").textContent = text;
    $("status").className = `status ${cls || ""}`;
  };

  async function load() {
    const sync = await chrome.storage.sync.get({ apiUrl: lib.DEFAULTS.apiUrl, dashboardUrl: lib.DEFAULTS.dashboardUrl, threshold: lib.DEFAULTS.threshold });
    const local = await chrome.storage.local.get({ apiKey: "" });
    $("apiUrl").value = sync.apiUrl;
    $("dashboardUrl").value = sync.dashboardUrl;
    $("threshold").value = String(sync.threshold);
    $("apiKey").value = local.apiKey;
  }

  function read() {
    const apiUrl = lib.normalizeApiUrl($("apiUrl").value);
    const dashboardUrl = $("dashboardUrl").value.trim() ? lib.normalizeApiUrl($("dashboardUrl").value) : "";
    if (!apiUrl) return { error: "Enter the API URL as http:// or https://, without a username or password." };
    if (dashboardUrl === null) return { error: "Enter the dashboard URL as http:// or https://, or leave it empty." };
    return { apiUrl, dashboardUrl, threshold: Number($("threshold").value), apiKey: $("apiKey").value.trim() };
  }

  async function ensurePermission(url) {
    // The API host must be granted before the background worker can call it.
    const origin = new URL(url).origin + "/*";
    if (await chrome.permissions.contains({ origins: [origin] })) return true;
    return chrome.permissions.request({ origins: [origin] });
  }

  $("form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const v = read();
    if (v.error) return status(v.error, "err");
    if (!(await ensurePermission(v.apiUrl))) return status("Permission to contact the API was not granted; settings not saved.", "err");
    await chrome.storage.sync.set({ apiUrl: v.apiUrl, dashboardUrl: v.dashboardUrl, threshold: v.threshold });
    await chrome.storage.local.set({ apiKey: v.apiKey });
    status("Saved.", "ok");
  });

  $("test").addEventListener("click", async () => {
    const v = read();
    if (v.error) return status(v.error, "err");
    if (!(await ensurePermission(v.apiUrl))) return status("Permission to contact the API was not granted.", "err");
    status("Testing…");
    try {
      const headers = v.apiKey ? { Authorization: `Bearer ${v.apiKey}` } : {};
      const res = await fetch(`${v.apiUrl}/api/v1/info`, { headers, credentials: "omit" });
      if (!res.ok) return status(res.status === 401 ? "The API rejected the key (401)." : `The API answered HTTP ${res.status}.`, "err");
      const info = await res.json();
      const chains = (info.chains || []).map((c) => c.chainId).join(", ") || "none (offline analysis only)";
      status(`Connected. Engine ${info.version}, ${info.rules} rules, simulator ${info.simulator}, chains with RPC: ${chains}.`, "ok");
    } catch {
      status("Could not reach the API at that URL.", "err");
    }
  });

  load();
})();
