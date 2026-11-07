/*
 * TxShield background service worker: holds the settings and calls the
 * TxShield API. Pages never see the API URL or key; content scripts only
 * receive the analysis result.
 */
importScripts("lib.js");
const lib = globalThis.TxShieldLib;

async function loadSettings() {
  const sync = await chrome.storage.sync.get({ apiUrl: lib.DEFAULTS.apiUrl, dashboardUrl: lib.DEFAULTS.dashboardUrl, threshold: lib.DEFAULTS.threshold });
  // The API key stays on this device (not synced).
  const local = await chrome.storage.local.get({ apiKey: "" });
  return { ...lib.DEFAULTS, ...sync, ...local };
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Only our own content scripts (which run in tabs) may ask for analyses.
  if (!msg || msg.type !== "txshield:analyze" || sender.id !== chrome.runtime.id || !sender.tab) return false;
  (async () => {
    const settings = await loadSettings();
    const res = await lib.analyze(settings, msg.request);
    // Settings the content script needs; never the API key.
    sendResponse({ ...res, settings: { threshold: settings.threshold, dashboardUrl: settings.dashboardUrl } });
  })();
  return true; // async response
});

chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === "install") chrome.runtime.openOptionsPage();
});
