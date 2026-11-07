/* Stands in for the background worker: chrome.runtime.sendMessage -> lib.analyze. */
(function () {
  "use strict";
  const q = new URLSearchParams(location.search);
  const settings = Object.assign({}, TxShieldLib.DEFAULTS, {
    apiUrl: q.get("api") || TxShieldLib.DEFAULTS.apiUrl,
    dashboardUrl: q.get("dashboard") || TxShieldLib.DEFAULTS.dashboardUrl,
    threshold: q.get("threshold") ? Number(q.get("threshold")) : TxShieldLib.DEFAULTS.threshold,
  });
  window.chrome = window.chrome || {};
  window.chrome.runtime = {
    async sendMessage(msg) {
      const res = await TxShieldLib.analyze(settings, msg.request);
      return Object.assign({}, res, { settings: { threshold: settings.threshold, dashboardUrl: settings.dashboardUrl } });
    },
  };
  document.addEventListener("DOMContentLoaded", () => {
    const el = document.getElementById("api");
    if (el) el.textContent = settings.apiUrl;
  });
})();
