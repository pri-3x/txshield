/*
 * TxShield content script (isolated world). Receives check requests from the
 * in-page interceptor, asks the background worker to analyze them, and shows
 * the warning. All text is set with textContent; nothing from the report or
 * the page is ever parsed as HTML.
 */
(function () {
  "use strict";
  const lib = globalThis.TxShieldLib;
  if (!lib || globalThis.__txshieldContent) return;
  globalThis.__txshieldContent = true;

  function reply(id, type, extra) {
    window.postMessage(Object.assign({ source: "txshield-content", id, type }, extra || {}), window.location.origin);
  }

  window.addEventListener("message", async (ev) => {
    const d = ev.data;
    if (ev.source !== window || !d || d.source !== "txshield-inpage" || d.type !== "check" || typeof d.id !== "string") return;
    reply(d.id, "ack");
    const decision = await handle(d.tx, d.chainId);
    reply(d.id, "decision", { decision });
  });

  async function handle(tx, chainId) {
    const built = lib.toApiRequest(tx, chainId);
    if (!built.ok) return ask(errorView(`TxShield could not read this transaction (${built.error}).`), {});
    showChecking();
    let res;
    try {
      res = await chrome.runtime.sendMessage({ type: "txshield:analyze", request: built.request });
    } catch {
      res = { ok: false, error: "The TxShield extension is not responding. Reload the page and try again." };
    }
    hideChecking();
    if (!res || !res.ok) return ask(errorView(res && res.error ? res.error : "TxShield could not check this transaction."), res && res.settings ? res.settings : {});
    const settings = res.settings || {};
    const report = res.report;
    if (lib.decide(report, settings.threshold) === "allow") {
      toast(`TxShield: score ${report.risk.score}/100. No significant risks detected by enabled checks. Review the details in your wallet.`);
      return "continue";
    }
    return ask(lib.viewModel(report, settings), settings);
  }

  function errorView(message) {
    return { error: message };
  }

  // --- DOM ---------------------------------------------------------------

  const CSS = `
  :host { all: initial; }
  * { box-sizing: border-box; }
  .backdrop { position: fixed; inset: 0; background: rgba(5,7,10,.72); display: flex; align-items: center; justify-content: center; padding: 16px; z-index: 2147483647; font: 14px/1.5 Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: #E6EAF0; }
  .card { width: 100%; max-width: 460px; max-height: calc(100vh - 32px); overflow: auto; background: #12161D; border: 1px solid #262E3A; border-radius: 16px; box-shadow: 0 24px 64px rgba(0,0,0,.5); }
  .band { display: flex; align-items: center; gap: 10px; padding: 10px 18px; font-size: 12px; font-weight: 700; letter-spacing: .06em; text-transform: uppercase; }
  .band.critical { background: #3A1418; color: #FF8A80; }
  .band.high, .band.elevated { background: #3A1F12; color: #FFA77A; }
  .band.moderate { background: #3A2A0C; color: #FFC266; }
  .band.low, .band.error { background: #1E2633; color: #B4BECC; }
  .score { margin-left: auto; font-variant-numeric: tabular-nums; }
  .body { padding: 16px 18px 18px; display: flex; flex-direction: column; gap: 14px; }
  h2 { margin: 0; font-size: 18px; line-height: 1.35; font-weight: 700; color: #E6EAF0; }
  h3 { margin: 0 0 6px; font-size: 11px; font-weight: 700; letter-spacing: .06em; text-transform: uppercase; color: #9AA4B2; }
  ul { margin: 0; padding: 0; list-style: none; display: flex; flex-direction: column; gap: 6px; }
  .asset { display: flex; justify-content: space-between; gap: 10px; padding: 8px 10px; border-radius: 10px; background: #181E27; border: 1px solid #262E3A; }
  .asset.out .amt { color: #FF8A80; }
  .asset.in .amt { color: #6EE7A0; }
  .amt { font-weight: 600; font-variant-numeric: tabular-nums; }
  .tag { font-size: 11px; color: #9AA4B2; white-space: nowrap; }
  .muted { color: #9AA4B2; font-size: 12px; }
  .mono { font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
  .reason { display: flex; gap: 8px; align-items: baseline; }
  .sev { flex: none; font-size: 10px; font-weight: 700; letter-spacing: .05em; text-transform: uppercase; padding: 1px 6px; border-radius: 5px; background: #1E2633; color: #B4BECC; }
  .sev.critical { background: #3A1418; color: #FF8A80; } .sev.high { background: #3A1F12; color: #FFA77A; } .sev.medium { background: #3A2A0C; color: #FFC266; }
  .nothing { padding: 8px 10px; border-radius: 10px; border: 1px dashed #3A4352; color: #C1C9D4; }
  label.ack { display: flex; gap: 8px; align-items: flex-start; font-size: 13px; color: #C1C9D4; cursor: pointer; }
  input[type=checkbox] { width: 16px; height: 16px; margin-top: 2px; accent-color: #E5484D; }
  .actions { display: flex; gap: 8px; flex-wrap: wrap; }
  button { font: 600 14px Inter, ui-sans-serif, system-ui, sans-serif; height: 44px; padding: 0 16px; border-radius: 10px; cursor: pointer; flex: 1 1 160px; }
  button.reject { background: #E6EAF0; color: #0B0E13; border: 0; }
  button.reject:hover { background: #FFFFFF; }
  button.continue { background: transparent; color: #C1C9D4; border: 1px solid #3A4352; }
  button.continue:disabled { opacity: .45; cursor: not-allowed; }
  button:focus-visible, a:focus-visible, input:focus-visible { outline: 2px solid #8FC0FF; outline-offset: 2px; }
  a { color: #8FC0FF; }
  .brand { display: flex; align-items: center; gap: 6px; }
  .toast { position: fixed; right: 16px; bottom: 16px; max-width: 360px; background: #12161D; color: #E6EAF0; border: 1px solid #262E3A; border-radius: 12px; padding: 12px 14px; font: 13px/1.45 Inter, ui-sans-serif, system-ui, sans-serif; box-shadow: 0 12px 32px rgba(0,0,0,.45); z-index: 2147483647; }
  `;

  let sheet = null;
  function mount() {
    const host = document.createElement("txshield-root");
    const shadow = host.attachShadow({ mode: "closed" });
    if (!sheet) {
      sheet = new CSSStyleSheet();
      sheet.replaceSync(CSS);
    }
    shadow.adoptedStyleSheets = [sheet];
    (document.body || document.documentElement).appendChild(host);
    return { host, shadow };
  }

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function shield() {
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("width", "16");
    svg.setAttribute("height", "16");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    const p = document.createElementNS(ns, "path");
    p.setAttribute("d", "M12 2.5 4 5.5v6c0 4.7 3.3 8.6 8 10 4.7-1.4 8-5.3 8-10v-6l-8-3Z");
    p.setAttribute("fill", "none");
    p.setAttribute("stroke", "currentColor");
    p.setAttribute("stroke-width", "2");
    svg.appendChild(p);
    return svg;
  }

  let checking = null;
  function showChecking() {
    checking = mount();
    const t = el("div", "toast");
    t.setAttribute("role", "status");
    t.textContent = "TxShield is checking this transaction…";
    checking.shadow.appendChild(t);
  }
  function hideChecking() {
    if (checking) checking.host.remove();
    checking = null;
  }

  function toast(text) {
    const m = mount();
    const t = el("div", "toast");
    t.setAttribute("role", "status");
    t.textContent = text;
    m.shadow.appendChild(t);
    setTimeout(() => m.host.remove(), 6000);
  }

  function assetRow(a, dir) {
    const li = el("li", `asset ${dir}`);
    li.appendChild(el("span", "amt", `${dir === "out" ? "−" : "+"}${a.label}${a.unverified ? "*" : ""}`));
    if (a.entireBalance) li.appendChild(el("span", "tag", "entire balance"));
    else if (a.address) li.appendChild(el("span", "tag mono", lib.shortHex(a.address)));
    return li;
  }

  /** Shows the warning; resolves "continue" or "reject". */
  function ask(vm, settings) {
    return new Promise((resolve) => {
      const { host, shadow } = mount();
      const previousFocus = document.activeElement;
      const backdrop = el("div", "backdrop");
      const card = el("div", "card");
      card.setAttribute("role", "alertdialog");
      card.setAttribute("aria-modal", "true");
      card.setAttribute("aria-labelledby", "txs-title");
      card.setAttribute("aria-describedby", "txs-desc");
      backdrop.appendChild(card);
      shadow.appendChild(backdrop);

      const tone = vm.error ? "error" : vm.category;
      const band = el("div", `band ${tone}`);
      const brand = el("span", "brand");
      brand.appendChild(shield());
      brand.appendChild(el("span", "", vm.error ? "TxShield · check failed" : `TxShield · ${vm.categoryLabel}`));
      band.appendChild(brand);
      if (!vm.error) band.appendChild(el("span", "score", `${vm.score}/100`));
      card.appendChild(band);

      const body = el("div", "body");
      card.appendChild(body);
      const title = el("h2", "", vm.error ? "This transaction could not be checked" : vm.headline);
      title.id = "txs-title";
      body.appendChild(title);
      const desc = el("p", "muted", vm.error ? vm.error : `${vm.chainName} · contract ${vm.target || "creation"}`);
      desc.id = "txs-desc";
      desc.style.margin = "0";
      body.appendChild(desc);

      if (!vm.error) {
        if (vm.simulated) {
          if (vm.sends.length) {
            const sec = el("section");
            sec.appendChild(el("h3", "", "You send"));
            const ul = el("ul");
            vm.sends.slice(0, 6).forEach((a) => ul.appendChild(assetRow(a, "out")));
            sec.appendChild(ul);
            body.appendChild(sec);
          }
          if (vm.receives.length) {
            const sec = el("section");
            sec.appendChild(el("h3", "", "You receive"));
            const ul = el("ul");
            vm.receives.slice(0, 6).forEach((a) => ul.appendChild(assetRow(a, "in")));
            sec.appendChild(ul);
            body.appendChild(sec);
          } else if (vm.receivesNothing) {
            body.appendChild(el("div", "nothing", "You receive nothing."));
          }
          if (vm.recipients.length) body.appendChild(el("p", "muted", `Assets go to ${vm.recipients.join(", ")}.`));
        } else {
          body.appendChild(el("p", "muted", vm.notSimulatedReason));
        }
        if (vm.permissions.length) {
          const sec = el("section");
          sec.appendChild(el("h3", "", "You allow"));
          const ul = el("ul");
          vm.permissions.forEach((p) => {
            const li = el("li", "asset out");
            li.appendChild(el("span", "amt", `${p.spender} to spend ${p.what}`));
            if (p.signed) li.appendChild(el("span", "tag", "signature"));
            ul.appendChild(li);
          });
          sec.appendChild(ul);
          body.appendChild(sec);
        }
        if (vm.reasons.length) {
          const sec = el("section");
          sec.appendChild(el("h3", "", "Why"));
          const ul = el("ul");
          vm.reasons.forEach((r) => {
            const li = el("li", "reason");
            li.appendChild(el("span", `sev ${r.severity}`, r.severity));
            li.appendChild(el("span", "", r.count > 1 ? `${r.title} (×${r.count})` : r.title));
            ul.appendChild(li);
          });
          sec.appendChild(ul);
          body.appendChild(sec);
        }
        if (vm.recommendation) body.appendChild(el("p", "", vm.recommendation));
      }

      const severe = !vm.error && (vm.category === "critical" || vm.category === "high");
      const reject = el("button", "reject", "Reject");
      reject.type = "button";
      const cont = el("button", "continue", vm.error ? "Continue without check" : "Continue to wallet");
      cont.type = "button";
      if (severe) {
        const label = el("label", "ack");
        const box = document.createElement("input");
        box.type = "checkbox";
        label.appendChild(box);
        label.appendChild(el("span", "", "I understand the risk and still want to open my wallet."));
        body.appendChild(label);
        cont.disabled = true;
        box.addEventListener("change", () => (cont.disabled = !box.checked));
      }
      const actions = el("div", "actions");
      actions.appendChild(reject);
      actions.appendChild(cont);
      body.appendChild(actions);

      const foot = el("p", "muted");
      foot.style.margin = "0";
      if (vm.anyUnverified) foot.appendChild(document.createTextNode("* token name and decimals reported by the token contract, unverified. "));
      if (vm.reportUrl) {
        const a = el("a", "", "Full report");
        a.href = vm.reportUrl;
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        foot.appendChild(a);
        foot.appendChild(document.createTextNode(". "));
      }
      foot.appendChild(document.createTextNode(vm.disclaimer || "TxShield checks are heuristics and not exhaustive."));
      body.appendChild(foot);

      function done(decision) {
        document.removeEventListener("keydown", onKey, true);
        host.remove();
        if (previousFocus && typeof previousFocus.focus === "function") previousFocus.focus();
        resolve(decision);
      }
      function onKey(e) {
        if (e.key === "Escape") {
          e.stopPropagation();
          done("reject");
        }
      }
      document.addEventListener("keydown", onKey, true);
      reject.addEventListener("click", () => done("reject"));
      cont.addEventListener("click", () => done("continue"));
      reject.focus();
    });
  }
})();
