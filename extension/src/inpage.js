/*
 * TxShield in-page interceptor. Runs in the page's JavaScript world at
 * document_start. It wraps EIP-1193 wallet providers (window.ethereum and
 * EIP-6963 announced providers) so that eth_sendTransaction is checked by
 * TxShield before the wallet's confirmation opens.
 *
 * Limits (documented in extension/README.md): this is best-effort
 * protection for transactions requested through the normal provider API. A
 * page that deliberately evades the extension (by grabbing the provider
 * first or answering the messages below itself) is out of scope; wallet-level
 * integration is the robust option.
 */
(function () {
  "use strict";
  if (window.__txshieldInpage) return;
  Object.defineProperty(window, "__txshieldInpage", { value: true });

  const CHECKED = ["eth_sendTransaction"];
  const ACK_TIMEOUT_MS = 2000; // no answer from the content script: extension not active
  const wrapped = new WeakMap(); // original provider -> wrapper
  const wrappers = new WeakSet();

  function rpcError(code, message) {
    const e = new Error(message);
    e.code = code;
    return e;
  }

  function newId() {
    const a = new Uint8Array(16);
    crypto.getRandomValues(a);
    return Array.from(a, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  /** Asks the content script to check tx; resolves "continue" or "reject". */
  function check(tx, chainId) {
    return new Promise((resolve) => {
      const id = newId();
      let acked = false;
      const ackTimer = setTimeout(() => {
        if (!acked) {
          window.removeEventListener("message", onMessage);
          console.warn("[TxShield] extension did not respond; transaction was not checked");
          resolve("continue");
        }
      }, ACK_TIMEOUT_MS);
      function onMessage(ev) {
        const d = ev.data;
        if (ev.source !== window || !d || d.source !== "txshield-content" || d.id !== id) return;
        if (d.type === "ack") {
          acked = true;
          clearTimeout(ackTimer);
          return;
        }
        if (d.type === "decision") {
          clearTimeout(ackTimer);
          window.removeEventListener("message", onMessage);
          resolve(d.decision === "continue" ? "continue" : "reject");
        }
      }
      window.addEventListener("message", onMessage);
      window.postMessage({ source: "txshield-inpage", type: "check", id, tx, chainId }, window.location.origin);
    });
  }

  async function guard(provider, args) {
    const tx = args && Array.isArray(args.params) ? Object.assign({}, args.params[0]) : null;
    if (!tx) return;
    let chainId = tx.chainId;
    try {
      if (!chainId) chainId = await provider.request({ method: "eth_chainId" });
      if (!tx.from) {
        const accounts = await provider.request({ method: "eth_accounts" });
        if (Array.isArray(accounts) && accounts[0]) tx.from = accounts[0];
      }
    } catch {
      // Leave gaps; the content script reports what is missing.
    }
    const decision = await check(tx, chainId);
    if (decision !== "continue") throw rpcError(4001, "TxShield: transaction rejected after a security warning");
  }

  function wrap(provider) {
    if (!provider || typeof provider !== "object" || wrappers.has(provider)) return provider;
    if (wrapped.has(provider)) return wrapped.get(provider);
    if (typeof provider.request !== "function") return provider;

    const request = async function (args) {
      if (args && CHECKED.includes(args.method)) await guard(provider, args);
      return provider.request(args);
    };
    // Legacy callback API (web3.js 0.x style).
    const sendAsync = function (payload, cb) {
      if (payload && CHECKED.includes(payload.method)) {
        guard(provider, payload).then(
          () => provider.sendAsync(payload, cb),
          (err) => cb(err, { id: payload.id, jsonrpc: "2.0", error: { code: err.code, message: err.message } }),
        );
        return;
      }
      return provider.sendAsync(payload, cb);
    };

    const proxy = new Proxy(provider, {
      get(target, prop) {
        if (prop === "request") return request;
        if (prop === "sendAsync" && typeof target.sendAsync === "function") return sendAsync;
        if (prop === "__txshield") return true;
        const v = Reflect.get(target, prop, target);
        return typeof v === "function" ? v.bind(target) : v;
      },
    });
    wrapped.set(provider, proxy);
    wrappers.add(proxy);
    return proxy;
  }

  // window.ethereum: wrap whatever is (or later gets) assigned.
  try {
    let current = window.ethereum;
    Object.defineProperty(window, "ethereum", {
      configurable: true,
      enumerable: true,
      get() {
        return current ? wrap(current) : current;
      },
      set(v) {
        current = v;
      },
    });
  } catch {
    console.warn("[TxShield] could not hook window.ethereum");
  }

  // EIP-6963: re-announce providers wrapped. Our capture listener runs
  // before the page's listeners because this script runs first.
  window.addEventListener(
    "eip6963:announceProvider",
    (ev) => {
      const d = ev.detail;
      if (!d || !d.provider || wrappers.has(d.provider)) return;
      ev.stopImmediatePropagation();
      const detail = Object.freeze(Object.assign({}, d, { provider: wrap(d.provider) }));
      window.dispatchEvent(new CustomEvent("eip6963:announceProvider", { detail }));
    },
    true,
  );
})();
