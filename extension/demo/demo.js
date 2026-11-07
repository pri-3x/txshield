/* Demo dApp + mock wallet (local Anvil only). */
(function () {
  "use strict";
  const RPC = "http://127.0.0.1:8545";
  const ACCOUNT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"; // Anvil test account #1
  const DRAINER = "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9";
  const TUSD = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0";
  const FRIEND = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
  const log = (m) => {
    const el = document.getElementById("log");
    el.textContent = `${new Date().toLocaleTimeString()}  ${m}\n` + el.textContent;
  };

  if (!window.ethereum) {
    // Minimal EIP-1193 mock wallet. Assigned like a real wallet would, so the
    // TxShield interceptor wraps it the same way.
    let id = 0;
    window.ethereum = {
      isMockWallet: true,
      async request({ method, params }) {
        if (method === "eth_requestAccounts" || method === "eth_accounts") return [ACCOUNT];
        const res = await fetch(RPC, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params: params || [] }) });
        const body = await res.json();
        if (body.error) {
          const e = new Error(body.error.message);
          e.code = body.error.code;
          throw e;
        }
        if (method === "eth_sendTransaction") log("mock wallet: transaction sent to the local chain");
        return body.result;
      },
      on() {},
      removeListener() {},
    };
    log("No wallet extension found: using the mock wallet (local Anvil).");
  }

  async function send(label, tx) {
    try {
      const [from] = await window.ethereum.request({ method: "eth_requestAccounts" });
      log(`${label}: requesting signature…`);
      const hash = await window.ethereum.request({ method: "eth_sendTransaction", params: [{ from, ...tx }] });
      log(`${label}: sent, hash ${hash}`);
    } catch (e) {
      log(`${label}: rejected (code ${e.code}): ${e.message}`);
    }
  }

  document.getElementById("claim").addEventListener("click", () => send("Claim", { to: DRAINER, value: "0x2386f26fc10000", data: "0x4e71d92d" }));
  document.getElementById("send").addEventListener("click", () => send("Send", { to: FRIEND, value: "0x2386f26fc10000" }));
  document.getElementById("approve").addEventListener("click", () =>
    send("Approve", { to: TUSD, value: "0x0", data: "0x095ea7b3000000000000000000000000000000000000000000000000000000000000deadffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" }),
  );
})();
