# TxShield browser extension

Checks every transaction a website asks your wallet to send, **before your
wallet opens**. It sends the transaction to a TxShield API, which simulates
it on a private fork, and shows a plain-language warning when something is
wrong, for example:

> Don't sign this. It sends 0.01 ETH, 1,000 TUSD* and NFT #1 out of your
> wallet, and you receive nothing.

**Reject** is the default. For high and critical risk, **Continue to wallet**
stays disabled until you tick "I understand the risk". Low-risk transactions
show a short notice and the wallet opens as usual.

Status: prototype (v0.1.0). Chrome, Edge, and Brave (Manifest V3).
Not yet published to any extension store.

## Install (developer mode)

1. Start a TxShield API (see the repository README), or use one you trust.
2. Open `chrome://extensions`, turn on **Developer mode**, click **Load
   unpacked**, and choose this `extension/` folder.
3. The settings page opens. Set the **API URL** (default
   `http://127.0.0.1:18080`), an **API key** if the server needs one, and the
   **Dashboard URL** for "Full report" links. Click **Test connection**, then
   **Save**. Saving a non-local API URL asks Chrome for permission to contact
   that host.

## Try it

`demo/index.html` is a fake airdrop dApp with three buttons: a drainer
"claim", a plain ETH send, and an unlimited approval to a blocklisted
address. It talks to a local Anvil chain (chain 31337) with the demo
contracts deployed (see the repository's manual test notes); without a
wallet extension it uses a built-in mock wallet.

```bash
python3 -m http.server 5180 --bind 127.0.0.1 --directory extension
```

Then open http://127.0.0.1:5180/demo/index.html with the extension loaded.

`demo/harness.html` runs the extension's own scripts inside the page (no
extension install needed) and calls the API directly, which is how the
automated browser checks run. The API must allow the page's origin:
`TXSHIELD_CORS_ORIGINS=http://127.0.0.1:5180`.

## How it works

| File | Runs in | Role |
|---|---|---|
| `src/inpage.js` | the page's JavaScript world, before any page script | Wraps EIP-1193 providers (`window.ethereum`, and EIP-6963 announced providers) so `eth_sendTransaction` waits for TxShield. A rejection reaches the dApp as error `4001`, the standard "user rejected" code. |
| `src/content.js` | isolated extension world | Bridges the page and the extension, and draws the warning in a closed shadow root. All text is set with `textContent`. |
| `src/background.js` | extension service worker | Holds the settings and calls `POST /api/v1/analyze`. Pages never see the API URL or key. |
| `src/lib.js` | everywhere | Pure logic: request building, the warn/allow decision, and the plain-language view of a report. Unit-tested. |

## Privacy

Every transaction a site asks you to send (sender, recipient, value,
calldata) goes to the API URL you configure, and nowhere else. Run your own
server, or use one you trust. The API key is stored on this device only
(`chrome.storage.local`). The extension never sees or handles private keys
and cannot sign or send anything itself.

## Limits

- **Best effort.** Only transactions requested through the normal wallet API
  are checked. A site built to evade the extension (for example by capturing
  the wallet before the extension loads, or by answering its messages
  itself) can bypass it. Wallet-level integration, such as a MetaMask Snap,
  is the robust option.
- **Signatures are not checked yet.** Typed-data signatures
  (`eth_signTypedData_v4`), such as Permit and Permit2 approvals, are a
  common phishing route and pass through unchecked in this version.
- **Detection is not exhaustive.** A low score means no significant risks
  were detected by the enabled checks, not that a transaction is safe.
- **Token names are unverified.** Symbols and decimals come from the token
  contract, so they are marked `*`.

## Development

```bash
cd extension
npm install
npm test          # unit tests (lib.js) against real API responses
npm run package   # dist/txshield-extension-<version>.zip
```
