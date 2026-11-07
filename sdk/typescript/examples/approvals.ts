// Show which token permissions a transaction grants and what is in force today.
import { TxShield } from "@txshield/sdk";

const shield = new TxShield({ baseUrl: process.env.TXSHIELD_URL ?? "http://localhost:8080" });

const analysis = await shield.analyzeApprovals({
  chainId: 1,
  from: "0x1111111111111111111111111111111111111111",
  to: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
  data: "0x095ea7b30000000000000000000000002222222222222222222222222222222222222222ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
});

for (const a of analysis.approvals) {
  const now = a.current ? (a.current.unlimited ? "UNLIMITED" : a.current.amount ?? "n/a") : "unknown (no RPC configured)";
  console.log(`${a.kind} on ${a.token} to ${a.spender}: grants ${a.unlimited ? "UNLIMITED" : a.amount}, currently ${now}`);
}
console.log(`approval risk: ${analysis.risk.score}/100 (${analysis.risk.category})`);
