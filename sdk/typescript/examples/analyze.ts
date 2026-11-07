// Analyze a transaction before signing it.
//
//   TXSHIELD_URL=http://localhost:8080 npx tsx examples/analyze.ts
import { TxShield, isTxShieldError } from "@txshield/sdk";

const shield = new TxShield({
  baseUrl: process.env.TXSHIELD_URL ?? "http://localhost:8080",
  apiKey: process.env.TXSHIELD_API_KEY, // only needed if the server sets TXSHIELD_API_KEYS
});

async function main() {
  try {
    const result = await shield.analyze({
      chainId: 11155111,
      from: "0x1111111111111111111111111111111111111111",
      to: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
      value: "0",
      // approve(spender, type(uint256).max)
      data: "0x095ea7b30000000000000000000000002222222222222222222222222222222222222222ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    });

    console.log(`${result.riskScore}/100 (${result.riskCategory}, confidence ${result.risk.confidence})`);
    console.log(result.verdict);
    for (const f of result.findings) {
      console.log(`- [${f.severity}/${f.confidence}, ${f.source}] ${f.ruleId}: ${f.title}`);
    }
    for (const w of result.warnings ?? []) console.log(`! ${w}`);

    // Block signing in your wallet flow when the risk is high.
    if (result.riskScore >= 60) process.exitCode = 3;
  } catch (e) {
    if (isTxShieldError(e)) {
      console.error(`${e.kind}/${e.code}: ${e.message} (request ${e.requestId ?? "n/a"})`);
      process.exitCode = 1;
    } else throw e;
  }
}

void main();
