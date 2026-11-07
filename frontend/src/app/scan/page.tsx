import type { Metadata } from "next";
import { Notice } from "@/components/ui";
import { KNOWN_CHAINS } from "@/lib/format";
import { txshield } from "@/lib/txshield";
import { Scanner } from "./Scanner";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Transaction scanner" };

export default async function ScanPage() {
  let configured: number[] = [];
  let reachable = true;
  try {
    configured = (await txshield().info()).chains.map((c) => c.chainId);
  } catch {
    reachable = false;
  }
  const chains = [
    ...configured.map((id) => ({ id, name: KNOWN_CHAINS.find((c) => c.id === id)?.name ?? `Chain ${id}`, rpc: true })),
    ...KNOWN_CHAINS.filter((c) => !configured.includes(c.id)).map((c) => ({ id: c.id, name: c.name, rpc: false })),
  ];
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold text-ink">Transaction scanner</h1>
        <p className="text-sm text-ink-2">Analyze a transaction before signing it. Nothing is signed or broadcast. Chains without an RPC endpoint are analyzed offline (no simulation).</p>
      </div>
      {!reachable && <Notice tone="critical" title="The TxShield API is not reachable; analysis requests will fail." />}
      <Scanner chains={chains} />
    </div>
  );
}
