import type { Metadata } from "next";
import { Notice, PageHeader } from "@/components/ui";
import { KNOWN_CHAINS } from "@/lib/format";
import { txshield } from "@/lib/txshield";
import { Scanner } from "./Scanner";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Transaction scanner" };

export default async function ScanPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const sp = await searchParams;
  const initialHash = typeof sp.hash === "string" && /^0x[0-9a-fA-F]{64}$/.test(sp.hash) ? sp.hash : undefined;
  const initialChain = typeof sp.chainId === "string" && /^\d{1,15}$/.test(sp.chainId) ? Number(sp.chainId) : undefined;
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
      <PageHeader title="Transaction scanner" subtitle="Analyze a transaction before signing it. Nothing is signed or broadcast. Chains without an RPC endpoint are analyzed offline (no simulation)." />
      {!reachable && <Notice tone="critical" title="The TxShield API is not reachable; analysis requests will fail." />}
      <Scanner chains={chains} initialHash={initialHash} initialChain={initialChain} />
    </div>
  );
}
