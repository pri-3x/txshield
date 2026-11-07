import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import { Notice, PageHeader } from "@/components/ui";
import { searchTarget } from "@/lib/search";
import { txshield } from "@/lib/txshield";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Search" };

export default async function GoPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const sp = await searchParams;
  const q = typeof sp.q === "string" ? sp.q.slice(0, 200) : "";
  let chain = 1;
  try {
    chain = (await txshield().info()).chains[0]?.chainId ?? 1;
  } catch {
    // API unreachable: fall back to Ethereum; the target page reports the error.
  }
  const target = q ? searchTarget(q, chain) : null;
  if (target) redirect(target);
  return (
    <div className="space-y-4">
      <PageHeader title="Search" />
      <Notice tone="warning" title={q ? "Not a transaction hash, address, or analysis ID" : "Enter something to search for"}>
        <p>
          Search accepts a 32-byte transaction hash (0x + 64 hex), a 20-byte address (0x + 40 hex), or an analysis ID. To analyze calldata, use the{" "}
          <Link href="/scan" className="text-accent-ink underline">
            scanner
          </Link>
          .
        </p>
      </Notice>
    </div>
  );
}
