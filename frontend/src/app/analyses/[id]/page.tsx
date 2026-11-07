import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { isTxShieldError, type RiskReport } from "@txshield/sdk";
import { SecurityReport } from "@/components/report";
import { Notice } from "@/components/ui";
import { txshield } from "@/lib/txshield";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Security report" };

export default async function AnalysisPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  let report: RiskReport;
  try {
    report = await txshield().getAnalysis(id);
  } catch (e) {
    if (isTxShieldError(e) && (e.kind === "not_found" || e.code === "client_validation")) notFound();
    return (
      <Notice tone="critical" title="Could not load this analysis">
        {isTxShieldError(e) ? `${e.kind}: ${e.message}` : "Unexpected error."}
      </Notice>
    );
  }
  return (
    <div className="space-y-4">
      <p className="text-sm">
        <Link href="/" className="text-accent-ink hover:underline">
          ← Dashboard
        </Link>
      </p>
      <h1 className="text-2xl font-semibold text-ink">Security report</h1>
      <SecurityReport report={report} />
    </div>
  );
}
