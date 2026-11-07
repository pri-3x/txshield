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
      <nav aria-label="Breadcrumb" className="flex items-center gap-2 text-[13px] text-ink-3">
        <Link href="/analyses" className="hover:text-ink">
          History
        </Link>
        <span aria-hidden="true">/</span>
        <span className="font-mono">{report.id.slice(0, 8)}</span>
      </nav>
      <h1 className="sr-only">Security report</h1>
      <SecurityReport report={report} stored />
    </div>
  );
}
