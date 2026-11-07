import type { Metadata } from "next";
import Link from "next/link";
import { isTxShieldError, type AnalysisPage } from "@txshield/sdk";
import { AnalysesTable } from "@/components/AnalysesTable";
import { Card, Notice } from "@/components/ui";
import { CATEGORY } from "@/lib/risk";
import { txshield } from "@/lib/txshield";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Analysis history" };

const PAGE = 25;
const FILTERS = [
  { label: "All", minScore: undefined },
  { label: "Elevated and above (40+)", minScore: 40 },
  { label: `${CATEGORY.high.label} and ${CATEGORY.critical.label.toLowerCase()} (60+)`, minScore: 60 },
];

export default async function HistoryPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const sp = await searchParams;
  const offset = typeof sp.offset === "string" && /^\d+$/.test(sp.offset) ? Math.min(Number(sp.offset), 10_000) : 0;
  const minScore = typeof sp.minScore === "string" && /^\d+$/.test(sp.minScore) ? Math.min(Number(sp.minScore), 100) : undefined;

  let page: AnalysisPage | null = null;
  let error: string | null = null;
  try {
    page = await txshield().listAnalyses({ limit: PAGE, offset, minScore });
  } catch (e) {
    error = isTxShieldError(e) ? (e.code === "persistence_disabled" ? "History is disabled on this server (no persistence)." : e.message) : "Unexpected error";
  }
  const href = (o: number, m = minScore) => `/analyses?offset=${o}${m !== undefined ? `&minScore=${m}` : ""}`;

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold text-ink">Analysis history</h1>
      <nav aria-label="Filter by risk" className="flex flex-wrap gap-2 text-sm">
        {FILTERS.map((f) => {
          const active = f.minScore === minScore;
          return (
            <Link key={f.label} href={href(0, f.minScore)} aria-current={active ? "page" : undefined} className={`rounded-full border px-3 py-1 ${active ? "border-accent text-ink" : "border-line text-ink-2 hover:text-ink"}`}>
              {f.label}
            </Link>
          );
        })}
      </nav>
      {error && <Notice tone={page ? "warning" : "neutral"} title={error} />}
      {page && (
        <Card>
          <AnalysesTable page={page} empty="No analyses match." label="Analysis history" />
          <nav aria-label="Pagination" className="mt-3 flex items-center gap-4 text-sm">
            {offset > 0 && (
              <Link className="text-accent-ink hover:underline" href={href(Math.max(0, offset - PAGE))}>
                ← Newer
              </Link>
            )}
            <span className="text-ink-3">
              {page.total === 0 ? "0" : `${offset + 1}–${offset + page.items.length}`} of {page.total.toLocaleString("en-US")}
            </span>
            {offset + page.items.length < page.total && (
              <Link className="text-accent-ink hover:underline" href={href(offset + PAGE)}>
                Older →
              </Link>
            )}
          </nav>
        </Card>
      )}
    </div>
  );
}
