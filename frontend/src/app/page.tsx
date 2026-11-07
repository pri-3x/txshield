import Link from "next/link";
import { isTxShieldError, type AnalysisPage, type AnalysisStats, type InfoResponse } from "@txshield/sdk";
import { BarChart } from "@/components/BarChart";
import { AnalysesTable } from "@/components/AnalysesTable";
import { Card, EmptyState, Notice, PageHeader, btnPrimary } from "@/components/ui";
import { CATEGORY, CATEGORY_ORDER } from "@/lib/risk";
import { chainName } from "@/lib/format";
import { apiLocation, txshield } from "@/lib/txshield";

export const dynamic = "force-dynamic";

async function load() {
  const api = txshield();
  const info = await api.info();
  if (!info.persistence) return { info, stats: null, recent: null, highRisk: null };
  const [stats, recent, highRisk] = await Promise.all([
    api.stats(),
    api.listAnalyses({ limit: 10 }),
    api.listAnalyses({ limit: 5, minScore: 60 }),
  ]);
  return { info, stats, recent, highRisk };
}

export default async function DashboardPage() {
  let data: { info: InfoResponse; stats: AnalysisStats | null; recent: AnalysisPage | null; highRisk: AnalysisPage | null };
  try {
    data = await load();
  } catch (e) {
    return (
      <Notice tone="critical" title="The TxShield API is not reachable">
        <p>
          Tried {apiLocation()}. {isTxShieldError(e) ? `${e.kind}: ${e.message}` : "Unexpected error."} Check that <code>txshield serve</code> is running and that
          TXSHIELD_API_URL (and TXSHIELD_API_KEY, if the API requires keys) are set for the dashboard.
        </p>
      </Notice>
    );
  }
  const { info, stats, recent, highRisk } = data;

  return (
    <div className="space-y-4">
      <PageHeader
        title="Overview"
        subtitle={
          <>
            {info.chains.length ? `RPC: ${info.chains.map((c) => chainName(c.chainId)).join(", ")}` : "No RPC endpoints configured: analyses run offline"} · simulator {info.simulator} ·{" "}
            {info.rules} rules · engine <span className="font-mono">{info.version}</span>
          </>
        }
        actions={
          <Link href="/scan" className={btnPrimary}>
            Analyze a transaction
          </Link>
        }
      />

      {!stats || !recent || !highRisk ? (
        <Notice title="History is disabled on this server">
          Statistics and recent analyses need persistence (set TXSHIELD_DATABASE_URL on the API). You can still analyze transactions in the{" "}
          <Link className="text-accent-ink underline" href="/scan">
            scanner
          </Link>
          .
        </Notice>
      ) : (
        <>
          <section aria-label="Totals" className="grid grid-cols-2 gap-px overflow-hidden rounded-xl border border-line bg-line lg:grid-cols-4">
            <Stat label="Analyzed" value={stats.total.toLocaleString("en-US")} />
            <Stat label="High or critical" value={stats.highRisk.toLocaleString("en-US")} hint="score 60+" tone={stats.highRisk > 0 ? "text-critical-ink" : undefined} />
            <Stat label="Share high or critical" value={`${stats.total ? Math.round((stats.highRisk / stats.total) * 100) : 0}%`} />
            <Stat label="Chains seen" value={Object.keys(stats.byChain).length.toLocaleString("en-US")} />
          </section>

          <div className="grid grid-cols-1 items-start gap-4 xl:grid-cols-[minmax(0,1fr)_420px]">
            <div className="min-w-0 space-y-4">
              <Card title="High-risk analyses" id="high-risk" flush>
                <AnalysesTable page={highRisk} empty="No analyses scored 60 or above." label="High-risk analyses" />
              </Card>
              <Card
                title="Recent analyses"
                id="recent"
                flush
                actions={
                  <Link href="/analyses" className="text-[13px] text-accent-ink hover:underline">
                    View all
                  </Link>
                }
              >
                <AnalysesTable page={recent} empty="No analyses stored yet." label="Recent analyses" />
              </Card>
            </div>
            <div className="grid min-w-0 gap-4 md:grid-cols-2 xl:grid-cols-1">
              <Card title="Risk distribution" id="risk-dist">
                {stats.total === 0 ? (
                  <EmptyState title="No analyses yet" />
                ) : (
                  <BarChart
                    title="Analyses by risk category"
                    bars={CATEGORY_ORDER.map((c) => ({ label: CATEGORY[c].label, value: stats.byCategory[c] ?? 0, hint: `score ${CATEGORY[c].range}` }))}
                  />
                )}
              </Card>
              <Card title="Chain distribution" id="chain-dist">
                {stats.total === 0 ? (
                  <EmptyState title="No analyses yet" />
                ) : (
                  <BarChart
                    title="Analyses by chain"
                    bars={Object.entries(stats.byChain)
                      .map(([id, n]) => ({ label: chainName(Number(id)), value: n }))
                      .sort((a, b) => b.value - a.value)
                      .slice(0, 8)}
                  />
                )}
              </Card>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function Stat({ label, value, hint, tone }: { label: string; value: string; hint?: string; tone?: string }) {
  return (
    <div className="bg-surface px-4 py-3.5">
      <p className="text-[11px] font-semibold uppercase tracking-[0.06em] text-ink-3">{label}</p>
      <p className={`mt-1 text-2xl font-semibold tabular-nums ${tone ?? "text-ink"}`}>
        {value}
        {hint && <span className="ml-2 text-xs font-normal text-ink-3">{hint}</span>}
      </p>
    </div>
  );
}
