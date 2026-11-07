import Link from "next/link";
import { isTxShieldError, type AnalysisPage, type AnalysisStats, type InfoResponse } from "@txshield/sdk";
import { BarChart } from "@/components/BarChart";
import { AnalysesTable } from "@/components/AnalysesTable";
import { Card, EmptyState, Notice } from "@/components/ui";
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
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-ink">Dashboard</h1>
          <p className="text-sm text-ink-2">
            {info.chains.length ? `Chains with RPC: ${info.chains.map((c) => chainName(c.chainId)).join(", ")}` : "No RPC endpoints configured: analyses run offline."} · simulator{" "}
            {info.simulator} · {info.rules} rules · engine {info.version}
          </p>
        </div>
        <Link href="/scan" className="rounded-md bg-btn px-4 py-2 text-sm font-medium text-white hover:opacity-90">
          Analyze a transaction
        </Link>
      </div>

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
          <section aria-label="Totals" className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <Stat label="Analyzed transactions" value={stats.total} />
            <Stat label="High or critical risk" value={stats.highRisk} hint="score 60 or above" />
            <Stat label="Share high or critical" value={stats.total ? Math.round((stats.highRisk / stats.total) * 100) : 0} unit="%" />
          </section>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
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

          <Card title="High-risk analyses" id="high-risk">
            <AnalysesTable page={highRisk} empty="No analyses scored 60 or above." label="High-risk analyses" />
          </Card>
          <Card
            title="Recent analyses"
            id="recent"
            actions={
              <Link href="/analyses" className="text-sm text-accent-ink hover:underline">
                View all
              </Link>
            }
          >
            <AnalysesTable page={recent} empty="No analyses stored yet." label="Recent analyses" />
          </Card>
        </>
      )}
    </div>
  );
}

function Stat({ label, value, unit = "", hint }: { label: string; value: number; unit?: string; hint?: string }) {
  return (
    <div className="rounded-lg border border-line bg-surface p-4">
      <p className="text-sm text-ink-2">{label}</p>
      <p className="mt-1 text-3xl font-semibold tabular-nums text-ink">
        {value.toLocaleString("en-US")}
        {unit && <span className="text-lg text-ink-2">{unit}</span>}
      </p>
      {hint && <p className="text-xs text-ink-3">{hint}</p>}
    </div>
  );
}
