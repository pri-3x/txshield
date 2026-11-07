import Link from "next/link";
import type { AnalysisPage } from "@txshield/sdk";
import { chainName, formatDateTime } from "@/lib/format";
import { EmptyState, Hex, RiskBadge, TableWrap, td, th } from "./ui";

export function AnalysesTable({ page, empty, label = "Analyses" }: { page: AnalysisPage; empty: string; label?: string }) {
  if (page.items.length === 0) return <EmptyState title={empty} />;
  return (
    <TableWrap label={label}>
      <table className="w-full min-w-[40rem] border-collapse">
        <thead>
          <tr>
            <th className={th}>Analyzed</th>
            <th className={th}>Risk</th>
            <th className={th}>Target</th>
            <th className={th}>Method</th>
            <th className={th}>Chain</th>
            <th className={th}>Findings</th>
          </tr>
        </thead>
        <tbody>
          {page.items.map((a) => (
            <tr key={a.id}>
              <td className={td}>
                <Link href={`/analyses/${a.id}`} className="text-accent-ink underline-offset-2 hover:underline">
                  {formatDateTime(a.analyzedAt)}
                </Link>
              </td>
              <td className={td}>
                <RiskBadge category={a.category} score={a.score} />
              </td>
              <td className={td}>{a.to ? <Hex value={a.to} /> : <span className="text-ink-3">creation</span>}</td>
              <td className={`${td} whitespace-nowrap font-mono text-xs`} title={a.method || undefined}>
                {a.method ? a.method.split("(")[0] : a.kind.replaceAll("_", " ")}
              </td>
              <td className={td}>{chainName(a.chainId)}</td>
              <td className={`${td} tabular-nums`}>{a.findingCount}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {page.total > page.items.length && <p className="mt-2 text-xs text-ink-3">Showing {page.items.length} of {page.total.toLocaleString("en-US")}.</p>}
    </TableWrap>
  );
}
