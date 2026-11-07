import type { Metadata } from "next";
import { isTxShieldError, type AddressReport } from "@txshield/sdk";
import { AnalysesTable } from "@/components/AnalysesTable";
import { Card, EmptyState, Hex, KeyValue, Notice, TableWrap, td, th } from "@/components/ui";
import { KNOWN_CHAINS, chainName, formatDateTime, visible } from "@/lib/format";
import { txshield } from "@/lib/txshield";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Address inspector" };

const STATUS_LABEL = { unknown: "No record", allowed: "Allowed", suspicious: "Suspicious", blocked: "Blocked" } as const;

export default async function AddressPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const sp = await searchParams;
  const address = typeof sp.address === "string" ? sp.address.trim() : "";
  const chainId = typeof sp.chainId === "string" ? sp.chainId : "1";
  const offset = typeof sp.offset === "string" && /^\d+$/.test(sp.offset) ? Number(sp.offset) : 0;

  let report: AddressReport | null = null;
  let error: string | null = null;
  if (address) {
    try {
      report = await txshield().inspectAddress(address, { chainId: /^\d+$/.test(chainId) ? BigInt(chainId) : 0, limit: 20, offset });
    } catch (e) {
      error = isTxShieldError(e) ? (e.fields.length ? e.fields.map((f) => `${f.field}: ${f.message}`).join("; ") : e.message) : "Unexpected error";
    }
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold text-ink">Address inspector</h1>
        <p className="text-sm text-ink-2">On-chain facts, reputation, and analyses involving an address that this TxShield server has seen.</p>
      </div>
      <Card>
        <form method="get" className="grid grid-cols-1 gap-3 sm:grid-cols-[1fr_14rem_auto] sm:items-end">
          <div>
            <label htmlFor="address" className="mb-1 block text-sm font-medium text-ink">
              Address
            </label>
            <input id="address" name="address" defaultValue={address} placeholder="0x…" required spellCheck={false} autoComplete="off" className="w-full rounded-md border border-line bg-surface px-3 py-2 font-mono text-sm text-ink placeholder:text-ink-3" />
          </div>
          <div>
            <label htmlFor="chainId" className="mb-1 block text-sm font-medium text-ink">
              Network
            </label>
            <select id="chainId" name="chainId" defaultValue={chainId} className="w-full rounded-md border border-line bg-surface px-3 py-2 text-sm text-ink">
              {KNOWN_CHAINS.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name} ({c.id})
                </option>
              ))}
            </select>
          </div>
          <button type="submit" className="rounded-md bg-btn px-4 py-2 text-sm font-medium text-white hover:opacity-90">
            Inspect
          </button>
        </form>
      </Card>

      {error && <Notice tone="critical" title={`Could not inspect address: ${error}`} />}

      {report && (
        <>
          {report.warnings?.length ? (
            <Notice tone="warning" title="Partial information">
              <ul className="list-disc pl-5">
                {report.warnings.map((w, i) => (
                  <li key={i}>{visible(w)}</li>
                ))}
              </ul>
            </Notice>
          ) : null}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card title="On-chain facts" id="facts">
              {report.contract ? (
                <KeyValue
                  items={[
                    ["Address", <Hex key="a" value={report.address} />],
                    ["Network", `${chainName(report.chainId)} (${report.chainId})`],
                    ["Type", report.contract.isContract ? "Contract" : report.contract.standards?.includes("eip7702-delegated") ? "Account with EIP-7702 delegation" : "Account (no code)"],
                    ...(report.contract.isContract ? ([["Code size", `${report.contract.codeSize.toLocaleString("en-US")} bytes`]] as [string, string][]) : []),
                    ...(report.contract.isProxy ? ([["Proxy implementation", <Hex key="i" value={report.contract.implementation ?? ""} />]] as [string, React.ReactNode][]) : []),
                    ...(report.contract.standards?.length ? ([["Detected standards", report.contract.standards.join(", ")]] as [string, string][]) : []),
                    ["Verified source", report.contract.verified === undefined ? "Not checked (no verification source configured)" : report.contract.verified ? "Yes" : "No"],
                  ]}
                />
              ) : (
                <EmptyState title="No on-chain facts">This server has no RPC endpoint for the chain.</EmptyState>
              )}
            </Card>
            <Card title="Reputation" id="reputation">
              <p className="mb-3 text-sm">
                <span className="text-ink-2">Resolved status: </span>
                <span className={`font-semibold ${report.reputation.status === "blocked" ? "text-critical-ink" : report.reputation.status === "suspicious" ? "text-serious-ink" : "text-ink"}`}>
                  {STATUS_LABEL[report.reputation.status]}
                </span>
                <span className="text-ink-3"> · sources: {report.reputation.sources.length ? report.reputation.sources.join(", ") : "none configured"}</span>
              </p>
              {report.reputation.records.length === 0 ? (
                <p className="text-sm text-ink-2">No reputation records. An unknown address is not evidence of anything; verify it through official channels.</p>
              ) : (
                <TableWrap label="Reputation records">
                  <table className="w-full min-w-[30rem] border-collapse">
                    <thead>
                      <tr>
                        <th className={th}>Source</th>
                        <th className={th}>Status</th>
                        <th className={th}>Reason</th>
                        <th className={th}>Updated</th>
                      </tr>
                    </thead>
                    <tbody>
                      {report.reputation.records.map((r, i) => (
                        <tr key={i}>
                          <td className={td}>
                            {visible(r.source, 80)} <span className="text-xs text-ink-3">({r.sourceKind})</span>
                          </td>
                          <td className={td}>{STATUS_LABEL[r.status]}</td>
                          <td className={`${td} break-words`}>{visible(r.reason, 300)}</td>
                          <td className={`${td} whitespace-nowrap text-ink-2`}>{r.updatedAt && !r.updatedAt.startsWith("0001") ? formatDateTime(r.updatedAt) : "–"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </TableWrap>
              )}
            </Card>
          </div>
          <Card title="Analyses involving this address" id="history">
            {report.history ? (
              <>
                <AnalysesTable page={report.history} empty="This server has not analyzed transactions involving this address." />
                {(offset > 0 || report.history.total > offset + report.history.items.length) && (
                  <nav aria-label="Pagination" className="mt-3 flex gap-3 text-sm">
                    {offset > 0 && (
                      <a className="text-accent-ink hover:underline" href={`?address=${encodeURIComponent(address)}&chainId=${chainId}&offset=${Math.max(0, offset - 20)}`}>
                        ← Newer
                      </a>
                    )}
                    {report.history.total > offset + report.history.items.length && (
                      <a className="text-accent-ink hover:underline" href={`?address=${encodeURIComponent(address)}&chainId=${chainId}&offset=${offset + 20}`}>
                        Older →
                      </a>
                    )}
                  </nav>
                )}
              </>
            ) : (
              <p className="text-sm text-ink-2">History is disabled on this server (no persistence).</p>
            )}
            <p className="mt-3 text-xs text-ink-3">
              Token approvals listed here are limited to approvals seen in stored analyses. Use <code>txshield approval-check</code> to read the permissions currently in force for a specific token and spender.
            </p>
          </Card>
        </>
      )}
    </div>
  );
}
