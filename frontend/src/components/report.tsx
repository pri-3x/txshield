import type { ApprovalGrant, ApprovalWithState, BalanceChange, CallFrame, DecodedCall, DecodedParam, Finding, RiskReport, SimulationResult, AssetTransfer } from "@txshield/sdk";
import { CATEGORY, CATEGORY_ORDER, TONE_CLASSES } from "@/lib/risk";
import { chainName, describeAmount, formatDateTime, formatUnits, groupDigits, nativeSymbol, visible } from "@/lib/format";
import { Card, ConfidenceText, EmptyState, Hex, KeyValue, Notice, RiskBadge, SeverityBadge, SourceBadge, TableWrap, td, th } from "./ui";

/** Score header: the hero number, its band, and what produced it. */
export function ScoreHeader({ report }: { report: RiskReport }) {
  const { risk } = report;
  const c = CATEGORY[risk.category];
  return (
    <section aria-labelledby="score-title" className="rounded-lg border border-line bg-surface p-4 sm:p-6">
      <h2 id="score-title" className="sr-only">
        Risk score
      </h2>
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-baseline gap-3">
          <span className="text-5xl font-semibold tabular-nums text-ink">{risk.score}</span>
          <span className="text-ink-2">/ 100</span>
        </div>
        <div className="flex flex-col items-start gap-1 sm:items-end">
          <RiskBadge category={risk.category} />
          <ConfidenceText confidence={risk.confidence} />
        </div>
      </div>
      <ScoreBand score={risk.score} />
      <p className="mt-4 text-sm font-medium text-ink">{visible(report.verdict)}</p>
      <p className="mt-1 text-xs text-ink-2">Band {c.range}. Confidence reflects how complete the analysis was (simulation, contract checks), not how sure TxShield is that the transaction is safe.</p>
    </section>
  );
}

/** Five-band scale with a marker at the score. */
const BAND_STARTS = [0, 20, 40, 60, 80];
const BAND_WIDTHS = [20, 20, 20, 20, 21];

function ScoreBand({ score }: { score: number }) {
  return (
    <svg viewBox="0 0 101 10" preserveAspectRatio="none" className="mt-4 h-3 w-full" role="img" aria-label={`Score ${score} on a 0 to 100 scale`}>
      {CATEGORY_ORDER.map((cat, i) => (
        // 0.5-unit surface gap between bands.
        <rect key={cat} x={BAND_STARTS[i]! + (i ? 0.5 : 0)} y={2} width={BAND_WIDTHS[i]! - (i ? 0.5 : 0)} height={6} rx={1} className={`${fillFor(cat)} opacity-35`} />
      ))}
      <rect x={Math.min(score, 100) - 0.6} y={0} width={1.2} height={10} rx={0.6} className="fill-ink" />
    </svg>
  );
}

function fillFor(cat: keyof typeof CATEGORY): string {
  return { good: "fill-good", warning: "fill-warning", serious: "fill-serious", critical: "fill-critical", neutral: "fill-ink-3" }[CATEGORY[cat].tone];
}

export function FindingsList({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return <EmptyState title="No findings from enabled checks">This does not mean the transaction is safe; see the analysis limitations.</EmptyState>;
  }
  return (
    <ul className="divide-y divide-line">
      {findings.map((f) => (
        <li key={f.fingerprint} className="py-3">
          <details className="group">
            <summary className="flex cursor-pointer list-none flex-wrap items-center gap-2 [&::-webkit-details-marker]:hidden">
              <span aria-hidden="true" className="text-ink-3 transition-transform group-open:rotate-90">
                ▸
              </span>
              <SeverityBadge severity={f.severity} />
              <span className="font-medium text-ink">{f.title}</span>
              <span className="font-mono text-xs text-ink-3">{f.ruleId}</span>
            </summary>
            <div className="mt-3 space-y-3 pl-5 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <SourceBadge source={f.source} />
                <ConfidenceText confidence={f.confidence} />
              </div>
              <p className="text-ink">{visible(f.description, 2000)}</p>
              {f.evidence && f.evidence.length > 0 && (
                <div>
                  <h4 className="mb-1 text-xs font-medium uppercase tracking-wide text-ink-2">Evidence</h4>
                  <ul className="space-y-1">
                    {f.evidence.map((e, i) => (
                      <li key={i} className="rounded bg-surface-2 px-2 py-1">
                        <span className="text-xs text-ink-3">{e.type} · {e.source}</span>
                        <p className="break-words text-ink">{visible(e.detail, 1000)}</p>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              <p>
                <span className="font-medium text-ink">Mitigation: </span>
                <span className="text-ink-2">{f.mitigation}</span>
              </p>
              {f.falsePositiveNotes && (
                <p>
                  <span className="font-medium text-ink">Possible false positive: </span>
                  <span className="text-ink-2">{f.falsePositiveNotes}</span>
                </p>
              )}
            </div>
          </details>
        </li>
      ))}
    </ul>
  );
}

function paramValue(p: DecodedParam): React.ReactNode {
  const v = p.value as unknown;
  if (typeof v === "string") {
    if (p.type.startsWith("address")) return <Hex value={v} />;
    if (/^u?int/.test(p.type)) return <span className="font-mono tabular-nums">{describeAmount(v)}</span>;
    return <span className="break-all font-mono text-[0.8125rem]">{visible(v, 300)}</span>;
  }
  if (typeof v === "boolean") return <span className="font-mono">{String(v)}</span>;
  if (Array.isArray(v)) {
    if (v.length === 0) return <span className="font-mono text-ink-3">[]</span>;
    const isTuple = typeof v[0] === "object" && v[0] !== null && "name" in (v[0] as object) && "type" in (v[0] as object);
    if (isTuple) return <ParamList params={v as DecodedParam[]} />;
    return (
      <ol className="list-decimal pl-5">
        {v.map((item, i) => (
          <li key={i}>{paramValue({ name: `[${i}]`, type: p.type.replace(/\[\d*\]$/, ""), value: item })}</li>
        ))}
      </ol>
    );
  }
  return <span className="font-mono text-ink-3">–</span>;
}

function ParamList({ params }: { params: DecodedParam[] }) {
  return (
    <dl className="space-y-1">
      {params.map((p, i) => (
        <div key={i} className="grid grid-cols-1 gap-x-3 sm:grid-cols-[minmax(8rem,max-content)_1fr]">
          <dt className="text-ink-2">
            {p.name} <span className="font-mono text-xs text-ink-3">{p.type}</span>
          </dt>
          <dd className="min-w-0">{paramValue(p)}</dd>
        </div>
      ))}
    </dl>
  );
}

export function DecodedCallTree({ call, depth = 0 }: { call: DecodedCall; depth?: number }) {
  const heading =
    call.kind === "native_transfer"
      ? "Native transfer"
      : call.kind === "contract_creation"
        ? "Contract creation"
        : call.signature || (call.selector ? `Unrecognized function ${call.selector}` : "Unrecognized call");
  return (
    <div className={depth > 0 ? "border-l-2 border-line pl-3" : ""}>
      <div className="flex flex-wrap items-center gap-2 text-sm">
        {call.label && <span className="text-ink-3">{call.label}:</span>}
        <span className="break-all font-mono font-medium text-ink">{visible(heading, 300)}</span>
        {call.standard && <span className="rounded border border-line px-1.5 text-xs text-ink-2">{call.standard}</span>}
        {call.callType !== "call" && <span className="rounded bg-surface-2 px-1.5 text-xs text-ink-2">{call.callType}</span>}
      </div>
      <div className="mt-2 space-y-2 text-sm">
        {call.target && (
          <p className="text-ink-2">
            Target <Hex value={call.target} />
          </p>
        )}
        {call.value && <p className="text-ink-2">Value {formatUnits(call.value)} (native)</p>}
        {call.params && call.params.length > 0 && <ParamList params={call.params} />}
        {call.candidates && call.candidates.length > 0 && <p className="text-ink-2">Other signatures with this selector: {call.candidates.join(", ")}</p>}
        {call.rawData && (
          <details>
            <summary className="cursor-pointer text-ink-2">Raw calldata ({(call.rawData.length - 2) / 2} bytes)</summary>
            <p className="mt-1 break-all font-mono text-xs text-ink-2">{call.rawData}</p>
          </details>
        )}
        {call.warnings?.map((w, i) => (
          <p key={i} className="text-serious-ink">
            ⚠ {visible(w)}
          </p>
        ))}
        {call.children && call.children.length > 0 && (
          <div className="space-y-3 pt-1">
            {call.children.map((c, i) => (
              <DecodedCallTree key={i} call={c} depth={depth + 1} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export function ApprovalsTable({ approvals }: { approvals: (ApprovalGrant | ApprovalWithState)[] }) {
  if (approvals.length === 0) return <EmptyState title="No token permissions">This transaction grants or revokes no permissions that TxShield recognizes.</EmptyState>;
  const hasCurrent = approvals.some((a) => "current" in a && a.current);
  return (
    <TableWrap label="Token permissions">
      <table className="w-full min-w-[42rem] border-collapse">
        <thead>
          <tr>
            <th className={th}>Permission</th>
            <th className={th}>Token</th>
            <th className={th}>Spender</th>
            <th className={th}>Grants</th>
            {hasCurrent && <th className={th}>In force now</th>}
          </tr>
        </thead>
        <tbody>
          {approvals.map((a, i) => {
            const cur = "current" in a ? a.current : undefined;
            return (
              <tr key={i}>
                <td className={td}>
                  <span className="text-ink">{a.kind.replaceAll("_", " ")}</span>
                  <div className="text-xs text-ink-3">{a.ownerIsSender ? "your assets" : "intermediary contract"}{a.signed ? " · signed permit" : ""}</div>
                </td>
                <td className={td}>
                  <Hex value={a.token} />
                </td>
                <td className={td}>
                  <Hex value={a.spender} />
                </td>
                <td className={`${td} font-mono`}>
                  {a.revocation ? "Revocation" : a.approved !== undefined ? (a.approved ? "All tokens (operator)" : "Revoke operator") : a.tokenId ? `Token #${a.tokenId}` : describeAmount(a.amount)}
                </td>
                {hasCurrent && (
                  <td className={`${td} font-mono`}>
                    {!cur ? "–" : cur.error ? <span className="text-ink-3">{cur.error}</span> : cur.approvedForAll !== undefined ? (cur.approvedForAll ? "Operator approved" : "None") : cur.tokenApproved !== undefined ? (cur.tokenApproved ? "Approved" : "None") : describeAmount(cur.amount)}
                  </td>
                )}
              </tr>
            );
          })}
        </tbody>
      </table>
    </TableWrap>
  );
}

function assetName(kind: string, address?: string, tokenId?: string) {
  if (kind === "native") return <span>Native</span>;
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      <span className="text-xs uppercase text-ink-3">{kind}</span>
      {address && <Hex value={address} />}
      {tokenId && <span className="font-mono text-xs">#{tokenId}</span>}
    </span>
  );
}

export function BalanceChangesTable({ changes, chainId }: { changes: BalanceChange[]; chainId: number }) {
  if (changes.length === 0) return <p className="text-sm text-ink-2">No balance changes for the sender.</p>;
  return (
    <TableWrap label="Balance changes">
      <table className="w-full min-w-[36rem] border-collapse">
        <thead>
          <tr>
            <th className={th}>Asset</th>
            <th className={`${th} text-right`}>Change</th>
            <th className={`${th} text-right`}>After</th>
          </tr>
        </thead>
        <tbody>
          {changes.map((b, i) => {
            const native = b.asset.kind === "native";
            const neg = b.delta.startsWith("-");
            return (
              <tr key={i}>
                <td className={td}>{assetName(b.asset.kind, b.asset.address, b.asset.tokenId)}</td>
                <td className={`${td} text-right font-mono tabular-nums ${neg ? "text-critical-ink" : "text-good-ink"}`}>
                  {!neg && "+"}
                  {native ? `${formatUnits(b.delta)} ${nativeSymbol(chainId)}` : groupDigits(b.delta)}
                </td>
                <td className={`${td} text-right font-mono tabular-nums text-ink-2`}>{native ? `${formatUnits(b.after)} ${nativeSymbol(chainId)}` : groupDigits(b.after)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <p className="mt-2 text-xs text-ink-3">Token amounts are raw base units (token decimals are not trusted or assumed).</p>
    </TableWrap>
  );
}

function TransfersTable({ transfers, chainId }: { transfers: AssetTransfer[]; chainId: number }) {
  return (
    <TableWrap label="Asset transfers">
      <table className="w-full min-w-[44rem] border-collapse">
        <thead>
          <tr>
            <th className={th}>Asset</th>
            <th className={th}>From</th>
            <th className={th}>To</th>
            <th className={`${th} text-right`}>Amount</th>
          </tr>
        </thead>
        <tbody>
          {transfers.slice(0, 50).map((t, i) => (
            <tr key={i}>
              <td className={td}>{assetName(t.asset.kind, t.asset.address, t.asset.tokenId)}</td>
              <td className={td}>
                <Hex value={t.from} />
              </td>
              <td className={td}>
                <Hex value={t.to} />
              </td>
              <td className={`${td} text-right font-mono tabular-nums`}>{t.asset.kind === "native" ? `${formatUnits(t.amount)} ${nativeSymbol(chainId)}` : groupDigits(t.amount)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {transfers.length > 50 && <p className="mt-2 text-xs text-ink-3">Showing 50 of {transfers.length} transfers.</p>}
    </TableWrap>
  );
}

function TraceNode({ f, depth }: { f: CallFrame; depth: number }) {
  return (
    <li className={depth ? "border-l border-line pl-3" : ""}>
      <div className="flex flex-wrap items-center gap-2 py-0.5 font-mono text-xs">
        <span className={f.type === "DELEGATECALL" ? "font-semibold text-serious-ink" : "text-ink-2"}>{f.type}</span>
        {f.to && <Hex value={f.to} copy={false} />}
        {f.input && f.input.length >= 10 && <span className="text-ink-3">{f.input.slice(0, 10)}</span>}
        {f.value && f.value !== "0" && <span className="text-ink-2">value {formatUnits(f.value)}</span>}
        {f.error && <span className="text-critical-ink">✕ {visible(f.revertReason || f.error, 120)}</span>}
      </div>
      {f.calls && f.calls.length > 0 && depth < 12 && (
        <ul className="ml-1">
          {f.calls.map((c, i) => (
            <TraceNode key={i} f={c} depth={depth + 1} />
          ))}
        </ul>
      )}
    </li>
  );
}

export function SimulationPanel({ sim }: { sim: SimulationResult }) {
  const statusTone = sim.status === "success" ? "good" : sim.status === "reverted" ? "critical" : "neutral";
  const t = TONE_CLASSES[statusTone];
  const statusLabel = { success: "Executed", reverted: "Reverted", not_run: "Not run", error: "Could not run" }[sim.status];
  return (
    <div className="space-y-4">
      <KeyValue
        items={[
          [
            "Status",
            <span key="s" className={`font-medium ${t.text}`}>
              {statusLabel} <span className="font-normal text-ink-2">({sim.completeness} data, backend {sim.backend})</span>
            </span>,
          ],
          ...(sim.status === "success" || sim.status === "reverted"
            ? ([
                ["Network / block", `${chainName(sim.chainId)} · block ${sim.blockNumber.toLocaleString("en-US")}`],
                ["Gas", `${sim.gasUsed.toLocaleString("en-US")} used${sim.gasEstimate ? ` · estimate ${sim.gasEstimate.toLocaleString("en-US")}` : ""}`],
              ] as [string, string][])
            : []),
          ...(sim.revertReason ? ([["Revert reason", <span key="r" className="break-words font-mono">{visible(sim.revertReason)}</span>]] as [string, React.ReactNode][]) : []),
        ]}
      />
      {sim.status === "success" && sim.completeness !== "none" && (
        <>
          <div>
            <h3 className="mb-2 text-sm font-semibold text-ink">Sender balance changes</h3>
            <BalanceChangesTable changes={sim.balanceChanges ?? []} chainId={sim.chainId} />
          </div>
          {sim.assetTransfers && sim.assetTransfers.length > 0 && (
            <div>
              <h3 className="mb-2 text-sm font-semibold text-ink">Asset transfers</h3>
              <TransfersTable transfers={sim.assetTransfers} chainId={sim.chainId} />
            </div>
          )}
        </>
      )}
      {sim.trace && (
        <details>
          <summary className="cursor-pointer text-sm text-ink-2">Call trace (contract interactions)</summary>
          <ul className="mt-2 overflow-x-auto">
            <TraceNode f={sim.trace} depth={0} />
          </ul>
        </details>
      )}
      {(sim.incompleteReasons?.length || sim.notes?.length) && (
        <ul className="space-y-1 text-xs text-ink-2">
          {sim.incompleteReasons?.map((r, i) => <li key={`i${i}`}>Incomplete: {visible(r)}</li>)}
          {sim.notes?.map((n, i) => <li key={`n${i}`}>Note: {visible(n)}</li>)}
        </ul>
      )}
    </div>
  );
}

/** The full security report. Used by the scanner and the stored-report page. */
export function SecurityReport({ report }: { report: RiskReport }) {
  const tx = report.transaction;
  return (
    <div className="space-y-4">
      <ScoreHeader report={report} />
      {report.warnings && report.warnings.length > 0 && (
        <Notice tone="warning" title="Analysis limitations">
          <ul className="list-disc space-y-1 pl-5">
            {report.warnings.map((w, i) => (
              <li key={i}>{visible(w)}</li>
            ))}
          </ul>
        </Notice>
      )}
      <Card title="Transaction" id="tx">
        <KeyValue
          items={[
            ["Summary", visible(tx.description, 400)],
            ["Network", `${tx.chainName || chainName(tx.chainId)} (chain ${tx.chainId})`],
            ["From", tx.from === "[redacted-sender]" ? <span key="f" className="text-ink-2">Not stored (server privacy setting)</span> : <Hex key="f" value={tx.from} />],
            ["To", tx.to ? <Hex key="t" value={tx.to} /> : "– (contract creation)"],
            ["Value", `${formatUnits(tx.value)} ${nativeSymbol(tx.chainId)}`],
            ["State", `block ${tx.block}`],
            ["Analyzed", formatDateTime(report.analyzedAt)],
          ]}
        />
      </Card>
      <Card title={`Findings (${report.findings.length})`} id="findings">
        <FindingsList findings={report.findings} />
      </Card>
      <Card title="Recommended actions" id="recs">
        <ol className="list-decimal space-y-1 pl-5 text-sm text-ink">
          {report.recommendations.map((r, i) => (
            <li key={i}>{r}</li>
          ))}
        </ol>
      </Card>
      <Card title="Token permissions" id="approvals">
        <ApprovalsTable approvals={report.approvals} />
      </Card>
      {report.simulation && (
        <Card title="Simulation" id="sim">
          <SimulationPanel sim={report.simulation} />
        </Card>
      )}
      {report.decoded && (
        <Card title="Decoded call" id="decoded">
          <DecodedCallTree call={report.decoded} />
        </Card>
      )}
      <Card title="How the score was computed" id="score-breakdown">
        {report.risk.contributions.length === 0 ? (
          <p className="text-sm text-ink-2">No finding contributed to the score.</p>
        ) : (
          <ul className="space-y-1 text-sm">
            {report.risk.contributions.map((c, i) => (
              <li key={i} className="flex flex-wrap gap-x-3">
                <span className="w-14 text-right font-mono tabular-nums text-ink">+{c.points.toFixed(1)}</span>
                <span className="font-mono text-xs text-ink-3">{c.ruleId || c.fingerprint}</span>
                <span className="text-ink-2">{c.reason}</span>
              </li>
            ))}
          </ul>
        )}
        <details className="mt-3 text-sm">
          <summary className="cursor-pointer text-ink-2">Enabled checks ({report.enabledChecks.length})</summary>
          <p className="mt-1 break-words font-mono text-xs text-ink-2">{report.enabledChecks.join(", ")}</p>
        </details>
      </Card>
      <p className="text-xs text-ink-3">
        {report.disclaimer} Report {report.id}
        {report.requestId ? ` · request ${report.requestId}` : ""} · engine {report.engineVersion}
      </p>
    </div>
  );
}
