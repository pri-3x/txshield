import type { ApprovalGrant, ApprovalWithState, AssetTransfer, BalanceChange, CallFrame, DecodedCall, DecodedParam, Finding, RiskReport, SimulationResult } from "@txshield/sdk";
import { CATEGORY, SEVERITY, TONE_CLASSES, type Tone } from "@/lib/risk";
import { KNOWN_SELECTORS, assetDisplay, chainName, describeAmount, formatDateTime, formatUnits, nativeSymbol, shortHex, visible } from "@/lib/format";
import { FindingsTable } from "./FindingsTable";
import { ReportActions } from "./ReportActions";
import { Card, EmptyState, Hex, Notice, RiskBadge, SourceBadge, Tag, TableWrap, td, th } from "./ui";

// ---------------------------------------------------------------------------
// Summary bar

function ScoreTile({ score, tone }: { score: number; tone: Tone }) {
  const t = TONE_CLASSES[tone];
  return (
    <div className={`flex size-16 shrink-0 flex-col items-center justify-center rounded-xl ${t.tag}`}>
      <span className="text-2xl font-bold leading-none tabular-nums">{score}</span>
      <span className="mt-0.5 text-[10px] tracking-wider opacity-90">/100</span>
    </div>
  );
}

function topFinding(findings: Finding[], points: Record<string, number>): Finding | undefined {
  return [...findings].sort((a, b) => SEVERITY[b.severity].rank - SEVERITY[a.severity].rank || (points[b.fingerprint] ?? 0) - (points[a.fingerprint] ?? 0))[0];
}

function SummaryBar({ report, points, stored }: { report: RiskReport; points: Record<string, number>; stored: boolean }) {
  const { risk, transaction: tx } = report;
  const c = CATEGORY[risk.category];
  const top = topFinding(report.findings, points);
  const selector = report.decoded?.selector;
  const method = report.decoded?.signature ? report.decoded.signature.split("(")[0] : report.decoded?.kind === "native_transfer" ? "native transfer" : undefined;
  return (
    <section aria-labelledby="score-title" className="rounded-xl border border-line bg-surface p-4">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-4">
        <div className="flex min-w-0 items-center gap-3.5">
          <ScoreTile score={risk.score} tone={c.tone} />
          <div className="min-w-0">
            <h2 id="score-title" className="sr-only">
              Risk score {risk.score} of 100
            </h2>
            <div className="flex flex-wrap items-center gap-1.5">
              <RiskBadge category={risk.category} />
              <Tag>{risk.confidence === "high" ? "High" : risk.confidence === "medium" ? "Medium" : "Low"} confidence</Tag>
            </div>
            <p className="mt-1.5 text-[15px] font-semibold text-ink">{visible(report.verdict)}</p>
            {top && <p className="text-[13px] text-ink-3">Top finding: {top.title}</p>}
          </div>
        </div>
        <dl className="grid grid-cols-2 gap-x-7 gap-y-1 text-[13px] sm:grid-cols-3 xl:grid-flow-col xl:grid-cols-none xl:grid-rows-2">
          <dt className="text-ink-3">From</dt>
          <dd className="font-mono">{tx.from === "[redacted-sender]" ? <span className="font-sans text-ink-3">not stored</span> : <Hex value={tx.from} copy={false} />}</dd>
          <dt className="text-ink-3">To</dt>
          <dd className="font-mono">{tx.to ? <Hex value={tx.to} copy={false} /> : <span className="font-sans text-ink-3">contract creation</span>}</dd>
          <dt className="text-ink-3">Value</dt>
          <dd className="font-mono tabular-nums">
            {formatUnits(tx.value)} {nativeSymbol(tx.chainId)}
          </dd>
          <dt className="text-ink-3">Call</dt>
          <dd className="font-mono">
            {method ?? selector ?? "–"}
            {!report.decoded?.signature && selector && <span className="font-sans text-ink-3"> (unknown)</span>}
          </dd>
          <dt className="text-ink-3">Chain · block</dt>
          <dd className="font-mono">
            {tx.chainId} · {report.simulation?.blockNumber || tx.block}
          </dd>
        </dl>
        <div className="ml-auto">
          <ReportActions report={report} stored={stored} />
        </div>
      </div>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Left column: score breakdown and coverage

function ScoreBreakdown({ report }: { report: RiskReport }) {
  const sevByRule = new Map<string, Finding["severity"]>();
  for (const f of report.findings) {
    const cur = sevByRule.get(f.ruleId);
    if (!cur || SEVERITY[f.severity].rank > SEVERITY[cur].rank) sevByRule.set(f.ruleId, f.severity);
  }
  const groups = new Map<string, { points: number; n: number }>();
  for (const c of report.risk.contributions) {
    const key = c.ruleId || c.fingerprint;
    const g = groups.get(key) ?? { points: 0, n: 0 };
    g.points += c.points;
    g.n += 1;
    groups.set(key, g);
  }
  const rows = [...groups.entries()].filter(([, g]) => g.points > 0).sort((a, b) => b[1].points - a[1].points);
  const max = Math.max(1, ...rows.map(([, g]) => g.points));
  return (
    <Card title="Score breakdown" id="score-breakdown">
      {rows.length === 0 ? (
        <p className="text-[13px] text-ink-3">No finding contributed to the score.</p>
      ) : (
        <ul className="space-y-2.5">
          {rows.map(([rule, g]) => {
            const sev = sevByRule.get(rule);
            const fill = sev ? TONE_CLASSES[SEVERITY[sev].tone].fill : "fill-ink-3";
            return (
              <li key={rule}>
                <div className="flex items-baseline justify-between gap-2 font-mono text-[12px]">
                  <span className="text-ink-2">
                    {rule.replace(/^TXS-/, "")}
                    {g.n > 1 && <span className="text-ink-3"> ×{g.n}</span>}
                  </span>
                  <span className="tabular-nums text-ink">{g.points.toFixed(1)}</span>
                </div>
                <svg viewBox="0 0 100 6" preserveAspectRatio="none" className="mt-1 h-1.5 w-full" aria-hidden="true">
                  <rect x="0" y="0" width="100" height="6" rx="3" className="fill-line-2" />
                  <rect x="0" y="0" width={Math.max(2, (g.points / max) * 100)} height="6" rx="3" className={fill} />
                </svg>
              </li>
            );
          })}
        </ul>
      )}
      <p className="mt-4 text-[12px] leading-relaxed text-ink-3">
        Points combine as 100 × (1 − Π(1 − p)) and repeats within a rule are halved, so they do not add up to the score. Severe facts set a floor. Confidence reflects how
        complete the analysis was (simulation, contract checks), not how sure TxShield is that the transaction is safe.
      </p>
    </Card>
  );
}

function Coverage({ report }: { report: RiskReport }) {
  const sim = report.simulation;
  const failed = (report.warnings ?? []).filter((w) => /^rule \S+ did not complete/.test(w)).length;
  const total = report.enabledChecks.filter((c) => c.startsWith("TXS-")).length;
  const simLabel = !sim
    ? "not requested"
    : sim.status === "success"
      ? `${sim.completeness} · ${sim.backend}`
      : sim.status === "reverted"
        ? `reverted · ${sim.backend}`
        : sim.status === "not_run"
          ? "not run"
          : "could not run";
  const rows: [string, React.ReactNode][] = [
    ["Simulation", simLabel],
    ["Rules", total ? `${total - failed} / ${total} ran` : "–"],
    ...(sim && sim.gasUsed ? ([["Gas used", <span key="g" className="font-mono">{sim.gasUsed.toLocaleString("en-US")}</span>]] as [string, React.ReactNode][]) : []),
    ...(sim?.durationMs ? ([["Simulation time", `${sim.durationMs.toLocaleString("en-US")} ms`]] as [string, React.ReactNode][]) : []),
    ["Analyzed", <span key="a" className="font-mono text-[12px]">{formatDateTime(report.analyzedAt)}</span>],
  ];
  return (
    <Card title="Coverage" id="coverage">
      <dl className="grid grid-cols-[1fr_auto] gap-x-4 gap-y-2 text-[13px]">
        {rows.map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-ink-3">{k}</dt>
            <dd className="text-right text-ink">{v}</dd>
          </div>
        ))}
      </dl>
      <details className="mt-3 text-[12px]">
        <summary className="cursor-pointer text-ink-3 hover:text-ink">Enabled checks ({report.enabledChecks.length})</summary>
        <p className="mt-1.5 break-words font-mono text-ink-3">{report.enabledChecks.join(", ")}</p>
      </details>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Right column: wallet effects and execution

function UnverifiedMark() {
  return (
    <span className="text-ink-3" title="Symbol and decimals reported by the token contract, unverified">
      *
    </span>
  );
}

export function BalanceChangesTable({ changes, chainId }: { changes: BalanceChange[]; chainId: number }) {
  if (changes.length === 0) return <p className="px-4 py-3 text-[13px] text-ink-3">No balance changes for the sender.</p>;
  const anyUnverified = changes.some((b) => assetDisplay(b.asset, b.delta, chainId).unverified);
  const anyRaw = changes.some((b) => assetDisplay(b.asset, b.delta, chainId).raw);
  return (
    <>
      <TableWrap label="Balance changes">
        <table className="w-full border-collapse">
          <thead>
            <tr>
              <th scope="col" className={th}>
                Asset
              </th>
              <th scope="col" className={`${th} text-right`}>
                Before
              </th>
              <th scope="col" className={`${th} text-right`}>
                Change
              </th>
            </tr>
          </thead>
          <tbody>
            {changes.map((b, i) => {
              const d = assetDisplay(b.asset, b.delta, chainId);
              const before = assetDisplay(b.asset, b.before, chainId);
              const neg = b.delta.startsWith("-");
              return (
                <tr key={i}>
                  <td className={td}>
                    <div className="text-ink">
                      {d.name}
                      {d.unverified && <UnverifiedMark />}
                    </div>
                    <div className="font-mono text-[11px] text-ink-3">{b.asset.address ? shortHex(b.asset.address) : "native"}</div>
                  </td>
                  <td className={`${td} text-right font-mono tabular-nums text-ink-2`}>{before.amount}</td>
                  <td className={`${td} whitespace-nowrap text-right font-mono font-semibold tabular-nums ${neg ? "text-critical-ink" : "text-good-ink"}`}>
                    {neg ? "−" : "+"}
                    {d.amount.replace(/^-/, "")}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </TableWrap>
      {(anyUnverified || anyRaw) && (
        <p className="space-x-2 px-4 py-2.5 text-[11px] text-ink-3">
          {anyUnverified && <span>* symbol and decimals reported by the token contract, unverified.</span>}
          {anyRaw && <span>Amounts without decimals are raw base units.</span>}
        </p>
      )}
    </>
  );
}

function TransfersList({ transfers, chainId, sender }: { transfers: AssetTransfer[]; chainId: number; sender: string }) {
  // Stored reports may redact the sender; either way, name it instead of showing hex.
  const who = (a: string) =>
    a === "[redacted-sender]" || a.toLowerCase() === sender.toLowerCase() ? (
      <span className="font-sans text-ink">sender</span>
    ) : (
      <span title={a}>{shortHex(a)}</span>
    );
  return (
    <>
      <ol className="divide-y divide-line-2">
        {transfers.slice(0, 50).map((t, i) => {
          const d = assetDisplay(t.asset, t.amount, chainId);
          return (
            <li key={i} className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5 px-4 py-2 text-[13px]">
              <span className="font-mono text-[12px] text-ink-2">
                {who(t.from)} <span className="text-ink-3">→</span> {who(t.to)}
              </span>
              <span className="font-mono tabular-nums text-ink">
                {d.amount} {d.name}
                {d.unverified && <UnverifiedMark />}
              </span>
            </li>
          );
        })}
      </ol>
      {transfers.length > 50 && <p className="px-4 py-2 text-[11px] text-ink-3">Showing 50 of {transfers.length} transfers.</p>}
    </>
  );
}

function countFrames(f: CallFrame): number {
  return 1 + (f.calls ?? []).reduce((n, c) => n + countFrames(c), 0);
}

function TraceNode({ f, depth, last }: { f: CallFrame; depth: number; last: boolean }) {
  const sel = f.input && f.input.length >= 10 ? f.input.slice(0, 10).toLowerCase() : "";
  const name = sel ? KNOWN_SELECTORS[sel] : undefined;
  const short = f.type === "STATICCALL" ? "STATIC" : f.type === "DELEGATECALL" ? "DELEGATE" : f.type;
  const moves = f.value && f.value !== "0" && f.value !== "0x0";
  return (
    <li>
      <div className="flex flex-wrap items-baseline gap-x-1.5 whitespace-nowrap py-px">
        {depth > 0 && (
          <span aria-hidden="true" className="text-ink-3">
            {"  ".repeat(depth - 1)}
            {last ? "└" : "├"}
          </span>
        )}
        <span className={f.type === "DELEGATECALL" ? "font-semibold text-serious-ink" : "text-fact-ink"}>{short}</span>
        {f.to && <span title={f.to}>{shortHex(f.to)}</span>}
        {name ? <span className="text-ink-2">{name}</span> : sel ? <span className="text-ink-3">{sel}</span> : null}
        {moves && <span className="text-warning-ink">{formatUnits(f.value!)} native</span>}
        {f.error && <span className="whitespace-normal text-critical-ink">✕ {visible(f.revertReason || f.error, 120)}</span>}
      </div>
      {f.calls && f.calls.length > 0 && depth < 12 && (
        <ul>
          {f.calls.map((c, i) => (
            <TraceNode key={i} f={c} depth={depth + 1} last={i === f.calls!.length - 1} />
          ))}
        </ul>
      )}
    </li>
  );
}

function SimulationNotes({ sim }: { sim: SimulationResult }) {
  if (!sim.incompleteReasons?.length && !sim.notes?.length) return null;
  return (
    <ul className="space-y-1 border-t border-line-2 px-4 py-3 text-[12px] text-ink-3">
      {sim.incompleteReasons?.map((r, i) => <li key={`i${i}`}>Incomplete: {visible(r)}</li>)}
      {sim.notes?.map((n, i) => <li key={`n${i}`}>{visible(n)}</li>)}
    </ul>
  );
}

// ---------------------------------------------------------------------------
// Middle column extras

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
          <dt className="text-ink-3">
            {p.name} <span className="font-mono text-[11px]">{p.type}</span>
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
    <div className={depth > 0 ? "border-l border-line pl-3" : ""}>
      <div className="flex flex-wrap items-center gap-2 text-[13px]">
        {call.label && <span className="text-ink-3">{call.label}:</span>}
        <span className="break-all font-mono font-medium text-ink">{visible(heading, 300)}</span>
        {call.standard && <Tag>{call.standard}</Tag>}
        {call.callType !== "call" && <Tag tone="serious">{call.callType}</Tag>}
      </div>
      <div className="mt-2 space-y-2 text-[13px]">
        {call.target && (
          <p className="text-ink-3">
            Target <Hex value={call.target} />
          </p>
        )}
        {call.value && <p className="text-ink-3">Value {formatUnits(call.value)} (native)</p>}
        {call.params && call.params.length > 0 && <ParamList params={call.params} />}
        {call.candidates && call.candidates.length > 0 && <p className="text-ink-3">Other signatures with this selector: {call.candidates.join(", ")}</p>}
        {call.rawData && (
          <details>
            <summary className="cursor-pointer text-ink-3 hover:text-ink">Raw calldata ({(call.rawData.length - 2) / 2} bytes)</summary>
            <p className="mt-1 break-all font-mono text-[11px] text-ink-3">{call.rawData}</p>
          </details>
        )}
        {call.warnings?.map((w, i) => (
          <p key={i} className="text-serious-ink">
            <span aria-hidden="true">! </span>
            {visible(w)}
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
  if (approvals.length === 0)
    return (
      <div className="p-4">
        <EmptyState title="No token permissions">This transaction grants or revokes no permissions that TxShield recognizes.</EmptyState>
      </div>
    );
  const hasCurrent = approvals.some((a) => "current" in a && a.current);
  return (
    <TableWrap label="Token permissions">
      <table className="w-full min-w-[40rem] border-collapse">
        <thead>
          <tr>
            <th scope="col" className={th}>
              Permission
            </th>
            <th scope="col" className={th}>
              Token
            </th>
            <th scope="col" className={th}>
              Spender
            </th>
            <th scope="col" className={th}>
              Grants
            </th>
            {hasCurrent && (
              <th scope="col" className={th}>
                In force now
              </th>
            )}
          </tr>
        </thead>
        <tbody>
          {approvals.map((a, i) => {
            const cur = "current" in a ? a.current : undefined;
            return (
              <tr key={i}>
                <td className={td}>
                  <span className="text-ink">{a.kind.replaceAll("_", " ")}</span>
                  <div className="text-[11px] text-ink-3">
                    {a.ownerIsSender ? "your assets" : "intermediary contract"}
                    {a.signed ? " · signed permit" : ""}
                  </div>
                </td>
                <td className={td}>
                  <Hex value={a.token} />
                </td>
                <td className={td}>
                  <Hex value={a.spender} />
                </td>
                <td className={`${td} font-mono text-[13px] ${a.unlimited ? "text-critical-ink" : ""}`}>
                  {a.revocation ? "Revocation" : a.approved !== undefined ? (a.approved ? "All tokens (operator)" : "Revoke operator") : a.tokenId ? `Token #${a.tokenId}` : describeAmount(a.amount)}
                </td>
                {hasCurrent && (
                  <td className={`${td} font-mono text-[13px]`}>
                    {!cur
                      ? "–"
                      : cur.error
                        ? <span className="text-ink-3">{cur.error}</span>
                        : cur.approvedForAll !== undefined
                          ? cur.approvedForAll
                            ? "Operator approved"
                            : "None"
                          : cur.tokenApproved !== undefined
                            ? cur.tokenApproved
                              ? "Approved"
                              : "None"
                            : describeAmount(cur.amount)}
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

// ---------------------------------------------------------------------------
// The console

/** The full security report: summary bar over a three-column console. */
export function SecurityReport({ report, stored = false }: { report: RiskReport; stored?: boolean }) {
  const points: Record<string, number> = {};
  for (const c of report.risk.contributions) points[c.fingerprint] = (points[c.fingerprint] ?? 0) + c.points;
  const sim = report.simulation;
  const ran = sim && (sim.status === "success" || sim.status === "reverted");
  const counts = { fact: 0, heuristic: 0, external: 0 } as Record<Finding["source"], number>;
  for (const f of report.findings) counts[f.source] += 1;

  return (
    <div className="space-y-4">
      <SummaryBar report={report} points={points} stored={stored} />

      {sim?.status === "reverted" && (
        <Notice tone="critical" title="The transaction reverts in simulation">
          <p>
            Reason: <span className="font-mono">{sim.revertReason ? visible(sim.revertReason) : "none given"}</span>. A reverting transaction still costs gas if sent.
          </p>
        </Notice>
      )}
      {report.warnings && report.warnings.length > 0 && (
        <Notice tone="warning" title="Analysis limitations">
          <ul className="list-disc space-y-1 pl-5">
            {report.warnings.map((w, i) => (
              <li key={i}>{visible(w)}</li>
            ))}
          </ul>
        </Notice>
      )}

      <div className="grid grid-cols-1 items-start gap-4 lg:grid-cols-[minmax(0,1fr)_340px] xl:grid-cols-[280px_minmax(0,1fr)_360px]">
        <div className="order-3 grid min-w-0 gap-4 sm:grid-cols-2 lg:col-span-2 xl:order-1 xl:col-span-1 xl:grid-cols-1">
          <ScoreBreakdown report={report} />
          <Coverage report={report} />
        </div>

        <div className="order-1 min-w-0 space-y-4 xl:order-2">
          <Card
            title={`Findings · ${report.findings.length}`}
            id="findings"
            flush
            actions={
              report.findings.length > 0 && (
                <span className="flex gap-1.5">
                  {(Object.keys(counts) as Finding["source"][])
                    .filter((k) => counts[k] > 0)
                    .map((k) => (
                      <SourceBadge key={k} source={k} count={counts[k]} />
                    ))}
                </span>
              )
            }
          >
            <FindingsTable findings={report.findings} points={points} />
          </Card>
          <Card title="Recommended actions" id="recs">
            <ol className="list-decimal space-y-1.5 pl-5 text-[13px] text-ink-2 marker:text-ink-3">
              {report.recommendations.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ol>
          </Card>
          <Card title={`Token permissions · ${report.approvals.length}`} id="approvals" flush>
            <ApprovalsTable approvals={report.approvals} />
          </Card>
          {report.decoded && (
            <Card title="Decoded call" id="decoded">
              <DecodedCallTree call={report.decoded} />
            </Card>
          )}
        </div>

        <div className="order-2 min-w-0 space-y-4 xl:order-3">
          {ran && sim.status === "success" && (
            <Card title="Sender balance diff" id="balances" flush>
              <BalanceChangesTable changes={sim.balanceChanges ?? []} chainId={sim.chainId} />
            </Card>
          )}
          {ran && sim.assetTransfers && sim.assetTransfers.length > 0 && (
            <Card title={`Asset transfers · ${sim.assetTransfers.length}`} id="transfers" flush>
              <TransfersList transfers={sim.assetTransfers} chainId={sim.chainId} sender={report.transaction.from} />
            </Card>
          )}
          {sim && (
            <Card
              title="Call trace"
              id="trace"
              flush
              actions={sim.trace ? <span className="font-mono text-[11px] text-ink-3">{countFrames(sim.trace)} frames</span> : undefined}
            >
              {sim.trace ? (
                <div className="overflow-x-auto px-4 py-3">
                  <ul className="font-mono text-[12px] leading-[1.9] text-ink-2">
                    <TraceNode f={sim.trace} depth={0} last />
                  </ul>
                </div>
              ) : (
                <p className="px-4 py-3 text-[13px] text-ink-3">
                  {sim.status === "not_run" || sim.status === "error"
                    ? `Simulation ${sim.status === "error" ? "could not run" : "did not run"}; no trace.`
                    : stored
                      ? "Not kept in the stored copy (server privacy setting). Re-run the analysis to see the trace."
                      : "No trace available."}
                </p>
              )}
              <SimulationNotes sim={sim} />
            </Card>
          )}
        </div>
      </div>

      <p className="text-[12px] text-ink-3">
        {report.disclaimer} Report <span className="font-mono">{report.id}</span>
        {report.requestId ? (
          <>
            {" "}
            · request <span className="font-mono">{report.requestId}</span>
          </>
        ) : null}{" "}
        · engine {report.engineVersion} · network {report.transaction.chainName || chainName(report.transaction.chainId)}
      </p>
    </div>
  );
}
