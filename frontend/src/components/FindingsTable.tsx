"use client";

import { Fragment, useState } from "react";
import type { Finding } from "@txshield/sdk";
import { CONFIDENCE_LABEL, CONFIDENCE_SHORT, SEVERITY } from "@/lib/risk";
import { shortHex, visible } from "@/lib/format";
import { EmptyState, SeverityBadge, SourceBadge } from "./ui";

/**
 * Findings as a dense table, most severe first. Each row expands to its
 * description, evidence, mitigation, and false-positive notes; the first row
 * starts expanded.
 */
export function FindingsTable({ findings, points }: { findings: Finding[]; points: Record<string, number> }) {
  const rows = [...findings].sort(
    (a, b) => SEVERITY[b.severity].rank - SEVERITY[a.severity].rank || (points[b.fingerprint] ?? 0) - (points[a.fingerprint] ?? 0),
  );
  const [open, setOpen] = useState<Set<string>>(() => new Set(rows[0] ? [rows[0].fingerprint] : []));

  if (rows.length === 0) {
    return (
      <div className="p-4">
        <EmptyState title="No findings from enabled checks">This does not mean the transaction is safe; see the analysis limitations.</EmptyState>
      </div>
    );
  }
  const toggle = (fp: string) =>
    setOpen((s) => {
      const n = new Set(s);
      if (n.has(fp)) n.delete(fp);
      else n.add(fp);
      return n;
    });

  const th = "whitespace-nowrap border-b border-line px-3 py-2.5 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-ink-3";
  return (
    <div role="region" aria-label="Findings (scrollable table)" tabIndex={0} className="overflow-x-auto">
      <table className="w-full min-w-[36rem] border-collapse">
        <thead>
          <tr>
            <th scope="col" className={`${th} w-24 pl-4`}>
              Severity
            </th>
            <th scope="col" className={th}>
              Finding
            </th>
            <th scope="col" className={`${th} w-24`}>
              Source
            </th>
            <th scope="col" className={`${th} w-16`}>
              Conf
            </th>
            <th scope="col" className={`${th} w-16 pr-4 text-right`}>
              Pts
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((f, i) => {
            const isOpen = open.has(f.fingerprint);
            const detailsId = `finding-${i}`;
            const pts = points[f.fingerprint];
            const subject = f.subjects?.[0];
            return (
              <Fragment key={f.fingerprint}>
                <tr className={isOpen ? "bg-surface-2" : "hover:bg-surface-2/60"}>
                  <td className="border-b border-line-2 py-2.5 pl-4 pr-3 align-top">
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td className="border-b border-line-2 px-3 py-2 align-top">
                    <button
                      type="button"
                      aria-expanded={isOpen}
                      aria-controls={detailsId}
                      onClick={() => toggle(f.fingerprint)}
                      className="group flex w-full items-start gap-2 text-left"
                    >
                      <span aria-hidden="true" className={`mt-0.5 text-[10px] text-ink-3 transition-transform ${isOpen ? "rotate-90" : ""}`}>
                        ▶
                      </span>
                      <span className="min-w-0">
                        <span className="block font-medium text-ink group-hover:text-accent-ink">{f.title}</span>
                        <span className="mt-0.5 block font-mono text-[11px] text-ink-3">
                          {f.ruleId}
                          {subject ? ` · ${shortHex(visible(subject, 66))}` : ""}
                        </span>
                      </span>
                    </button>
                  </td>
                  <td className="border-b border-line-2 px-3 py-2.5 align-top">
                    <SourceBadge source={f.source} />
                  </td>
                  <td className="border-b border-line-2 px-3 py-2.5 align-top text-[13px] text-ink-2">
                    <span title={CONFIDENCE_LABEL[f.confidence]}>{CONFIDENCE_SHORT[f.confidence]}</span>
                  </td>
                  <td className="border-b border-line-2 py-2.5 pl-3 pr-4 text-right align-top font-mono text-[13px] tabular-nums text-ink">{pts === undefined ? "–" : pts.toFixed(1)}</td>
                </tr>
                {isOpen && (
                  <tr className="bg-surface-2">
                    <td className="border-b border-line-2" />
                    <td id={detailsId} colSpan={4} className="border-b border-line-2 px-3 pb-4 pr-4 pt-1">
                      <div className="space-y-3 text-[13px] leading-relaxed">
                        <p className="text-ink-2">{visible(f.description, 2000)}</p>
                        {f.evidence && f.evidence.length > 0 && (
                          <div className="rounded-lg border border-line bg-page px-3 py-2.5">
                            <h3 className="mb-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-ink-3">Evidence</h3>
                            <ul className="space-y-1.5">
                              {f.evidence.map((e, j) => (
                                <li key={j} className="break-words">
                                  <span className="font-mono text-[12px] text-ink-2">{visible(e.detail, 1000)}</span>
                                  <span className="ml-2 text-[11px] text-ink-3">
                                    {e.type} · {e.source}
                                  </span>
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
                            <span className="text-ink-3">{f.falsePositiveNotes}</span>
                          </p>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
