import type { ReactNode } from "react";
import type { Confidence, Finding, RiskCategory, Severity } from "@txshield/sdk";
import { CATEGORY, CONFIDENCE_LABEL, SEVERITY, TONE_CLASSES, type Tone } from "@/lib/risk";
import { shortHex } from "@/lib/format";
import { CopyButton } from "./CopyButton";

export function Card({ title, children, actions, id, className = "" }: { title?: ReactNode; children: ReactNode; actions?: ReactNode; id?: string; className?: string }) {
  const headingId = id ? `${id}-title` : undefined;
  return (
    <section aria-labelledby={headingId} className={`rounded-lg border border-line bg-surface p-4 sm:p-5 ${className}`}>
      {(title || actions) && (
        <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2">
          {title && (
            <h2 id={headingId} className="text-base font-semibold text-ink">
              {title}
            </h2>
          )}
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}

function ToneBadge({ tone, icon, children, title }: { tone: Tone; icon?: string; children: ReactNode; title?: string }) {
  const t = TONE_CLASSES[tone];
  return (
    <span title={title} className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-xs font-medium ${t.border} ${t.text}`}>
      {icon ? <span aria-hidden="true">{icon}</span> : <span aria-hidden="true" className={`size-2 rounded-full ${t.dot}`} />}
      {children}
    </span>
  );
}

export function RiskBadge({ category, score }: { category: RiskCategory; score?: number }) {
  const c = CATEGORY[category];
  return (
    <ToneBadge tone={c.tone} icon={c.icon} title={`Score range ${c.range}`}>
      {c.label}
      {score !== undefined && <span className="tabular-nums">· {score}</span>}
    </ToneBadge>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const s = SEVERITY[severity];
  return <ToneBadge tone={s.tone}>{s.label}</ToneBadge>;
}

export function ConfidenceText({ confidence }: { confidence: Confidence }) {
  return <span className="text-xs text-ink-2">{CONFIDENCE_LABEL[confidence]}</span>;
}

const SOURCE: Record<Finding["source"], { label: string; hint: string }> = {
  fact: { label: "Fact", hint: "Observed directly in calldata, chain state, simulation, or an operator list" },
  heuristic: { label: "Heuristic", hint: "Inferred from a pattern; may be wrong" },
  external: { label: "External", hint: "Opinion of a third-party reputation source" },
};

export function SourceBadge({ source }: { source: Finding["source"] }) {
  const s = SOURCE[source];
  return (
    <span title={s.hint} className="rounded border border-line px-1.5 py-0.5 text-xs text-ink-2">
      {s.label}
    </span>
  );
}

/** An address or hash: monospace, shortened on small screens, copyable. */
export function Hex({ value, short = true, copy = true }: { value: string; short?: boolean; copy?: boolean }) {
  if (!value) return <span className="text-ink-3">–</span>;
  return (
    <span className="inline-flex max-w-full items-center gap-1 align-middle">
      <code className="truncate font-mono text-[0.8125rem] text-ink" title={value}>
        {short ? (
          <>
            <span className="sm:hidden">{shortHex(value)}</span>
            <span className="hidden sm:inline">{value}</span>
          </>
        ) : (
          value
        )}
      </code>
      {copy && <CopyButton value={value} />}
    </span>
  );
}

export function KeyValue({ items }: { items: [ReactNode, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-[max-content_1fr]">
      {items.map(([k, v], i) => (
        <div key={i} className="contents">
          <dt className="text-ink-2">{k}</dt>
          <dd className="min-w-0 break-words text-ink">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Notice({ tone = "neutral", title, children }: { tone?: Tone; title: string; children?: ReactNode }) {
  const t = TONE_CLASSES[tone];
  return (
    <div role={tone === "critical" ? "alert" : "status"} className={`rounded-md border-l-4 ${t.border} bg-surface-2 px-4 py-3 text-sm`}>
      <p className="font-medium text-ink">{title}</p>
      {children && <div className="mt-1 text-ink-2">{children}</div>}
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="rounded-md border border-dashed border-line px-4 py-8 text-center text-sm">
      <p className="font-medium text-ink">{title}</p>
      {children && <div className="mt-1 text-ink-2">{children}</div>}
    </div>
  );
}

export function TableWrap({ children, label }: { children: ReactNode; label: string }) {
  return (
    // "(scrollable table)" keeps the region's name distinct from its card's heading.
    <div role="region" aria-label={`${label} (scrollable table)`} tabIndex={0} className="-mx-4 overflow-x-auto px-4 sm:mx-0 sm:px-0">
      {children}
    </div>
  );
}

export const th = "border-b border-line py-2 pr-4 text-left text-xs font-medium uppercase tracking-wide text-ink-2";
export const td = "border-b border-line py-2 pr-4 align-top text-sm";
