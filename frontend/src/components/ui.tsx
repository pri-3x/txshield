import type { ReactNode } from "react";
import type { Confidence, Finding, RiskCategory, Severity } from "@txshield/sdk";
import { CATEGORY, CONFIDENCE_LABEL, SEVERITY, TONE_CLASSES, type Tone } from "@/lib/risk";
import { shortHex } from "@/lib/format";
import { CopyButton } from "./CopyButton";

/**
 * Console panel: an uppercase header bar and a body. `flush` removes body
 * padding for tables and lists that run edge to edge.
 */
export function Card({
  title,
  children,
  actions,
  id,
  className = "",
  flush = false,
}: {
  title?: ReactNode;
  children: ReactNode;
  actions?: ReactNode;
  id?: string;
  className?: string;
  flush?: boolean;
}) {
  const headingId = id ? `${id}-title` : undefined;
  return (
    <section aria-labelledby={headingId} className={`min-w-0 rounded-xl border border-line bg-surface ${className}`}>
      {(title || actions) && (
        <div className="flex min-h-11 flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-2">
          {title && (
            <h2 id={headingId} className="text-xs font-semibold uppercase tracking-[0.06em] text-ink-3">
              {title}
            </h2>
          )}
          {actions}
        </div>
      )}
      <div className={flush ? "" : "p-4"}>{children}</div>
    </section>
  );
}

/** A compact rectangular label. Meaning is always in the text, never the color alone. */
export function Tag({ tone = "neutral", children, title, className = "" }: { tone?: Tone; children: ReactNode; title?: string; className?: string }) {
  return (
    <span title={title} className={`inline-flex h-5 items-center gap-1 whitespace-nowrap rounded-[5px] px-1.5 text-[11px] font-semibold ${TONE_CLASSES[tone].tag} ${className}`}>
      {children}
    </span>
  );
}

export function RiskBadge({ category, score }: { category: RiskCategory; score?: number }) {
  const c = CATEGORY[category];
  return (
    <Tag tone={c.tone} title={`Score range ${c.range}`}>
      <span aria-hidden="true">{c.icon}</span>
      <span className="uppercase tracking-wide">{c.short}</span>
      {score !== undefined && <span className="tabular-nums">{score}</span>}
    </Tag>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const s = SEVERITY[severity];
  return (
    <Tag tone={s.tone} className="uppercase tracking-wide">
      {s.label}
    </Tag>
  );
}

export function ConfidenceText({ confidence }: { confidence: Confidence }) {
  return <span className="text-xs text-ink-3">{CONFIDENCE_LABEL[confidence]}</span>;
}

const SOURCE: Record<Finding["source"], { label: string; hint: string; cls: string }> = {
  fact: { label: "fact", hint: "Observed directly in calldata, chain state, simulation, or an operator list", cls: "bg-fact-bg text-fact-ink" },
  heuristic: { label: "heuristic", hint: "Inferred from a pattern; may be wrong", cls: "bg-heur-bg text-heur-ink" },
  external: { label: "external", hint: "Opinion of a third-party reputation source", cls: "bg-ext-bg text-ext-ink" },
};

export function SourceBadge({ source, count }: { source: Finding["source"]; count?: number }) {
  const s = SOURCE[source];
  return (
    <span title={s.hint} className={`inline-flex h-5 items-center gap-1 whitespace-nowrap rounded-[5px] px-1.5 text-[11px] font-semibold ${s.cls}`}>
      {s.label}
      {count !== undefined && <span className="tabular-nums">{count}</span>}
    </span>
  );
}

/** An address or hash: monospace, shortened, full value in the tooltip, copyable. */
export function Hex({ value, short = true, copy = true, className = "" }: { value: string; short?: boolean; copy?: boolean; className?: string }) {
  if (!value) return <span className="text-ink-3">–</span>;
  return (
    <span className={`inline-flex max-w-full items-center gap-1 align-middle ${className}`}>
      <code className={`font-mono text-[0.8125rem] text-ink ${short ? "whitespace-nowrap" : "break-all"}`} title={value}>
        {short ? shortHex(value) : value}
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
          <dt className="text-ink-3">{k}</dt>
          <dd className="min-w-0 break-words text-ink">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

const NOTICE_ICON: Record<Tone, string> = { critical: "✕", serious: "!", warning: "!", good: "✓", neutral: "i" };

export function Notice({ tone = "neutral", title, children }: { tone?: Tone; title: string; children?: ReactNode }) {
  const t = TONE_CLASSES[tone];
  return (
    <div role={tone === "critical" ? "alert" : "status"} className="flex gap-3 rounded-xl border border-line bg-surface px-4 py-3 text-sm">
      <span aria-hidden="true" className={`mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-[5px] text-xs font-bold ${t.tag}`}>
        {NOTICE_ICON[tone]}
      </span>
      <div className="min-w-0">
        <p className="font-medium text-ink">{title}</p>
        {children && <div className="mt-1 text-ink-2">{children}</div>}
      </div>
    </div>
  );
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="rounded-lg border border-dashed border-line px-4 py-8 text-center text-sm">
      <p className="font-medium text-ink">{title}</p>
      {children && <div className="mt-1 text-ink-3">{children}</div>}
    </div>
  );
}

export function TableWrap({ children, label }: { children: ReactNode; label: string }) {
  return (
    // "(scrollable table)" keeps the region's name distinct from its panel's heading.
    <div role="region" aria-label={`${label} (scrollable table)`} tabIndex={0} className="overflow-x-auto">
      {children}
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold tracking-tight text-ink">{title}</h1>
        {subtitle && <p className="mt-0.5 text-sm text-ink-3">{subtitle}</p>}
      </div>
      {actions}
    </div>
  );
}

export const btnPrimary = "inline-flex h-9 items-center gap-2 rounded-lg bg-btn px-3.5 text-sm font-medium text-white hover:bg-btn-hover disabled:opacity-60";
export const btnSecondary = "inline-flex h-9 items-center gap-2 rounded-lg border border-line bg-surface-2 px-3.5 text-sm font-medium text-ink hover:border-ink-3";
export const inputClass =
  "w-full rounded-lg border border-line bg-page px-3 py-2 text-sm text-ink placeholder:text-ink-3 focus:border-accent aria-[invalid=true]:border-critical";

export const th = "whitespace-nowrap border-b border-line px-4 py-2.5 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-ink-3";
export const td = "border-b border-line-2 px-4 py-2.5 align-top text-sm";
