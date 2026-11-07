import type { Confidence, RiskCategory, Severity } from "@txshield/sdk";

export type Tone = "good" | "warning" | "serious" | "critical" | "neutral";

/** Risk bands map onto the fixed status palette. Each also has a distinct
 * label and icon, so the band is never conveyed by color alone. */
export const CATEGORY: Record<RiskCategory, { label: string; short: string; tone: Tone; icon: string; range: string }> = {
  low: { label: "Low observed risk", short: "Low", tone: "good", icon: "○", range: "0–19" },
  moderate: { label: "Moderate", short: "Moderate", tone: "warning", icon: "◔", range: "20–39" },
  elevated: { label: "Elevated", short: "Elevated", tone: "serious", icon: "◑", range: "40–59" },
  high: { label: "High", short: "High", tone: "serious", icon: "◕", range: "60–79" },
  critical: { label: "Critical", short: "Critical", tone: "critical", icon: "●", range: "80–100" },
};

export const CATEGORY_ORDER: RiskCategory[] = ["low", "moderate", "elevated", "high", "critical"];

export const SEVERITY: Record<Severity, { label: string; tone: Tone; rank: number }> = {
  info: { label: "Info", tone: "neutral", rank: 0 },
  low: { label: "Low", tone: "neutral", rank: 1 },
  medium: { label: "Medium", tone: "warning", rank: 2 },
  high: { label: "High", tone: "serious", rank: 3 },
  critical: { label: "Critical", tone: "critical", rank: 4 },
};

export const CONFIDENCE_LABEL: Record<Confidence, string> = { low: "Low confidence", medium: "Medium confidence", high: "High confidence" };
export const CONFIDENCE_SHORT: Record<Confidence, string> = { low: "low", medium: "med", high: "high" };

/** Tailwind classes per tone: marker fill, text ink, border, tag. */
export const TONE_CLASSES: Record<Tone, { dot: string; text: string; border: string; tag: string; fill: string }> = {
  good: { dot: "bg-good", text: "text-good-ink", border: "border-good", tag: "bg-good-bg text-good-ink", fill: "fill-good" },
  warning: { dot: "bg-warning", text: "text-warning-ink", border: "border-warning", tag: "bg-warning-bg text-warning-ink", fill: "fill-warning" },
  serious: { dot: "bg-serious", text: "text-serious-ink", border: "border-serious", tag: "bg-serious-bg text-serious-ink", fill: "fill-serious" },
  critical: { dot: "bg-critical", text: "text-critical-ink", border: "border-critical", tag: "bg-critical-bg text-critical-ink", fill: "fill-critical" },
  neutral: { dot: "bg-ink-3", text: "text-ink-2", border: "border-line", tag: "bg-neutral-bg text-neutral-ink", fill: "fill-ink-3" },
};
