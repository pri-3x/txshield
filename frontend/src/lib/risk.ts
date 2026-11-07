import type { Confidence, RiskCategory, Severity } from "@txshield/sdk";

export type Tone = "good" | "warning" | "serious" | "critical" | "neutral";

/** Risk bands map onto the fixed status palette; high and critical share
 * the critical hue and are told apart by their label and icon. */
export const CATEGORY: Record<RiskCategory, { label: string; tone: Tone; icon: string; range: string }> = {
  low: { label: "Low observed risk", tone: "good", icon: "○", range: "0–19" },
  moderate: { label: "Moderate", tone: "warning", icon: "◔", range: "20–39" },
  elevated: { label: "Elevated", tone: "serious", icon: "◑", range: "40–59" },
  high: { label: "High", tone: "critical", icon: "◕", range: "60–79" },
  critical: { label: "Critical", tone: "critical", icon: "●", range: "80–100" },
};

export const CATEGORY_ORDER: RiskCategory[] = ["low", "moderate", "elevated", "high", "critical"];

export const SEVERITY: Record<Severity, { label: string; tone: Tone }> = {
  info: { label: "Info", tone: "neutral" },
  low: { label: "Low", tone: "good" },
  medium: { label: "Medium", tone: "warning" },
  high: { label: "High", tone: "serious" },
  critical: { label: "Critical", tone: "critical" },
};

export const CONFIDENCE_LABEL: Record<Confidence, string> = { low: "Low confidence", medium: "Medium confidence", high: "High confidence" };

/** Tailwind classes per tone: a colored marker plus ink-colored text. */
export const TONE_CLASSES: Record<Tone, { dot: string; text: string; border: string }> = {
  good: { dot: "bg-good", text: "text-good-ink", border: "border-good" },
  warning: { dot: "bg-warning", text: "text-warning-ink", border: "border-warning" },
  serious: { dot: "bg-serious", text: "text-serious-ink", border: "border-serious" },
  critical: { dot: "bg-critical", text: "text-critical-ink", border: "border-critical" },
  neutral: { dot: "bg-ink-3", text: "text-ink-2", border: "border-line" },
};
