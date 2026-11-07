/**
 * Horizontal single-series bar chart in SVG (no style attributes, so the
 * strict CSP needs no 'unsafe-inline'). Follows the data-viz mark specs:
 * one hue, <=24px bars with a 4px rounded data end and square baseline,
 * direct value labels, a native tooltip per bar, and a table view.
 */
export interface Bar {
  label: string;
  value: number;
  hint?: string;
}

// Sized so the chart renders near 1:1 in a phone-width or half-width card,
// keeping 12px labels legible instead of scaling them down.
const BAR_H = 16;
const GAP = 14;
const LABEL_W = 118;
const VALUE_W = 44;
const PLOT_W = 178;

export function BarChart({ title, bars, unit = "" }: { title: string; bars: Bar[]; unit?: string }) {
  const max = Math.max(1, ...bars.map((b) => b.value));
  const height = bars.length * (BAR_H + GAP);
  const width = LABEL_W + PLOT_W + VALUE_W;
  return (
    <figure>
      <svg viewBox={`0 0 ${width} ${height}`} className="w-full max-w-[34rem]" role="img" aria-label={`${title}: ${bars.map((b) => `${b.label} ${b.value}${unit}`).join(", ")}`}>
        <line x1={LABEL_W} x2={LABEL_W} y1={0} y2={height} className="stroke-line" strokeWidth={1} />
        {bars.map((b, i) => {
          const y = i * (BAR_H + GAP) + GAP / 2;
          const w = b.value === 0 ? 0 : Math.max(2, (b.value / max) * PLOT_W);
          const r = Math.min(4, w / 2);
          // Rounded data end, square baseline.
          const path = w === 0 ? "" : `M${LABEL_W},${y} h${w - r} a${r},${r} 0 0 1 ${r},${r} v${BAR_H - 2 * r} a${r},${r} 0 0 1 ${-r},${r} h${-(w - r)} z`;
          return (
            <g key={b.label} tabIndex={0} aria-label={`${b.label}: ${b.value}${unit}`} className="outline-none focus-visible:[&>rect]:stroke-ink">
              <title>{`${b.label}: ${b.value.toLocaleString("en-US")}${unit}${b.hint ? ` (${b.hint})` : ""}`}</title>
              {/* Full-row hit target, larger than the mark. */}
              <rect x={0} y={y - GAP / 2} width={width} height={BAR_H + GAP} className="fill-transparent" strokeWidth={1} />
              <text x={LABEL_W - 8} y={y + BAR_H / 2} dominantBaseline="central" textAnchor="end" className="fill-ink-2 text-[12px]">
                {b.label}
              </text>
              {path && <path d={path} className="fill-[var(--bar)]" />}
              <text x={LABEL_W + w + 6} y={y + BAR_H / 2} dominantBaseline="central" className="fill-ink text-[12px] tabular-nums">
                {b.value.toLocaleString("en-US")}
                {unit}
              </text>
            </g>
          );
        })}
      </svg>
      <details className="mt-2 text-sm">
        <summary className="cursor-pointer text-ink-2">Show as table</summary>
        <table className="mt-2 w-full border-collapse text-sm">
          <caption className="sr-only">{title}</caption>
          <thead>
            <tr>
              <th scope="col" className="border-b border-line py-1 text-left font-medium text-ink-2">
                Category
              </th>
              <th scope="col" className="border-b border-line py-1 text-right font-medium text-ink-2">
                Count
              </th>
            </tr>
          </thead>
          <tbody>
            {bars.map((b) => (
              <tr key={b.label}>
                <td className="border-b border-line py-1">{b.label}</td>
                <td className="border-b border-line py-1 text-right tabular-nums">{b.value.toLocaleString("en-US")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </figure>
  );
}
