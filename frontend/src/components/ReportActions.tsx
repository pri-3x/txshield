"use client";

import { useState } from "react";
import type { RiskReport } from "@txshield/sdk";
import { btnSecondary } from "./ui";

/** Copy-link (stored reports) and JSON download, both client-side. */
export function ReportActions({ report, stored }: { report: RiskReport; stored: boolean }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex flex-wrap gap-2">
      {stored && (
        <button
          type="button"
          className={btnSecondary}
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(`${window.location.origin}/analyses/${report.id}`);
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            } catch {
              // Clipboard unavailable; the URL is in the address bar.
            }
          }}
        >
          {copied ? "Link copied" : "Copy link"}
        </button>
      )}
      <button
        type="button"
        className={btnSecondary}
        onClick={() => {
          const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = `txshield-report-${report.id}.json`;
          a.click();
          setTimeout(() => URL.revokeObjectURL(url), 1000);
        }}
      >
        Download JSON
      </button>
    </div>
  );
}
