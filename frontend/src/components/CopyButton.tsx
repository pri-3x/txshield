"use client";

import { useState } from "react";

export function CopyButton({ value }: { value: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        } catch {
          // Clipboard unavailable (insecure context); the value stays selectable.
        }
      }}
      className="shrink-0 rounded px-1 text-xs text-ink-3 hover:bg-surface-2 hover:text-ink"
      aria-label={done ? "Copied" : `Copy ${value}`}
      title="Copy"
    >
      {done ? "✓" : "⧉"}
    </button>
  );
}
