"use client";

export default function ErrorPage({ reset }: { error: Error; reset: () => void }) {
  return (
    <div role="alert" className="space-y-3">
      <h1 className="text-2xl font-semibold text-ink">Something went wrong</h1>
      <p className="text-ink-2">The page could not be rendered. No transaction was signed or sent.</p>
      <button type="button" onClick={reset} className="rounded-md border border-line px-3 py-1.5 text-sm hover:bg-surface-2">
        Try again
      </button>
    </div>
  );
}
