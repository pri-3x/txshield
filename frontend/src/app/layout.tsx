import type { Metadata } from "next";
import Link from "next/link";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "TxShield", template: "%s · TxShield" },
  description: "EVM transaction security analysis and simulation",
  robots: { index: false, follow: false },
};

const nav = [
  { href: "/", label: "Dashboard" },
  { href: "/scan", label: "Scanner" },
  { href: "/address", label: "Address inspector" },
];

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className="font-sans antialiased">
        <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-10 focus:rounded focus:bg-surface focus:px-3 focus:py-2">
          Skip to content
        </a>
        <header className="border-b border-line bg-surface">
          <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-4 py-3">
            <Link href="/" className="flex items-center gap-2 font-semibold text-ink">
              <span aria-hidden="true" className="inline-block size-5 rounded bg-accent" />
              TxShield
            </Link>
            <nav aria-label="Main">
              <ul className="flex flex-wrap gap-1 text-sm">
                {nav.map((n) => (
                  <li key={n.href}>
                    <Link href={n.href} className="rounded px-3 py-1.5 text-ink-2 hover:bg-surface-2 hover:text-ink">
                      {n.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </nav>
          </div>
        </header>
        <main id="main" className="mx-auto max-w-6xl px-4 py-6">
          {children}
        </main>
        <footer className="mx-auto max-w-6xl px-4 pb-8 text-xs text-ink-3">
          TxShield never signs or broadcasts transactions. Results describe what the enabled checks observed and are not a guarantee of safety.
        </footer>
      </body>
    </html>
  );
}
