import type { Metadata } from "next";
import Link from "next/link";
import type { ReactNode } from "react";
import { NavLinks } from "@/components/NavLinks";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "TxShield", template: "%s · TxShield" },
  description: "EVM transaction security analysis and simulation",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className="font-sans text-[14px] antialiased">
        <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-3 focus:z-10 focus:rounded-md focus:bg-surface-2 focus:px-3 focus:py-2">
          Skip to content
        </a>
        <header className="border-b border-line-2 bg-page">
          <div className="mx-auto flex min-h-13 max-w-[1600px] flex-wrap items-center gap-x-6 gap-y-2 px-4 py-2 sm:px-5">
            <Link href="/" className="flex items-center gap-2 text-[15px] font-bold text-ink">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path d="M12 2.5 4 5.5v6c0 4.7 3.3 8.6 8 10 4.7-1.4 8-5.3 8-10v-6l-8-3Z" className="stroke-accent" strokeWidth="2" strokeLinejoin="round" />
                <path d="m8.8 12 2.2 2.2 4.2-4.4" className="stroke-accent" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              TxShield
            </Link>
            <nav aria-label="Main">
              <NavLinks />
            </nav>
            <form action="/go" method="get" role="search" className="ml-auto flex w-full max-w-sm items-center gap-2 rounded-lg border border-line bg-surface px-2.5 sm:w-auto sm:min-w-80">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true" className="shrink-0">
                <circle cx="11" cy="11" r="7" className="stroke-ink-3" strokeWidth="2" />
                <path d="m20 20-4-4" className="stroke-ink-3" strokeWidth="2" strokeLinecap="round" />
              </svg>
              <label htmlFor="global-search" className="sr-only">
                Search by transaction hash, address, or analysis ID
              </label>
              <input
                id="global-search"
                name="q"
                type="search"
                placeholder="Tx hash, address, or analysis ID"
                autoComplete="off"
                spellCheck={false}
                className="h-8 min-w-0 flex-1 bg-transparent text-[13px] text-ink outline-none placeholder:text-ink-3"
              />
            </form>
          </div>
        </header>
        <main id="main" className="mx-auto max-w-[1600px] px-4 py-4 sm:px-5">
          {children}
        </main>
        <footer className="mx-auto max-w-[1600px] px-4 pb-6 text-xs text-ink-3 sm:px-5">
          TxShield never signs or broadcasts transactions. Results describe what the enabled checks observed and are not a guarantee of safety.
        </footer>
      </body>
    </html>
  );
}
