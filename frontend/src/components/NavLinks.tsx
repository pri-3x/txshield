"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const NAV = [
  { href: "/", label: "Overview", match: (p: string) => p === "/" },
  { href: "/scan", label: "Scanner", match: (p: string) => p.startsWith("/scan") },
  { href: "/analyses", label: "History", match: (p: string) => p.startsWith("/analyses") },
  { href: "/address", label: "Addresses", match: (p: string) => p.startsWith("/address") },
];

export function NavLinks() {
  const path = usePathname() ?? "/";
  return (
    <ul className="flex flex-wrap gap-0.5 text-[13px]">
      {NAV.map((n) => {
        const active = n.match(path);
        return (
          <li key={n.href}>
            <Link
              href={n.href}
              aria-current={active ? "page" : undefined}
              className={`block rounded-md px-2.5 py-2 ${active ? "bg-surface-2 text-ink" : "text-ink-3 hover:bg-surface hover:text-ink"}`}
            >
              {n.label}
            </Link>
          </li>
        );
      })}
    </ul>
  );
}
