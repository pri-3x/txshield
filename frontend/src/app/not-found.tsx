import Link from "next/link";

export default function NotFound() {
  return (
    <div className="space-y-2">
      <h1 className="text-2xl font-semibold text-ink">Not found</h1>
      <p className="text-ink-2">The page or analysis does not exist, or the analysis has expired under the server&apos;s retention policy.</p>
      <Link href="/" className="text-accent-ink hover:underline">
        Back to the dashboard
      </Link>
    </div>
  );
}
