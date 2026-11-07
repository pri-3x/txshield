// Copies static assets next to the standalone server (Next.js does not do
// this itself; see the `output: "standalone"` docs).
import { cpSync, existsSync } from "node:fs";
const root = new URL("..", import.meta.url);
cpSync(new URL(".next/static", root), new URL(".next/standalone/.next/static", root), { recursive: true });
if (existsSync(new URL("public", root))) cpSync(new URL("public", root), new URL(".next/standalone/public", root), { recursive: true });
