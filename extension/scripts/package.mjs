// Packs the extension into dist/txshield-extension-<version>.zip (runtime files only).
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync } from "node:fs";

const { version } = JSON.parse(readFileSync(new URL("../manifest.json", import.meta.url)));
const out = `dist/txshield-extension-${version}.zip`;
mkdirSync("dist", { recursive: true });
rmSync(out, { force: true });
execFileSync("zip", ["-r", "-X", out, "manifest.json", "src", "-x", "*.DS_Store"], { stdio: "inherit" });
console.log(`wrote ${out}`);
