import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  esbuild: { jsx: "automatic" },
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)), "server-only": fileURLToPath(new URL("./test/server-only-stub.ts", import.meta.url)) } },
  test: { environment: "jsdom", include: ["test/**/*.test.{ts,tsx}"] },
});
