import { describe, expect, it } from "vitest";
import { checkAuth, parseAuthConfig } from "@/lib/basicAuth";

const req = (authorization?: string) => ({ headers: new Headers(authorization ? { authorization } : {}) });
const basic = (s: string) => "Basic " + Buffer.from(s).toString("base64");
const cfg = parseAuthConfig("admin:correct-horse-battery");

describe("dashboard basic auth", () => {
  it("is off when unset", async () => {
    expect(parseAuthConfig(undefined)).toEqual({ kind: "off" });
    expect(await checkAuth(req(), { kind: "off" })).toBeUndefined();
  });

  it("rejects malformed or weak configuration and then fails closed", async () => {
    for (const raw of ["nocolon", ":password-is-long-enough", "admin:short"]) {
      expect(parseAuthConfig(raw).kind).toBe("invalid");
    }
    expect((await checkAuth(req(basic("admin:short")), { kind: "invalid" }))?.status).toBe(500);
  });

  it("accepts only the exact credentials", async () => {
    expect(cfg.kind).toBe("on");
    expect(await checkAuth(req(basic("admin:correct-horse-battery")), cfg)).toBeUndefined();
    for (const h of [undefined, basic("admin:correct-horse-batterY"), basic("admin:correct-horse-battery "), "Bearer x", "Basic !!!", basic("")]) {
      const res = await checkAuth(req(h), cfg);
      expect(res?.status, String(h)).toBe(401);
      expect(res?.headers.get("www-authenticate")).toMatch(/^Basic realm="TxShield"/);
    }
  });
});
