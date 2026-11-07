import { describe, expect, it } from "vitest";
import { describeAmount, formatUnits, groupDigits, shortHex, visible } from "@/lib/format";
import { searchTarget } from "@/lib/search";

describe("formatUnits (exact bigint math)", () => {
  it.each([
    ["1000000000000000000", "1"],
    ["1500000000000000000", "1.5"],
    ["-1500000000000000000", "-1.5"],
    ["123456789000000000000000", "123,456.789"],
    ["0", "0"],
    ["1", "<0.000001"],
    ["-1", "-<0.000001"],
    ["1000000000001", "0.000001"],
    ["not a number", "not a number"],
  ])("%s -> %s", (input, out) => expect(formatUnits(input)).toBe(out));

  it("does not lose precision beyond 2^53", () => {
    expect(formatUnits("9007199254740993000000000000000000", 18)).toBe("9,007,199,254,740,993");
  });
});

describe("amounts and hex", () => {
  it("names unlimited sentinels", () => {
    expect(describeAmount(((1n << 256n) - 1n).toString())).toMatch(/Unlimited/);
    expect(describeAmount(((1n << 160n) - 1n).toString())).toMatch(/Permit2/);
    expect(describeAmount("1000000")).toBe("1,000,000");
    expect(groupDigits("-1234567")).toBe("-1,234,567");
  });
  it("shortens long hex", () => {
    expect(shortHex("0x1111111111111111111111111111111111111111")).toBe("0x1111…1111");
    expect(shortHex("0x12")).toBe("0x12");
  });
});

describe("visible (untrusted text)", () => {
  it("exposes bidi overrides, zero-width and control characters", () => {
    expect(visible("pay‮evil")).toBe("pay\\u202eevil");
    expect(visible("a​b")).toBe("a\\u200bb");
    expect(visible("line1\u0007")).toBe("line1\\u0007");
    expect(visible("normal text ü")).toBe("normal text ü");
  });
  it("truncates and tolerates empty input", () => {
    expect(visible("x".repeat(10), 4)).toBe("xxxx…");
    expect(visible(undefined)).toBe("");
  });
});


describe("searchTarget", () => {
  it("routes each input shape and rejects the rest", () => {
    expect(searchTarget(" 14C8FB93-BA82-4835-B732-00717E2E583F ", 1)).toBe("/analyses/14c8fb93-ba82-4835-b732-00717e2e583f");
    expect(searchTarget("0x" + "ab".repeat(32), 31337)).toBe(`/scan?hash=0x${"ab".repeat(32)}&chainId=31337`);
    expect(searchTarget("0x70997970C51812dc3A010C7d01b50e0d17dc79C8", 1)).toBe("/address?address=0x70997970C51812dc3A010C7d01b50e0d17dc79C8&chainId=1");
    for (const bad of ["", "hello", "0x1234", "javascript:alert(1)", "/analyses/../x", "0x" + "zz".repeat(20)]) {
      expect(searchTarget(bad, 1)).toBeNull();
    }
  });
});
