import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@/app/scan/actions", () => ({
  analyzeAction: vi.fn(async () => ({ ok: false, error: { message: "request validation failed", code: "validation_failed", fields: [{ field: "from", message: "invalid EIP-55 checksum" }], requestId: "r-1" } })),
  lookupAction: vi.fn(),
  decodeAction: vi.fn(),
}));

import { Scanner } from "@/app/scan/Scanner";

afterEach(cleanup);
const chains = [
  { id: 31337, name: "Anvil (local)", rpc: true },
  { id: 1, name: "Ethereum", rpc: false },
];

describe("Scanner", () => {
  it("has accessible tabs with keyboard navigation", async () => {
    render(<Scanner chains={chains} />);
    const tabs = screen.getAllByRole("tab");
    expect(tabs.map((t) => t.getAttribute("aria-selected"))).toEqual(["true", "false", "false"]);
    fireEvent.keyDown(tabs[0]!, { key: "ArrowRight" });
    expect(screen.getAllByRole("tab")[1]!.getAttribute("aria-selected")).toBe("true");
    expect(screen.getByRole("textbox", { name: /Transaction hash/ })).toBeTruthy();
  });

  it("example inputs fill the form but do not submit", () => {
    render(<Scanner chains={chains} />);
    fireEvent.change(screen.getByLabelText(/Example input/), { target: { value: "0" } });
    expect((screen.getByLabelText(/^Data/) as HTMLTextAreaElement).value).toMatch(/^0x095ea7b3/);
    expect((screen.getByLabelText(/From/) as HTMLInputElement).value).toBe("0x1111111111111111111111111111111111111111");
  });

  it("maps server field errors onto inputs", async () => {
    render(<Scanner chains={chains} />);
    fireEvent.submit(screen.getByRole("button", { name: "Analyze" }).closest("form")!);
    const msg = await screen.findAllByText(/invalid EIP-55 checksum/);
    expect(msg.length).toBeGreaterThanOrEqual(2); // summary + inline
    expect(screen.getByLabelText(/From/).getAttribute("aria-invalid")).toBe("true");
  });

  it("has no detectable accessibility violations", async () => {
    const { container } = render(<Scanner chains={chains} />);
    const res = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(res.violations.map((v) => v.id)).toEqual([]);
  });
});
