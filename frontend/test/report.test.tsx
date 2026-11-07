import { cleanup, render, screen } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, describe, expect, it } from "vitest";
import type { RiskReport } from "@txshield/sdk";
import { SecurityReport } from "@/components/report";
import { BarChart } from "@/components/BarChart";

afterEach(cleanup);

// TEST FIXTURE (synthetic): shaped like a real /analyze response.
const MAX = ((1n << 256n) - 1n).toString();
const fixture: RiskReport = {
  id: "6f1c0d4e-1a2b-4c3d-8e9f-0a1b2c3d4e5f",
  requestId: "req-1",
  engineVersion: "test",
  analyzedAt: "2026-11-07T10:00:00Z",
  transaction: { chainId: 1, chainName: "Ethereum Mainnet", from: "0x1111111111111111111111111111111111111111", to: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", value: "0", kind: "contract_call", method: "approve", description: "Call approve(address,uint256) [erc20|erc721] on 0xA0b8…", block: "latest" },
  decoded: {
    kind: "contract_call", callType: "call", target: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", selector: "0x095ea7b3", method: "approve",
    signature: "approve(address,uint256)", standard: "erc20|erc721", source: "builtin",
    params: [
      { name: "spender", type: "address", value: "0xdead000000000000000000000000000000000001" },
      { name: "amountOrTokenId", type: "uint256", value: MAX },
      { name: "note", type: "string", value: "<img src=x onerror=alert(1)>‮gnp.exe" },
    ],
  },
  risk: { score: 89, category: "critical", confidence: "medium", contributions: [{ fingerprint: "TXS-APPROVAL-005:x", ruleId: "TXS-APPROVAL-005", points: 85, reason: "critical severity (85) x high confidence (1.00) x fact source (1.00)" }] },
  verdict: "Critical risk: 2 finding(s) require review before signing.",
  findings: [
    {
      ruleId: "TXS-APPROVAL-005", title: "Approval to a flagged spender", description: "Spender is blocked according to [list:demo].", category: "approval",
      severity: "critical", confidence: "high", source: "fact", mitigation: "Do not sign.", falsePositiveNotes: "Lists can be stale.", fingerprint: "TXS-APPROVAL-005:x",
      evidence: [{ type: "reputation_record", detail: "list:demo: blocked (drainer)", source: "fact" }],
    },
    {
      ruleId: "TXS-APPROVAL-001", title: "Unlimited token allowance", description: "Unlimited allowance.", category: "approval",
      severity: "medium", confidence: "medium", source: "fact", mitigation: "Approve only what you need.", fingerprint: "TXS-APPROVAL-001:x",
    },
  ],
  approvals: [{ kind: "erc20_or_erc721_approval", contract: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", owner: "0x1111111111111111111111111111111111111111", spender: "0xdead000000000000000000000000000000000001", ownerIsSender: true, amount: MAX, unlimited: true, revocation: false, signed: false, via: "root" }],
  simulation: { backend: "anvil", status: "reverted", completeness: "full", chainId: 1, blockNumber: 19000000, gasUsed: 21000, revertReason: "nope‮txet", durationMs: 30 },
  recommendations: ["Do not sign.", "Approve only what you need."],
  enabledChecks: ["TXS-APPROVAL-001", "TXS-APPROVAL-005"],
  warnings: ["contract facts were not checked"],
  disclaimer: "TxShield reports what its enabled checks observed.",
};

async function axeViolations(container: HTMLElement) {
  const res = await axe.run(container, { rules: { "color-contrast": { enabled: false } } }); // jsdom has no layout
  return res.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(" | ")} :: ${v.nodes[0]?.failureSummary ?? ""}`);
}

describe("SecurityReport", () => {
  it("renders the headline facts", () => {
    render(<SecurityReport report={fixture} />);
    expect(screen.getByText("89")).toBeTruthy();
    expect(screen.getAllByText(/Critical/).length).toBeGreaterThan(0);
    expect(screen.getByText("Findings · 2")).toBeTruthy();
    expect(screen.getByText("Approval to a flagged spender")).toBeTruthy();
    expect(screen.getAllByText(/Unlimited \(2²⁵⁶−1\)/).length).toBeGreaterThanOrEqual(2); // decoded param + approvals table
    expect(screen.getByText(/contract facts were not checked/)).toBeTruthy();
  });

  it("renders untrusted strings as inert, visible text", () => {
    const { container } = render(<SecurityReport report={fixture} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toContain("<img src=x onerror=alert(1)>\\u202egnp.exe");
    expect(container.textContent).toContain("nope\\u202etxet");
    expect(container.textContent).not.toContain("‮");
  });

  it("never claims the transaction is safe", () => {
    const { container } = render(<SecurityReport report={{ ...fixture, findings: [], verdict: "No significant risks detected by enabled checks." }} />);
    const text = container.textContent ?? "";
    expect(text).toContain("No significant risks detected by enabled checks.");
    // The only allowed mentions of "safe" are explicit non-guarantees.
    const remaining = text
      .replace(fixture.disclaimer, "")
      .replace("This does not mean the transaction is safe", "")
      .replace("not how sure TxShield is that the transaction is safe", "");
    expect(remaining).not.toMatch(/\bsafe\b/i);
  });

  it("has no detectable accessibility violations", async () => {
    const { container } = render(<SecurityReport report={fixture} />);
    expect(await axeViolations(container)).toEqual([]);
  });
});

describe("BarChart", () => {
  it("labels every bar and offers a table view", async () => {
    const { container } = render(<BarChart title="Analyses by risk category" bars={[{ label: "Low observed risk", value: 7 }, { label: "Critical", value: 0 }]} />);
    const svg = container.querySelector("svg")!;
    expect(svg.getAttribute("aria-label")).toBe("Analyses by risk category: Low observed risk 7, Critical 0");
    expect(container.querySelectorAll("table tbody tr")).toHaveLength(2);
    expect(container.querySelectorAll("[style]")).toHaveLength(0); // CSP: no inline styles
    expect(await axeViolations(container)).toEqual([]);
  });
});
