"use client";

import { useRef, useState, useTransition, type KeyboardEvent, type ReactNode } from "react";
import type { AnalysisResult, DecodedCall, TransactionLookup } from "@txshield/sdk";
import { DecodedCallTree, SecurityReport } from "@/components/report";
import { Card, Notice } from "@/components/ui";
import { analyzeAction, decodeAction, lookupAction, type ActionError } from "./actions";

type Mode = "params" | "hash" | "calldata";
const MODES: { id: Mode; label: string }[] = [
  { id: "params", label: "Transaction parameters" },
  { id: "hash", label: "Transaction hash" },
  { id: "calldata", label: "Calldata only" },
];

interface ChainOption {
  id: number;
  name: string;
  rpc: boolean;
}

interface TxFields {
  chainId: string;
  from: string;
  to: string;
  value: string;
  data: string;
  gas: string;
  block: string;
}

const EMPTY: TxFields = { chainId: "", from: "", to: "", value: "0", data: "", gas: "", block: "" };

// Demo INPUTS only: they pre-fill the form so you can see the analysis of a
// typical shape. The analysis itself always runs against the real API.
const EXAMPLES: { label: string; fields: Partial<TxFields> }[] = [
  {
    label: "Unlimited ERC-20 approval",
    fields: {
      to: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
      data: "0x095ea7b30000000000000000000000002222222222222222222222222222222222222222ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      value: "0",
    },
  },
  {
    label: "NFT collection-wide operator approval",
    fields: {
      to: "0x57f1887a8BF19b14fC0dF6Fd9B2acc9Af147eA85",
      data: "0xa22cb46500000000000000000000000022222222222222222222222222222222222222220000000000000000000000000000000000000000000000000000000000000001",
      value: "0",
    },
  },
  { label: "Plain ETH transfer", fields: { to: "0x2222222222222222222222222222222222222222", data: "", value: "1000000000000000000" } },
];
const EXAMPLE_SENDER = "0x1111111111111111111111111111111111111111";

export function Scanner({ chains }: { chains: ChainOption[] }) {
  const defaultChain = String(chains[0]?.id ?? 1);
  const [mode, setMode] = useState<Mode>("params");
  const [fields, setFields] = useState<TxFields>({ ...EMPTY, chainId: defaultChain });
  const [simulate, setSimulate] = useState(true);
  const [report, setReport] = useState<AnalysisResult | null>(null);
  const [decoded, setDecoded] = useState<DecodedCall | null>(null);
  const [lookup, setLookup] = useState<TransactionLookup | null>(null);
  const [error, setError] = useState<ActionError | null>(null);
  const [pending, startTransition] = useTransition();
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const resultRef = useRef<HTMLDivElement>(null);

  const set = (k: keyof TxFields) => (e: { target: { value: string } }) => setFields((f) => ({ ...f, [k]: e.target.value }));
  const fieldError = (name: string) => error?.fields.find((f) => f.field === name)?.message;

  function run<T>(action: (fd: FormData) => Promise<{ ok: true; data: T } | { ok: false; error: ActionError }>, fd: FormData, onOk: (d: T) => void) {
    setError(null);
    startTransition(async () => {
      const res = await action(fd);
      if (res.ok) {
        onOk(res.data);
        requestAnimationFrame(() => resultRef.current?.focus());
      } else setError(res.error);
    });
  }

  function onTabKey(e: KeyboardEvent, i: number) {
    const dir = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
    if (!dir) return;
    e.preventDefault();
    const next = (i + dir + MODES.length) % MODES.length;
    setMode(MODES[next]!.id);
    tabRefs.current[next]?.focus();
  }

  return (
    <div className="space-y-4">
      <div role="tablist" aria-label="Input type" className="flex flex-wrap gap-1 border-b border-line">
        {MODES.map((m, i) => (
          <button
            key={m.id}
            ref={(el) => {
              tabRefs.current[i] = el;
            }}
            id={`tab-${m.id}`}
            role="tab"
            type="button"
            aria-selected={mode === m.id}
            aria-controls={`panel-${m.id}`}
            tabIndex={mode === m.id ? 0 : -1}
            onClick={() => setMode(m.id)}
            onKeyDown={(e) => onTabKey(e, i)}
            className={`-mb-px border-b-2 px-3 py-2 text-sm ${mode === m.id ? "border-accent font-medium text-ink" : "border-transparent text-ink-2 hover:text-ink"}`}
          >
            {m.label}
          </button>
        ))}
      </div>

      {error && (
        <Notice tone="critical" title={error.message}>
          {error.fields.length > 0 && (
            <ul className="list-disc pl-5">
              {error.fields.map((f, i) => (
                <li key={i}>
                  <span className="font-mono">{f.field}</span>: {f.message}
                </li>
              ))}
            </ul>
          )}
          {error.requestId && <p className="mt-1 text-xs">Request ID {error.requestId}</p>}
        </Notice>
      )}

      {mode === "params" && (
        <div id="panel-params" role="tabpanel" aria-labelledby="tab-params">
          <Card>
            {lookup && (
              <div className="mb-4">
                <Notice title={`Loaded transaction ${lookup.hash.slice(0, 10)}… from chain ${lookup.chainId}`}>
                  <ul className="list-disc pl-5">
                    {lookup.notes.map((n, i) => (
                      <li key={i}>{n}</li>
                    ))}
                  </ul>
                </Notice>
              </div>
            )}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                run(analyzeAction, new FormData(e.currentTarget), (d) => {
                  setReport(d);
                  setDecoded(null);
                });
              }}
              className="space-y-4"
              noValidate
            >
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <ChainSelect chains={chains} value={fields.chainId} onChange={set("chainId")} error={fieldError("chainId")} />
                <Field label="Block" name="block" value={fields.block} onChange={set("block")} placeholder="latest" hint="latest, safe, finalized, a number, or a hash" error={fieldError("block")} />
                <Field label="From (sender)" name="from" value={fields.from} onChange={set("from")} placeholder="0x…" mono required error={fieldError("from")} />
                <Field label="To (contract or recipient)" name="to" value={fields.to} onChange={set("to")} placeholder="0x… (empty for contract creation)" mono error={fieldError("to")} />
                <Field label="Value (wei)" name="value" value={fields.value} onChange={set("value")} mono error={fieldError("value")} />
                <Field label="Gas limit" name="gas" value={fields.gas} onChange={set("gas")} placeholder="optional" mono error={fieldError("gas")} />
              </div>
              <TextArea label="Data (calldata, 0x-hex)" name="data" value={fields.data} onChange={set("data")} error={fieldError("data")} />
              <AbiField error={fieldError("abi")} />
              <div className="flex flex-wrap items-center gap-4">
                <label className="flex items-center gap-2 text-sm text-ink">
                  <input type="checkbox" name="simulate" checked={simulate} onChange={(e) => setSimulate(e.target.checked)} className="size-4 accent-[var(--accent)]" />
                  Simulate on a private fork (when the chain has an RPC endpoint)
                </label>
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <SubmitButton pending={pending}>Analyze</SubmitButton>
                <label className="flex items-center gap-2 text-sm text-ink-2">
                  <span>Example input (demo):</span>
                  <select
                    className="rounded-md border border-line bg-surface px-2 py-1.5 text-sm text-ink"
                    value=""
                    onChange={(e) => {
                      const ex = EXAMPLES[Number(e.target.value)];
                      if (ex) {
                        setFields((f) => ({ ...f, ...EMPTY, chainId: f.chainId, from: f.from || EXAMPLE_SENDER, ...ex.fields }));
                        setLookup(null);
                      }
                    }}
                  >
                    <option value="">Choose…</option>
                    {EXAMPLES.map((ex, i) => (
                      <option key={ex.label} value={i}>
                        {ex.label}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
            </form>
          </Card>
        </div>
      )}

      {mode === "hash" && (
        <div id="panel-hash" role="tabpanel" aria-labelledby="tab-hash">
          <Card>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                run(lookupAction, new FormData(e.currentTarget), (lk) => {
                  const t = lk.transaction;
                  setLookup(lk);
                  setFields({ chainId: String(t.chainId), from: t.from, to: t.to ?? "", value: t.value ?? "0", data: t.data ?? "", gas: t.gas ?? "", block: t.block ?? "" });
                  setMode("params");
                });
              }}
              className="space-y-4"
              noValidate
            >
              <p className="text-sm text-ink-2">Fetches the transaction from the chain&apos;s RPC endpoint and fills in the parameters for review. Mined transactions are replayed on top of their parent block.</p>
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-[minmax(10rem,14rem)_1fr]">
                <ChainSelect chains={chains.filter((c) => c.rpc)} value={fields.chainId} onChange={set("chainId")} error={fieldError("chainId")} requireRpc />
                <Field label="Transaction hash" name="hash" placeholder="0x… (32 bytes)" mono required error={fieldError("hash")} />
              </div>
              <SubmitButton pending={pending}>Load transaction</SubmitButton>
            </form>
          </Card>
        </div>
      )}

      {mode === "calldata" && (
        <div id="panel-calldata" role="tabpanel" aria-labelledby="tab-calldata">
          <Card>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                run(decodeAction, new FormData(e.currentTarget), (d) => {
                  setDecoded(d);
                  setReport(null);
                });
              }}
              className="space-y-4"
              noValidate
            >
              <p className="text-sm text-ink-2">Decodes calldata offline, without a sender or simulation. Recognizing a function does not mean it is safe; run a full analysis before signing.</p>
              <Field label="Target contract (optional)" name="to" placeholder="0x…" mono error={fieldError("to")} />
              <TextArea label="Calldata (0x-hex)" name="data" required error={fieldError("data")} />
              <AbiField error={fieldError("abi")} />
              <SubmitButton pending={pending}>Decode</SubmitButton>
            </form>
          </Card>
        </div>
      )}

      <div ref={resultRef} tabIndex={-1} aria-live="polite" className="outline-none">
        {pending && <p className="text-sm text-ink-2">Working… simulations can take a few seconds.</p>}
        {!pending && report && (
          <div className="space-y-2">
            <h2 className="text-xl font-semibold text-ink">Security report</h2>
            <SecurityReport report={report} />
          </div>
        )}
        {!pending && decoded && (
          <Card title="Decoded calldata">
            <DecodedCallTree call={decoded} />
          </Card>
        )}
      </div>
    </div>
  );
}

const inputClass = "w-full rounded-md border border-line bg-surface px-3 py-2 text-sm text-ink placeholder:text-ink-3 aria-[invalid=true]:border-critical";

function Field(props: { label: string; name: string; value?: string; onChange?: (e: { target: { value: string } }) => void; placeholder?: string; hint?: string; mono?: boolean; required?: boolean; error?: string }) {
  const id = `f-${props.name}`;
  const describedBy = [props.hint ? `${id}-hint` : "", props.error ? `${id}-err` : ""].filter(Boolean).join(" ") || undefined;
  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-sm font-medium text-ink">
        {props.label}
        {props.required && <span className="text-ink-3"> (required)</span>}
      </label>
      <input
        id={id}
        name={props.name}
        {...(props.onChange ? { value: props.value ?? "", onChange: props.onChange } : {})}
        placeholder={props.placeholder}
        required={props.required}
        autoComplete="off"
        spellCheck={false}
        aria-invalid={props.error ? true : undefined}
        aria-describedby={describedBy}
        className={`${inputClass} ${props.mono ? "font-mono" : ""}`}
      />
      {props.hint && (
        <p id={`${id}-hint`} className="mt-1 text-xs text-ink-3">
          {props.hint}
        </p>
      )}
      {props.error && (
        <p id={`${id}-err`} className="mt-1 text-xs text-critical-ink">
          {props.error}
        </p>
      )}
    </div>
  );
}

function TextArea(props: { label: string; name: string; value?: string; onChange?: (e: { target: { value: string } }) => void; required?: boolean; error?: string }) {
  const id = `f-${props.name}`;
  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-sm font-medium text-ink">
        {props.label}
        {props.required && <span className="text-ink-3"> (required)</span>}
      </label>
      <textarea
        id={id}
        name={props.name}
        rows={4}
        {...(props.onChange ? { value: props.value ?? "", onChange: props.onChange } : {})}
        required={props.required}
        spellCheck={false}
        aria-invalid={props.error ? true : undefined}
        aria-describedby={props.error ? `${id}-err` : undefined}
        className={`${inputClass} break-all font-mono`}
      />
      {props.error && (
        <p id={`${id}-err`} className="mt-1 text-xs text-critical-ink">
          {props.error}
        </p>
      )}
    </div>
  );
}

function AbiField({ error }: { error?: string }) {
  return (
    <details open={Boolean(error)}>
      <summary className="cursor-pointer text-sm text-ink-2">Contract ABI (optional, improves decoding)</summary>
      <div className="mt-2">
        <TextArea label="ABI JSON" name="abi" error={error} />
      </div>
    </details>
  );
}

function ChainSelect({ chains, value, onChange, error, requireRpc }: { chains: ChainOption[]; value: string; onChange: (e: { target: { value: string } }) => void; error?: string; requireRpc?: boolean }) {
  return (
    <div>
      <label htmlFor="f-chainId" className="mb-1 block text-sm font-medium text-ink">
        Network
      </label>
      <select id="f-chainId" name="chainId" value={value} onChange={onChange} aria-invalid={error ? true : undefined} className={inputClass}>
        {chains.length === 0 && <option value="">{requireRpc ? "No chain has an RPC endpoint" : "No chains"}</option>}
        {chains.map((c) => (
          <option key={c.id} value={c.id}>
            {c.name} ({c.id}){c.rpc ? "" : " – offline"}
          </option>
        ))}
      </select>
      {error && <p className="mt-1 text-xs text-critical-ink">{error}</p>}
    </div>
  );
}

function SubmitButton({ pending, children }: { pending: boolean; children: ReactNode }) {
  return (
    <button type="submit" disabled={pending} aria-disabled={pending} className="rounded-md bg-btn px-4 py-2 text-sm font-medium text-white hover:opacity-90 disabled:opacity-60">
      {pending ? "Working…" : children}
    </button>
  );
}
