package api

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pri-3x/txshield/pkg/interfaces"
	"github.com/pri-3x/txshield/pkg/models"
	"github.com/pri-3x/txshield/pkg/txerrors"
)

// The OpenAPI document is generated: component schemas are reflected from
// the Go types the handlers actually encode/decode, and paths are declared
// below next to their handlers' contracts. Regenerate with:
//
//	go test ./internal/api -run TestOpenAPISpec -update
var update = flag.Bool("update", false, "rewrite internal/api/openapi.json")

type obj = map[string]any

// enumValues documents string-typed enums.
var enumValues = map[reflect.Type][]string{
	reflect.TypeFor[models.Severity]():             {"info", "low", "medium", "high", "critical"},
	reflect.TypeFor[models.Confidence]():           {"low", "medium", "high"},
	reflect.TypeFor[models.RiskCategory]():         {"low", "moderate", "elevated", "high", "critical"},
	reflect.TypeFor[models.EvidenceSource]():       {"fact", "heuristic", "external"},
	reflect.TypeFor[models.Category]():             {"approval", "interaction", "value_transfer", "dangerous_pattern", "reputation", "simulation"},
	reflect.TypeFor[models.CallKind]():             {"native_transfer", "contract_call", "contract_creation", "unknown"},
	reflect.TypeFor[models.CallType]():             {"call", "delegatecall", "self", "router_command", "create"},
	reflect.TypeFor[models.DecodeSource]():         {"builtin", "user_abi", "signature_db", "none"},
	reflect.TypeFor[models.SimulationStatus]():     {"success", "reverted", "not_run", "error"},
	reflect.TypeFor[models.Completeness]():         {"full", "partial", "none"},
	reflect.TypeFor[models.AssetKind]():            {"native", "erc20", "erc721", "erc1155"},
	reflect.TypeFor[models.ApprovalKind]():         {"erc20_allowance", "erc20_allowance_increase", "erc20_or_erc721_approval", "erc721_token_approval", "operator_approval", "eip2612_permit", "dai_permit", "permit2_allowance", "permit2_permit"},
	reflect.TypeFor[models.ReputationStatus]():     {"unknown", "allowed", "suspicious", "blocked"},
	reflect.TypeFor[models.ReputationSourceKind](): {"local", "list", "external"},
	reflect.TypeFor[txerrors.Kind]():               {"invalid_input", "not_found", "payload_too_large", "rate_limited", "unsupported", "unavailable", "timeout", "internal"},
}

type schemaGen struct{ defs obj }

func (g *schemaGen) ref(t reflect.Type) obj {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch {
	case t == reflect.TypeFor[time.Time]():
		return obj{"type": "string", "format": "date-time"}
	case t == reflect.TypeFor[json.RawMessage]():
		return obj{"description": "arbitrary JSON"}
	case t == reflect.TypeFor[models.Quantity]():
		return obj{"type": "string", "pattern": "^-?[0-9]+$", "description": "integer as a decimal string (inputs also accept JSON numbers and 0x-hex strings)"}
	}
	if vals, ok := enumValues[t]; ok {
		return obj{"type": "string", "enum": vals}
	}
	switch t.Kind() {
	case reflect.String:
		return obj{"type": "string"}
	case reflect.Bool:
		return obj{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return obj{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return obj{"type": "number"}
	case reflect.Interface:
		return obj{"description": "any JSON value (decoded ABI value: string, boolean, array, or array of named params)"}
	case reflect.Slice, reflect.Array:
		return obj{"type": "array", "items": g.ref(t.Elem())}
	case reflect.Map:
		return obj{"type": "object", "additionalProperties": g.ref(t.Elem())}
	case reflect.Struct:
		name := schemaName(t)
		if _, done := g.defs[name]; !done {
			g.defs[name] = obj{} // placeholder for recursion
			g.defs[name] = g.object(t)
		}
		return obj{"$ref": "#/components/schemas/" + name}
	}
	panic("unsupported type " + t.String())
}

func schemaName(t reflect.Type) string {
	n := t.Name()
	if i := strings.Index(n, "["); i >= 0 { // generic: PageResponse[...AnalysisSummary]
		n = n[:i] + "Of" + n[strings.LastIndex(n, ".")+1:len(n)-1]
	}
	return n
}

func (g *schemaGen) object(t reflect.Type) obj {
	props := obj{}
	var required []string
	var add func(t reflect.Type)
	add = func(t reflect.Type) {
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.Anonymous && f.Tag.Get("json") == "" {
				add(f.Type)
				continue
			}
			tag := f.Tag.Get("json")
			if tag == "-" || !f.IsExported() {
				continue
			}
			name, opts, _ := strings.Cut(tag, ",")
			if name == "" {
				name = f.Name
			}
			props[name] = g.ref(f.Type)
			if !strings.Contains(opts, "omitempty") && f.Type.Kind() != reflect.Pointer {
				required = append(required, name)
			}
		}
	}
	add(t)
	o := obj{"type": "object", "properties": props}
	if len(required) > 0 {
		sort.Strings(required)
		o["required"] = required
	}
	return o
}

func jsonBody(ref obj) obj { return obj{"content": obj{"application/json": obj{"schema": ref}}} }

func buildSpec() obj {
	g := &schemaGen{defs: obj{}}
	errResp := func(desc string) obj {
		r := jsonBody(g.ref(reflect.TypeFor[ErrorBody]()))
		r["description"] = desc
		return r
	}
	ok := func(t reflect.Type, desc string) obj {
		r := jsonBody(g.ref(t))
		r["description"] = desc
		return r
	}
	common := func(extra obj) obj {
		r := obj{"400": errResp("Invalid input (see `error.fields`)"), "401": errResp("Missing or invalid API key (only when keys are configured)"),
			"429": errResp("Rate limited (see `Retry-After`)"), "500": errResp("Internal error")}
		for k, v := range extra {
			r[k] = v
		}
		return r
	}
	q := func(name, desc string, required bool, schema obj) obj {
		return obj{"name": name, "in": "query", "description": desc, "required": required, "schema": schema}
	}
	page := []any{
		q("limit", "Page size (1-100, default 20)", false, obj{"type": "integer", "minimum": 1, "maximum": 100}),
		q("offset", "Offset (0-10000)", false, obj{"type": "integer", "minimum": 0, "maximum": 10000}),
	}
	analyzeBody := jsonBody(g.ref(reflect.TypeFor[AnalyzeRequest]()))
	analyzeBody["required"] = true

	paths := obj{
		"/health": obj{"get": obj{"security": []any{},
			"summary": "Health with dependency checks", "operationId": "health", "tags": []any{"ops"},
			"responses": obj{"200": ok(reflect.TypeFor[HealthResponse](), "Healthy or degraded (a non-critical dependency failed)"),
				"503": ok(reflect.TypeFor[HealthResponse](), "A critical dependency failed")},
		}},
		"/livez": obj{"get": obj{"security": []any{}, "summary": "Liveness probe", "operationId": "livez", "tags": []any{"ops"},
			"responses": obj{"200": obj{"description": "Process is serving"}}}},
		"/metrics": obj{"get": obj{"security": []any{}, "summary": "Prometheus metrics", "operationId": "metrics", "tags": []any{"ops"},
			"responses": obj{"200": obj{"description": "Prometheus text exposition", "content": obj{"text/plain": obj{"schema": obj{"type": "string"}}}}}}},
		"/api/v1/info": obj{"get": obj{"summary": "Engine configuration", "operationId": "info", "tags": []any{"meta"},
			"responses": common(obj{"200": ok(reflect.TypeFor[InfoResponse](), "Configured chains, simulator, rules")})}},
		"/api/v1/openapi.json": obj{"get": obj{"security": []any{}, "summary": "This document", "operationId": "openapi", "tags": []any{"meta"},
			"responses": obj{"200": obj{"description": "OpenAPI 3.1 document"}}}},
		"/api/v1/analyze": obj{"post": obj{
			"summary": "Analyze a transaction", "operationId": "analyze", "tags": []any{"analysis"},
			"description": "Decodes, checks reputation and contract facts, simulates (when available and `simulate` is not false), evaluates security rules, and returns a risk report. Never signs or broadcasts. A low score means no significant risks were detected by the enabled checks, not that the transaction is safe.",
			"requestBody": analyzeBody,
			"responses": common(obj{"200": ok(reflect.TypeFor[models.RiskReport](), "Risk report"),
				"413": errResp("Body or calldata too large"), "422": errResp("Unsupported (e.g. RPC endpoint serves a different chain)"),
				"503": errResp("Engine or dependency unavailable"), "504": errResp("Timed out")}),
		}},
		"/api/v1/simulate": obj{"post": obj{
			"summary": "Simulate a transaction on a private fork", "operationId": "simulate", "tags": []any{"analysis"},
			"description": "Executes the transaction on a local fork (or the provider's tracer in rpc-trace mode). A revert is a successful response with `status: reverted`; infrastructure failures are errors.",
			"requestBody": obj{"required": true, "content": obj{"application/json": obj{"schema": g.ref(reflect.TypeFor[SimulateRequest]())}}},
			"responses": common(obj{"200": ok(reflect.TypeFor[models.SimulationResult](), "Simulation result"),
				"422": errResp("Simulation not available for this chain"), "503": errResp("Simulation backend unavailable"), "504": errResp("Simulation timed out")}),
		}},
		"/api/v1/approvals/analyze": obj{"post": obj{
			"summary": "Analyze the token permissions a transaction grants", "operationId": "analyzeApprovals", "tags": []any{"analysis"},
			"description": "Returns every approval/permit the transaction grants or revokes, the permission currently in force on-chain (when an RPC endpoint is configured), and approval findings scored on their own. Simulation is off by default.",
			"requestBody": analyzeBody,
			"responses":   common(obj{"200": ok(reflect.TypeFor[ApprovalAnalysis](), "Approval analysis"), "503": errResp("Engine unavailable")}),
		}},
		"/api/v1/analyses": obj{"get": obj{
			"summary": "List stored analyses (newest first)", "operationId": "listAnalyses", "tags": []any{"history"},
			"parameters": append(page,
				q("chainId", "Filter by chain", false, obj{"type": "integer"}),
				q("minScore", "Minimum risk score", false, obj{"type": "integer", "minimum": 0, "maximum": 100}),
				q("address", "Analyses involving this address (any role)", false, obj{"type": "string"}),
				q("since", "RFC 3339 lower bound", false, obj{"type": "string", "format": "date-time"})),
			"responses": common(obj{"200": ok(reflect.TypeFor[PageResponse[models.AnalysisSummary]](), "Page of summaries"), "503": errResp("Persistence disabled")}),
		}},
		"/api/v1/analyses/{id}": obj{"get": obj{
			"summary": "Get a stored analysis", "operationId": "getAnalysis", "tags": []any{"history"},
			"parameters": []any{obj{"name": "id", "in": "path", "required": true, "schema": obj{"type": "string", "format": "uuid"}}},
			"responses":  common(obj{"200": ok(reflect.TypeFor[models.RiskReport](), "Stored report (privacy options applied)"), "404": errResp("Not found or expired"), "503": errResp("Persistence disabled")}),
		}},
		"/api/v1/address/{address}": obj{"get": obj{
			"summary": "Inspect an address", "operationId": "inspectAddress", "tags": []any{"history"},
			"parameters": append([]any{obj{"name": "address", "in": "path", "required": true, "schema": obj{"type": "string"}},
				q("chainId", "Chain to inspect", true, obj{"type": "integer"})}, page...),
			"responses": common(obj{"200": ok(reflect.TypeFor[AddressReport](), "Contract facts, reputation, history"), "422": errResp("Unsupported chain"), "503": errResp("Engine unavailable")}),
		}},
		"/api/v1/decode": obj{"post": obj{
			"summary": "Decode calldata (offline)", "operationId": "decode", "tags": []any{"analysis"},
			"description": "Decodes calldata without chain access. Omit `to` when the target is unknown. Recognizing a function says nothing about whether it is safe.",
			"requestBody": obj{"required": true, "content": obj{"application/json": obj{"schema": g.ref(reflect.TypeFor[DecodeRequest]())}}},
			"responses":   common(obj{"200": ok(reflect.TypeFor[models.DecodedCall](), "Decoded call tree"), "413": errResp("Calldata or ABI too large")}),
		}},
		"/api/v1/transactions/{hash}": obj{"get": obj{
			"summary": "Look up a transaction for re-analysis", "operationId": "getTransaction", "tags": []any{"analysis"},
			"description": "Fetches a transaction by hash from the configured RPC endpoint and returns it in /analyze request form. Mined transactions are set to replay on top of their parent block (an approximation: earlier transactions in the same block are not re-applied).",
			"parameters": []any{obj{"name": "hash", "in": "path", "required": true, "schema": obj{"type": "string", "pattern": "^0x[0-9a-fA-F]{64}$"}},
				q("chainId", "Chain to look up", true, obj{"type": "integer"})},
			"responses": common(obj{"200": ok(reflect.TypeFor[TransactionLookup](), "Transaction ready for analysis"),
				"404": errResp("Transaction not found"), "422": errResp("Chain not configured"), "503": errResp("RPC unavailable")}),
		}},
		"/api/v1/stats": obj{"get": obj{
			"summary": "Aggregate statistics", "operationId": "stats", "tags": []any{"history"},
			"parameters": []any{q("since", "RFC 3339 lower bound", false, obj{"type": "string", "format": "date-time"})},
			"responses":  common(obj{"200": ok(reflect.TypeFor[interfaces.AnalysisStats](), "Counts by category and chain"), "503": errResp("Persistence disabled")}),
		}},
	}
	return obj{
		"openapi": "3.1.0",
		"info": obj{
			"title": "TxShield API", "version": "1",
			"description": "EVM transaction security analysis and simulation. TxShield never signs or broadcasts transactions and never labels a transaction safe.",
			"license":     obj{"name": "Apache-2.0", "identifier": "Apache-2.0"},
		},
		"servers": []any{obj{"url": "http://localhost:8080", "description": "Local development (docker compose)"}},
		// Authentication is optional: enabled when the operator sets
		// TXSHIELD_API_KEYS. Operational endpoints never require it.
		"security": []any{obj{"bearerAuth": []any{}}, obj{}},
		"paths":    paths,
		"components": obj{"schemas": g.defs, "securitySchemes": obj{"bearerAuth": obj{
			"type": "http", "scheme": "bearer", "description": "Required only when the server sets TXSHIELD_API_KEYS.",
		}}},
	}
}

func TestOpenAPISpec(t *testing.T) {
	got, err := json.MarshalIndent(buildSpec(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if *update {
		if err := os.WriteFile("openapi.json", got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile("openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("internal/api/openapi.json is out of date; run: go test ./internal/api -run TestOpenAPISpec -update")
	}
	if !bytes.Equal(openAPISpec, want) {
		t.Fatal("embedded spec differs from file (rebuild)")
	}
}

// TestOpenAPICoversRoutes checks that every route the server registers is
// documented with the same method, and nothing undocumented exists.
func TestOpenAPICoversRoutes(t *testing.T) {
	var spec struct {
		Paths map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(openAPISpec, &spec); err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t, nil)
	registered := map[string]bool{}
	for p := range s.routes {
		registered[p] = true
	}
	for _, p := range []string{"/api/v1/analyses/{id}", "/api/v1/address/{address}", "/api/v1/transactions/{hash}"} {
		registered[p] = true
	}
	for p := range registered {
		if _, ok := spec.Paths[p]; !ok {
			t.Errorf("route %s is not documented", p)
		}
	}
	for p := range spec.Paths {
		if !registered[p] {
			t.Errorf("documented path %s is not served", p)
		}
	}
	// Spot-check methods against the live router.
	for p, methods := range spec.Paths {
		path := strings.NewReplacer("{id}", "00000000-0000-4000-8000-000000000000", "{address}", "0x1111111111111111111111111111111111111111", "{hash}", "0x"+strings.Repeat("ab", 32)).Replace(p)
		for m := range methods {
			rr := do(t, s, strings.ToUpper(m), path, nil, nil)
			// The route-check server has no engine, so handlers answer 503;
			// 404/405 would mean the router does not know the operation.
			if rr.Code == 404 || rr.Code == 405 {
				t.Errorf("%s %s -> %d", strings.ToUpper(m), p, rr.Code)
			}
		}
	}
}
