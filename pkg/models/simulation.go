package models

// SimulationStatus is the outcome of executing the transaction in simulation.
type SimulationStatus string

const (
	// SimSuccess: the transaction executed without reverting. This is NOT
	// evidence that the transaction is safe.
	SimSuccess SimulationStatus = "success"
	// SimReverted: the transaction reverted; RevertReason may explain why.
	SimReverted SimulationStatus = "reverted"
	// SimNotRun: simulation was disabled or not requested.
	SimNotRun SimulationStatus = "not_run"
	// SimError: simulation could not be performed due to infrastructure
	// failure. Says nothing about whether the transaction would succeed.
	SimError SimulationStatus = "error"
)

// Completeness states how much of the expected simulation data was obtained.
type Completeness string

const (
	CompletenessFull    Completeness = "full"
	CompletenessPartial Completeness = "partial"
	CompletenessNone    Completeness = "none"
)

// SimulatorCapabilities advertises what a simulation backend can produce.
type SimulatorCapabilities struct {
	Fork          bool `json:"fork"`
	CallTrace     bool `json:"callTrace"`
	StateDiff     bool `json:"stateDiff"`
	BalanceDiff   bool `json:"balanceDiff"`
	StateOverride bool `json:"stateOverride"`
}

// SimulationResult is the structured outcome of a simulation.
type SimulationResult struct {
	Backend           string           `json:"backend"`
	Status            SimulationStatus `json:"status"`
	Completeness      Completeness     `json:"completeness"`
	IncompleteReasons []string         `json:"incompleteReasons,omitempty"`
	// Notes explain how the simulation environment differs from real
	// inclusion (e.g. fees zeroed so balance diffs exclude gas).
	Notes           []string         `json:"notes,omitempty"`
	ChainID         uint64           `json:"chainId"`
	BlockNumber     uint64           `json:"blockNumber"` // state the tx was executed on top of
	BlockHash       string           `json:"blockHash,omitempty"`
	GasUsed         uint64           `json:"gasUsed"`
	GasEstimate     *uint64          `json:"gasEstimate,omitempty"`
	ReturnData      string           `json:"returnData,omitempty"`
	RevertReason    string           `json:"revertReason,omitempty"` // untrusted, attacker-controlled text
	Logs            []Log            `json:"logs,omitempty"`
	Trace           *CallFrame       `json:"trace,omitempty"`
	BalanceChanges  []BalanceChange  `json:"balanceChanges,omitempty"`
	AssetTransfers  []AssetTransfer  `json:"assetTransfers,omitempty"`
	ApprovalChanges []ApprovalChange `json:"approvalChanges,omitempty"`
	DurationMs      int64            `json:"durationMs"`
}

// Log is an EVM event log emitted during simulation.
type Log struct {
	Address string   `json:"address"`
	Topics  []string `json:"topics"`
	Data    string   `json:"data"`
	Index   uint     `json:"index"`
}

// CallFrame is one frame of an execution call trace.
type CallFrame struct {
	Type         string      `json:"type"` // CALL, DELEGATECALL, STATICCALL, CREATE, CREATE2, SELFDESTRUCT
	From         string      `json:"from"`
	To           string      `json:"to,omitempty"`
	Value        Quantity    `json:"value,omitempty"`
	Gas          uint64      `json:"gas"`
	GasUsed      uint64      `json:"gasUsed"`
	Input        string      `json:"input,omitempty"`
	Output       string      `json:"output,omitempty"`
	Error        string      `json:"error,omitempty"`
	RevertReason string      `json:"revertReason,omitempty"`
	Calls        []CallFrame `json:"calls,omitempty"`
}

// AssetKind identifies the token standard of an asset.
type AssetKind string

const (
	AssetNative  AssetKind = "native"
	AssetERC20   AssetKind = "erc20"
	AssetERC721  AssetKind = "erc721"
	AssetERC1155 AssetKind = "erc1155"
)

// AssetRef identifies an asset. Tokens are identified by (chain, address,
// tokenId) only; Symbol and Name are untrusted display hints.
type AssetRef struct {
	Kind     AssetKind `json:"kind"`
	Address  string    `json:"address,omitempty"` // empty for native
	TokenID  Quantity  `json:"tokenId,omitempty"`
	Symbol   string    `json:"symbol,omitempty"`
	Name     string    `json:"name,omitempty"`
	Decimals *uint8    `json:"decimals,omitempty"`
}

// BalanceChange is the before/after balance of an owner for an asset.
// Delta is signed (negative means the owner lost the asset).
type BalanceChange struct {
	Owner  string   `json:"owner"`
	Asset  AssetRef `json:"asset"`
	Before Quantity `json:"before"`
	After  Quantity `json:"after"`
	Delta  Quantity `json:"delta"`
}

// AssetTransfer is an asset movement observed during simulation (from logs
// for tokens, from the call trace for native value).
type AssetTransfer struct {
	Asset    AssetRef `json:"asset"`
	From     string   `json:"from"`
	To       string   `json:"to"`
	Amount   Quantity `json:"amount"`
	LogIndex *uint    `json:"logIndex,omitempty"`
}

// ApprovalChange is an allowance or operator approval observed during
// simulation.
type ApprovalChange struct {
	Asset    AssetRef `json:"asset"`
	Owner    string   `json:"owner"`
	Spender  string   `json:"spender"`
	Amount   Quantity `json:"amount,omitempty"`   // ERC-20 allowance / per-token approval
	Approved *bool    `json:"approved,omitempty"` // ApprovalForAll
}
