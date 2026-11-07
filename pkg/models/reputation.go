package models

import "time"

// ReputationStatus is the classification a reputation source assigns.
type ReputationStatus string

const (
	ReputationUnknown    ReputationStatus = "unknown"
	ReputationAllowed    ReputationStatus = "allowed"
	ReputationSuspicious ReputationStatus = "suspicious"
	ReputationBlocked    ReputationStatus = "blocked"
)

// ReputationSourceKind distinguishes operator-maintained data from
// third-party opinion.
type ReputationSourceKind string

const (
	ReputationSourceLocal    ReputationSourceKind = "local"    // operator-maintained DB records
	ReputationSourceList     ReputationSourceKind = "list"     // configured allow/block list files
	ReputationSourceExternal ReputationSourceKind = "external" // external provider adapter
)

// ReputationRecord is one source's opinion about an address.
type ReputationRecord struct {
	ChainID    uint64               `json:"chainId"`
	Address    string               `json:"address"`
	Status     ReputationStatus     `json:"status"`
	Source     string               `json:"source"` // e.g. "local", "list:team-blocklist", "provider:example"
	SourceKind ReputationSourceKind `json:"sourceKind"`
	Reason     string               `json:"reason,omitempty"`
	Labels     []string             `json:"labels,omitempty"`
	Confidence Confidence           `json:"confidence"`
	UpdatedAt  time.Time            `json:"updatedAt"`
	ExpiresAt  *time.Time           `json:"expiresAt,omitempty"`
}

// ContractInfo holds on-chain facts about an address. Name is untrusted.
type ContractInfo struct {
	ChainID        uint64   `json:"chainId"`
	Address        string   `json:"address"`
	IsContract     bool     `json:"isContract"`
	CodeHash       string   `json:"codeHash,omitempty"`
	CodeSize       int      `json:"codeSize"`
	IsProxy        bool     `json:"isProxy"`
	Implementation string   `json:"implementation,omitempty"`
	Verified       *bool    `json:"verified,omitempty"` // nil when no verification source is configured
	Standards      []string `json:"standards,omitempty"`
	Name           string   `json:"name,omitempty"`
	AtBlock        uint64   `json:"atBlock"`
}
