package models

// ApprovalKind classifies a permission grant found in a transaction.
type ApprovalKind string

const (
	// ApprovalERC20: ERC-20 approve(spender, amount).
	ApprovalERC20 ApprovalKind = "erc20_allowance"
	// ApprovalERC20Increase: increaseAllowance(spender, added).
	ApprovalERC20Increase ApprovalKind = "erc20_allowance_increase"
	// ApprovalAmbiguous: approve(address,uint256) on a contract whose token
	// standard could not be determined (ERC-20 amount vs ERC-721 token ID).
	ApprovalAmbiguous ApprovalKind = "erc20_or_erc721_approval"
	// ApprovalNFTToken: ERC-721 approve for one token ID.
	ApprovalNFTToken ApprovalKind = "erc721_token_approval" //nolint:gosec // enum value, not a credential
	// ApprovalOperator: setApprovalForAll (every token of the collection).
	ApprovalOperator ApprovalKind = "operator_approval"
	// ApprovalEIP2612: EIP-2612 permit (signature-based ERC-20 allowance).
	ApprovalEIP2612 ApprovalKind = "eip2612_permit"
	// ApprovalDAIPermit: DAI-style permit (allowed=true is unlimited).
	ApprovalDAIPermit ApprovalKind = "dai_permit"
	// ApprovalPermit2: Permit2.approve (direct allowance on Permit2).
	ApprovalPermit2 ApprovalKind = "permit2_allowance"
	// ApprovalPermit2Signed: Permit2 permit / permitBatch (signature-based).
	ApprovalPermit2Signed ApprovalKind = "permit2_permit"
)

// ApprovalGrant is a token permission that the transaction would grant or
// revoke. Facts come from calldata; whether a grant is dangerous is decided
// by rules.
type ApprovalGrant struct {
	Kind ApprovalKind `json:"kind"`
	// Contract executing the approval: the token itself, or Permit2.
	Contract string `json:"contract"`
	// Token whose balance becomes spendable. Equals Contract for direct
	// approvals; for Permit2 it is the token named in the permit.
	Token   string `json:"token"`
	Owner   string `json:"owner"`
	Spender string `json:"spender"`
	// OwnerIsSender: the owner is the transaction sender, i.e. the grant
	// concerns the signer's own assets. Grants made by intermediary contracts
	// (e.g. a Multicall3 approving something) do not touch the sender's tokens.
	OwnerIsSender bool     `json:"ownerIsSender"`
	Amount        Quantity `json:"amount,omitempty"`
	TokenID       Quantity `json:"tokenId,omitempty"`
	Approved      *bool    `json:"approved,omitempty"` // operator approvals
	Unlimited     bool     `json:"unlimited"`
	Revocation    bool     `json:"revocation"`
	Expiration    *uint64  `json:"expiration,omitempty"` // unix seconds (permits, Permit2)
	Signed        bool     `json:"signed"`               // authorized by an off-chain signature
	Via           string   `json:"via"`                  // location in the decoded call tree
}

// ApprovalState is a permission's current on-chain value, read at a block.
type ApprovalState struct {
	Block          uint64   `json:"block"`
	Amount         Quantity `json:"amount,omitempty"`         // ERC-20 / Permit2 allowance
	Unlimited      bool     `json:"unlimited"`                // amount is the max sentinel
	ApprovedForAll *bool    `json:"approvedForAll,omitempty"` // ERC-721/1155 operator status
	TokenApproved  *bool    `json:"tokenApproved,omitempty"`  // ERC-721 single-token approval
	Expiration     *uint64  `json:"expiration,omitempty"`     // Permit2
	Error          string   `json:"error,omitempty"`          // why the state could not be read
}
