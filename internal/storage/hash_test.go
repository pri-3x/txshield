package storage

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestCalldataHashPrivacy(t *testing.T) {
	data := []byte{0x09, 0x5e, 0xa7, 0xb3, 1, 2, 3}
	private := NewAnalysisStore(nil, StoreOptions{})
	if h := private.calldataHash(data); bytes.Equal(h, crypto.Keccak256(data)) || len(h) != 32 {
		t.Fatal("without calldata storage the hash must not be the public keccak256")
	}
	if !bytes.Equal(private.calldataHash(data), private.calldataHash(data)) {
		t.Fatal("hash must be stable within a process")
	}
	if bytes.Equal(private.calldataHash(data), NewAnalysisStore(nil, StoreOptions{}).calldataHash(data)) {
		t.Fatal("keys must differ between stores")
	}
	full := NewAnalysisStore(nil, StoreOptions{StoreCalldata: true})
	if !bytes.Equal(full.calldataHash(data), crypto.Keccak256(data)) {
		t.Fatal("with calldata stored, the plain hash is fine")
	}
}
