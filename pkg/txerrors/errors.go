// Package txerrors defines TxShield's structured error type.
//
// Errors carry a Kind that maps deterministically to an HTTP status and a CLI
// exit code, a stable machine-readable Code, a human-readable Message that is
// safe to show to API clients, and an optional wrapped cause that is NOT
// exposed to clients (it may contain upstream URLs or internal details).
//
// The package is named txerrors rather than errors to avoid shadowing the
// standard library at every import site.
package txerrors

import (
	"errors"
	"fmt"
	"net/http"
)

// Kind classifies an error for transport mapping and retry decisions.
type Kind string

const (
	// KindInvalidInput: the caller sent something malformed. Not retryable.
	KindInvalidInput Kind = "invalid_input"
	// KindNotFound: the requested resource does not exist.
	KindNotFound Kind = "not_found"
	// KindPayloadTooLarge: request body or calldata exceeds configured limits.
	KindPayloadTooLarge Kind = "payload_too_large"
	// KindRateLimited: the caller exceeded a rate limit.
	KindRateLimited Kind = "rate_limited"
	// KindUnsupported: valid request for a feature/chain that is not configured.
	KindUnsupported Kind = "unsupported"
	// KindUnavailable: an infrastructure dependency (RPC, Anvil, DB) failed.
	// This is distinct from a transaction reverting during simulation.
	KindUnavailable Kind = "unavailable"
	// KindTimeout: the operation exceeded its deadline.
	KindTimeout Kind = "timeout"
	// KindInternal: a bug or unexpected condition inside TxShield.
	KindInternal Kind = "internal"
)

// FieldError describes a validation problem with a single input field.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Error is TxShield's structured error.
type Error struct {
	Kind    Kind
	Code    string // stable, machine-readable, e.g. "invalid_address"
	Message string // safe to expose to clients
	Fields  []FieldError
	Err     error // internal cause; never serialized to clients
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Kind, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Kind, e.Message)
}

func (e *Error) Unwrap() error { return e.Err }

// New creates an Error without a cause.
func New(kind Kind, code, message string) *Error {
	return &Error{Kind: kind, Code: code, Message: message}
}

// Wrap creates an Error that wraps an internal cause.
func Wrap(err error, kind Kind, code, message string) *Error {
	return &Error{Kind: kind, Code: code, Message: message, Err: err}
}

// Invalid creates a validation error carrying per-field details.
func Invalid(fields ...FieldError) *Error {
	return &Error{
		Kind:    KindInvalidInput,
		Code:    "validation_failed",
		Message: "request validation failed",
		Fields:  fields,
	}
}

// KindOf returns the Kind of err, or KindInternal if err is not a *Error.
func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return KindInternal
}

// As is a convenience wrapper around errors.As for *Error.
func As(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}

// HTTPStatus maps a Kind to an HTTP status code.
func HTTPStatus(k Kind) int {
	switch k {
	case KindInvalidInput:
		return http.StatusBadRequest
	case KindNotFound:
		return http.StatusNotFound
	case KindPayloadTooLarge:
		return http.StatusRequestEntityTooLarge
	case KindRateLimited:
		return http.StatusTooManyRequests
	case KindUnsupported:
		return http.StatusUnprocessableEntity
	case KindUnavailable:
		return http.StatusServiceUnavailable
	case KindTimeout:
		return http.StatusGatewayTimeout
	default:
		return http.StatusInternalServerError
	}
}

// Retryable reports whether an operation that failed with k may succeed if
// retried unchanged.
func Retryable(k Kind) bool {
	return k == KindUnavailable || k == KindTimeout || k == KindRateLimited
}
