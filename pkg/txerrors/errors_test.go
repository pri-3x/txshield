package txerrors

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

func TestKindOfAndUnwrap(t *testing.T) {
	cause := errors.New("dial tcp: connection refused")
	err := fmt.Errorf("simulate: %w", Wrap(cause, KindUnavailable, "rpc_unavailable", "upstream RPC unavailable"))

	if got := KindOf(err); got != KindUnavailable {
		t.Fatalf("KindOf = %q, want %q", got, KindUnavailable)
	}
	if !errors.Is(err, cause) {
		t.Fatal("wrapped cause not reachable via errors.Is")
	}
	if got := KindOf(errors.New("plain")); got != KindInternal {
		t.Fatalf("KindOf(plain) = %q, want internal", got)
	}
}

func TestHTTPStatus(t *testing.T) {
	cases := map[Kind]int{
		KindInvalidInput:    http.StatusBadRequest,
		KindNotFound:        http.StatusNotFound,
		KindPayloadTooLarge: http.StatusRequestEntityTooLarge,
		KindRateLimited:     http.StatusTooManyRequests,
		KindUnsupported:     http.StatusUnprocessableEntity,
		KindUnavailable:     http.StatusServiceUnavailable,
		KindTimeout:         http.StatusGatewayTimeout,
		KindInternal:        http.StatusInternalServerError,
		Kind("bogus"):       http.StatusInternalServerError,
	}
	for k, want := range cases {
		if got := HTTPStatus(k); got != want {
			t.Errorf("HTTPStatus(%q) = %d, want %d", k, got, want)
		}
	}
}

func TestRetryable(t *testing.T) {
	if Retryable(KindInvalidInput) || Retryable(KindInternal) {
		t.Fatal("non-transient kinds must not be retryable")
	}
	if !Retryable(KindUnavailable) || !Retryable(KindTimeout) {
		t.Fatal("transient kinds must be retryable")
	}
}
