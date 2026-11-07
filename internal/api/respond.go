package api

import (
	"encoding/json"
	"net/http"

	"github.com/txshield/txshield/internal/logging"
	"github.com/txshield/txshield/pkg/txerrors"
)

// ErrorBody is the JSON shape of every error response.
type ErrorBody struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail is the structured error payload.
type ErrorDetail struct {
	Kind      txerrors.Kind         `json:"kind"`
	Code      string                `json:"code"`
	Message   string                `json:"message"`
	Fields    []txerrors.FieldError `json:"fields,omitempty"`
	RequestID string                `json:"requestId,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

// writeError renders err as a structured error. Internal causes are logged
// but never sent to the client.
func writeError(w http.ResponseWriter, r *http.Request, err error) {
	e, ok := txerrors.As(err)
	if !ok {
		e = txerrors.Wrap(err, txerrors.KindInternal, "internal_error", "internal server error")
	}
	status := txerrors.HTTPStatus(e.Kind)
	log := logging.FromContext(r.Context())
	if status >= 500 {
		log.Error("request failed", "kind", e.Kind, "code", e.Code, "err", err)
	} else {
		log.Debug("request rejected", "kind", e.Kind, "code", e.Code)
	}
	writeJSON(w, status, ErrorBody{Error: ErrorDetail{
		Kind:      e.Kind,
		Code:      e.Code,
		Message:   e.Message,
		Fields:    e.Fields,
		RequestID: RequestIDFrom(r.Context()),
	}})
}
