package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"

	"github.com/txshield/txshield/pkg/txerrors"
)

// decodeJSON strictly decodes a single JSON object from the request body:
// unknown fields are rejected (typos in security-relevant fields such as
// "maxFeePerGas" must not be silently ignored), trailing data is rejected,
// and body-limit violations map to payload_too_large.
func decodeJSON(r *http.Request, dst any) error {
	if ct := r.Header.Get("Content-Type"); ct != "" {
		mt, _, err := mime.ParseMediaType(ct)
		if err != nil || mt != "application/json" {
			return txerrors.New(txerrors.KindInvalidInput, "unsupported_media_type", "Content-Type must be application/json")
		}
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return jsonError(err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if isBodyTooLarge(err) {
			return jsonError(err)
		}
		return txerrors.New(txerrors.KindInvalidInput, "invalid_json", "request body must contain a single JSON object")
	}
	return nil
}

func jsonError(err error) error {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case isBodyTooLarge(err):
		return txerrors.Wrap(err, txerrors.KindPayloadTooLarge, "body_too_large", "request body too large")
	case errors.Is(err, io.EOF):
		return txerrors.New(txerrors.KindInvalidInput, "invalid_json", "request body is empty")
	case errors.As(err, &syn):
		return txerrors.New(txerrors.KindInvalidInput, "invalid_json", fmt.Sprintf("malformed JSON at offset %d", syn.Offset))
	case errors.As(err, &typ):
		return txerrors.Invalid(txerrors.FieldError{Field: typ.Field, Message: "has the wrong JSON type, expected " + typ.Type.String()})
	default:
		// Covers "json: unknown field" and similar decoder messages; these
		// contain only the field name, which is safe to echo.
		return txerrors.New(txerrors.KindInvalidInput, "invalid_json", err.Error())
	}
}
