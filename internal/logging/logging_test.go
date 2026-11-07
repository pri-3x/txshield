package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestSanitize(t *testing.T) {
	cases := map[string]string{
		"USDC":                  "USDC",
		"line1\nFAKE log entry": "line1\\nFAKE log entry",
		"\x1b[31mred":           "\\u001b[31mred",
		"bidi\u202eevil":        "bidi\\u202eevil",
		"bad\xffutf8":           "bad\\ufffdutf8",
		"\u00fcn\u00efcode ok":  "\u00fcn\u00efcode ok",
	}
	for in, want := range cases {
		if got := Sanitize(in, 100); got != want {
			t.Errorf("Sanitize(%q) = %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("a", 300)
	got := Sanitize(long, 10)
	if got != strings.Repeat("a", 10)+"...[truncated]" {
		t.Fatalf("truncation wrong: %q", got)
	}
	if Sanitize("abc", 3) != "abc" {
		t.Fatal("exact-length string must not be truncated")
	}
}

func TestNewJSONAndContext(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, "debug", "json")
	ctx := WithLogger(context.Background(), l.With("request_id", "abc"))
	FromContext(ctx).Debug("hello")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("not JSON: %q", buf.String())
	}
	if rec["request_id"] != "abc" || rec["msg"] != "hello" {
		t.Fatalf("unexpected record: %v", rec)
	}
	if FromContext(context.Background()) == nil {
		t.Fatal("FromContext must fall back to default logger")
	}
}
