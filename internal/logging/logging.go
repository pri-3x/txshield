// Package logging configures structured logging and provides helpers for
// safely logging untrusted values.
package logging

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"unicode"
	"unicode/utf8"
)

// New builds a slog.Logger writing to w in the given format ("json"/"text")
// at the given level ("debug"/"info"/"warn"/"error").
func New(w io.Writer, level, format string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	if format == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}

// DefaultMaxLen bounds sanitized strings in logs.
const DefaultMaxLen = 256

// Sanitize makes an untrusted string safe to log: invalid UTF-8 and control
// characters (including newlines and ANSI escape introducers) are replaced
// with escaped forms, and the result is truncated to max runes. Use it for
// any value that originates from a request, a contract, or an RPC response
// (token symbols, revert reasons, user agents, paths).
func Sanitize(s string, max int) string {
	if max <= 0 {
		max = DefaultMaxLen
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if n >= max {
			b.WriteString("...[truncated]")
			break
		}
		switch {
		case r == utf8.RuneError && size == 1:
			b.WriteString(`\ufffd`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case unicode.IsControl(r) || r == '\u2028' || r == '\u2029' || unicode.Is(unicode.Bidi_Control, r):
			b.WriteString(`\u`)
			const hex = "0123456789abcdef"
			b.WriteByte(hex[(r>>12)&0xf])
			b.WriteByte(hex[(r>>8)&0xf])
			b.WriteByte(hex[(r>>4)&0xf])
			b.WriteByte(hex[r&0xf])
		default:
			b.WriteRune(r)
		}
		n++
	}
	return b.String()
}

type ctxKey struct{}

// WithLogger stores a request-scoped logger in ctx.
func WithLogger(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, l)
}

// FromContext returns the request-scoped logger, or slog.Default().
func FromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(ctxKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}
