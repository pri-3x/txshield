package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/txshield/txshield/internal/logging"
	"github.com/txshield/txshield/internal/metrics"
	"github.com/txshield/txshield/pkg/txerrors"
)

// RequestIDHeader carries the request ID in both directions.
const RequestIDHeader = "X-Request-ID"

var validRequestID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

type requestIDKey struct{}

// RequestIDFrom returns the request ID stored in ctx, if any.
func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

func newRequestID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b[:])
}

// statusRecorder captures the response status for logs and metrics.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *statusRecorder) code() int {
	if s.status == 0 {
		return http.StatusOK
	}
	return s.status
}

// requestID accepts a well-formed incoming X-Request-ID (so callers can
// correlate) or generates one, and attaches a request-scoped logger.
func requestID(base *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get(RequestIDHeader)
			if !validRequestID.MatchString(id) {
				id = newRequestID()
			}
			w.Header().Set(RequestIDHeader, id)
			ctx := context.WithValue(r.Context(), requestIDKey{}, id)
			ctx = logging.WithLogger(ctx, base.With("request_id", id))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// recoverer converts panics into structured 500 responses. A panic in a
// handler must never take down the server or leak a stack trace to clients.
func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if err, ok := v.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(v)
				}
				logging.FromContext(r.Context()).Error("panic recovered",
					"panic", v, "stack", string(debug.Stack()))
				writeError(w, r, txerrors.New(txerrors.KindInternal, "internal_error", "internal server error"))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// accessLog writes one structured line per request. Path and user agent are
// attacker-controlled and therefore sanitized.
func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		logging.FromContext(r.Context()).Info("http request",
			"method", r.Method,
			"path", logging.Sanitize(r.URL.Path, 200),
			"status", rec.code(),
			"bytes", rec.bytes,
			"duration_ms", time.Since(start).Milliseconds(),
			"user_agent", logging.Sanitize(r.UserAgent(), 120),
		)
	})
}

// timeout attaches a deadline to the request context. Handlers and the engine
// must honor ctx; http.TimeoutHandler is not used because it buffers whole
// responses and hides the deadline from downstream code.
func timeout(d time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), d)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// bodyLimit caps request bodies. Handlers that decode JSON translate
// *http.MaxBytesError into a payload_too_large error (see decodeJSON).
func bodyLimit(n int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > n {
				writeError(w, r, txerrors.New(txerrors.KindPayloadTooLarge, "body_too_large", "request body too large"))
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, n)
			next.ServeHTTP(w, r)
		})
	}
}

// instrument records Prometheus metrics. It must wrap the ServeMux directly:
// the mux sets r.Pattern on the request it receives, and the route pattern
// (not the raw path) is used as the label to keep cardinality bounded.
func instrument(m *metrics.Metrics, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		m.HTTPInFlight.Inc()
		defer m.HTTPInFlight.Dec()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		route := r.Pattern
		if route == "" {
			route = "unmatched"
		}
		m.HTTPRequests.WithLabelValues(r.Method, route, strconv.Itoa(rec.code())).Inc()
		m.HTTPDuration.WithLabelValues(r.Method, route).Observe(time.Since(start).Seconds())
	})
}

// isBodyTooLarge reports whether err came from http.MaxBytesReader.
func isBodyTooLarge(err error) bool {
	var mbe *http.MaxBytesError
	return errors.As(err, &mbe)
}
