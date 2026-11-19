package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/pri-3x/txshield/pkg/txerrors"
)

// Anonymous install tokens let a browser extension use the API without an
// account and without a shared secret baked into the extension (anything
// shipped in an extension is public). A token is a random ID plus an HMAC
// over it, so the server verifies tokens without storing them: nothing
// about who installed the extension is recorded.
//
// Requests that carry an install token may only call installRoutes, are
// rate limited per token as well as per IP, and are never persisted.

const (
	installPrefix = "txsi_"
	installIDLen  = 16
	installMACLen = 16
	// Tokens issued per IP: a burst of 5, then one every 12 minutes.
	installIssueBurst = 5
	installIssueRPS   = 1.0 / 720
)

// installRoutes are the operations an install token may call.
var installRoutes = map[string]bool{
	"POST /api/v1/analyze": true,
	"POST /api/v1/decode":  true,
	"GET /api/v1/info":     true,
}

type installIssuer struct {
	key    []byte
	issue  *rateLimiter // per IP, for POST /api/v1/install
	use    *rateLimiter // per token
	random func([]byte) (int, error)
}

func newInstallIssuer(secret string, rps float64, burst int) *installIssuer {
	key := []byte(secret)
	if len(key) == 0 {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			panic("crypto/rand failed: " + err.Error())
		}
	}
	return &installIssuer{
		key:    key,
		issue:  newRateLimiter(installIssueRPS, installIssueBurst),
		use:    newRateLimiter(rps, burst),
		random: rand.Read,
	}
}

func (i *installIssuer) mac(id []byte) []byte {
	h := hmac.New(sha256.New, i.key)
	h.Write([]byte("txshield-install-v1:"))
	h.Write(id)
	return h.Sum(nil)[:installMACLen]
}

func (i *installIssuer) newToken() (string, error) {
	id := make([]byte, installIDLen)
	if _, err := i.random(id); err != nil {
		return "", err
	}
	return installPrefix + base64.RawURLEncoding.EncodeToString(append(id, i.mac(id)...)), nil
}

// verify returns the token's ID when its signature is valid.
func (i *installIssuer) verify(token string) (string, bool) {
	rest, ok := strings.CutPrefix(token, installPrefix)
	if !ok {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil || len(raw) != installIDLen+installMACLen {
		return "", false
	}
	id, sig := raw[:installIDLen], raw[installIDLen:]
	if !hmac.Equal(sig, i.mac(id)) {
		return "", false
	}
	return string(id), true
}

type installCtxKey struct{}

// isInstallRequest reports whether the request was authenticated with an
// install token (and must therefore never be persisted).
func isInstallRequest(ctx context.Context) bool {
	v, _ := ctx.Value(installCtxKey{}).(bool)
	return v
}

// InstallResponse is the response of POST /api/v1/install.
type InstallResponse struct {
	// Token is sent as "Authorization: Bearer <token>". It identifies no
	// person or device and is not stored by the server.
	Token string `json:"token"`
	// Scope lists the operations the token may call.
	Scope []string `json:"scope"`
	// Note states how requests made with the token are handled.
	Note string `json:"note"`
}

// handleInstall serves POST /api/v1/install.
func (s *Server) handleInstall(w http.ResponseWriter, r *http.Request) {
	if s.install == nil {
		writeError(w, r, txerrors.New(txerrors.KindUnsupported, "install_tokens_disabled", "install tokens are not enabled on this server"))
		return
	}
	if ok, wait := s.install.issue.allow(rateKey(clientIP(r, s.cfg.API.TrustProxyHeaders))); !ok {
		s.metrics.RateLimited.Inc()
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
		writeError(w, r, txerrors.New(txerrors.KindRateLimited, "rate_limited", "too many install tokens requested; retry later"))
		return
	}
	tok, err := s.install.newToken()
	if err != nil {
		writeError(w, r, err)
		return
	}
	scope := make([]string, 0, len(installRoutes))
	for _, op := range []string{"POST /api/v1/analyze", "POST /api/v1/decode", "GET /api/v1/info"} {
		if installRoutes[op] {
			scope = append(scope, op)
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, InstallResponse{
		Token: tok, Scope: scope,
		Note: "Analyses made with this token are never stored. The token identifies no person or device.",
	})
}

// authenticate checks install tokens and API keys on /api/ routes. API keys
// keep their previous behavior: required when configured, otherwise the API
// is open. Install tokens are accepted whether or not keys are configured.
func authenticate(keys []string, inst *installIssuer) func(http.Handler) http.Handler {
	keyCheck := apiKeyAuth(keys)
	return func(next http.Handler) http.Handler {
		keyed := keyCheck(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, "/api/") || r.Method == http.MethodOptions || r.URL.Path == "/api/v1/openapi.json" {
				next.ServeHTTP(w, r)
				return
			}
			token, hasBearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			token = strings.TrimSpace(token)
			if inst != nil && hasBearer && strings.HasPrefix(token, installPrefix) {
				id, ok := inst.verify(token)
				if !ok {
					w.Header().Set("WWW-Authenticate", `Bearer realm="txshield", error="invalid_token"`)
					writeJSON(w, http.StatusUnauthorized, ErrorBody{Error: ErrorDetail{
						Kind: txerrors.KindInvalidInput, Code: "invalid_install_token", Message: "the install token is not valid on this server; request a new one", RequestID: RequestIDFrom(r.Context()),
					}})
					return
				}
				if !installRoutes[r.Method+" "+r.URL.Path] {
					writeJSON(w, http.StatusForbidden, ErrorBody{Error: ErrorDetail{
						Kind: txerrors.KindInvalidInput, Code: "forbidden", Message: "install tokens may only analyze transactions", RequestID: RequestIDFrom(r.Context()),
					}})
					return
				}
				if ok, wait := inst.use.allow(id); !ok {
					w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
					writeError(w, r, txerrors.New(txerrors.KindRateLimited, "rate_limited", "too many requests; retry later"))
					return
				}
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), installCtxKey{}, true)))
				return
			}
			if inst != nil && r.Method == http.MethodPost && r.URL.Path == "/api/v1/install" {
				next.ServeHTTP(w, r) // issuance: anonymous, rate limited per IP
				return
			}
			keyed.ServeHTTP(w, r)
		})
	}
}
