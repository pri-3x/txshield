package api

import (
	_ "embed"
	"net/http"
)

// openAPISpec is the OpenAPI 3.1 description of this API (api/openapi.json
// is the source; this embedded copy is served at /api/v1/openapi.json).
//
//go:embed openapi.json
var openAPISpec []byte

func (s *Server) handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(openAPISpec)
}
