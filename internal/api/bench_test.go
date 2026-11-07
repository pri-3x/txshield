package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// BenchmarkAPIAnalyzeParallel measures concurrent POST /api/v1/analyze
// throughput through the full middleware chain with an offline engine (no
// RPC, no simulation, no persistence), i.e. the API's own overhead.
func BenchmarkAPIAnalyzeParallel(b *testing.B) {
	t := &testing.T{}
	s := engineServer(t, nil, nil)
	body, _ := json.Marshal(map[string]any{"chainId": 1, "from": sender, "to": usdc, "data": approveMax})
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequestWithContext(b.Context(), "POST", "/api/v1/analyze", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			s.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				b.Errorf("status %d", rr.Code)
				return
			}
		}
	})
}
