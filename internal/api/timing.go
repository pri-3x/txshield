package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pri-3x/txshield/internal/analyzer"
	"github.com/pri-3x/txshield/internal/metrics"
)

// observeStages records per-stage latency in Prometheus and in a
// Server-Timing header, so callers (the extension, browser dev tools) can see
// where the time went. Stage names and durations only; nothing about the
// transaction.
func observeStages(m *metrics.Metrics, w http.ResponseWriter, t *analyzer.Timings) {
	stages := []struct {
		name string
		d    time.Duration
	}{
		{"decode", t.Decode}, {"block", t.Block}, {"simulate", t.Simulate},
		{"context", t.Context}, {"rules", t.Rules}, {"tokens", t.Tokens}, {"total", t.Total},
	}
	parts := make([]string, 0, len(stages))
	for _, st := range stages {
		if st.name != "total" {
			m.AnalysisStage.WithLabelValues(st.name).Observe(st.d.Seconds())
		}
		parts = append(parts, fmt.Sprintf("%s;dur=%.1f", st.name, float64(st.d.Microseconds())/1000))
	}
	w.Header().Set("Server-Timing", strings.Join(parts, ", "))
}
