// Package metrics defines TxShield's Prometheus metrics on a dedicated
// registry (no global state, so tests can create isolated instances).
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics holds all collectors.
type Metrics struct {
	Registry *prometheus.Registry

	HTTPRequests *prometheus.CounterVec
	HTTPDuration *prometheus.HistogramVec
	HTTPInFlight prometheus.Gauge
	HealthStatus *prometheus.GaugeVec

	RateLimited      prometheus.Counter
	Analyses         *prometheus.CounterVec
	AnalysisDuration prometheus.Histogram
	Simulations      *prometheus.CounterVec
	StoreErrors      prometheus.Counter
}

// New creates and registers all collectors.
func New(version, commit string) *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		Registry: reg,
		HTTPRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "txshield", Subsystem: "http", Name: "requests_total",
			Help: "HTTP requests by method, route pattern, and status code.",
		}, []string{"method", "route", "code"}),
		HTTPDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "txshield", Subsystem: "http", Name: "request_duration_seconds",
			Help:    "HTTP request latency by method and route pattern.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30},
		}, []string{"method", "route"}),
		HTTPInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "txshield", Subsystem: "http", Name: "in_flight_requests",
			Help: "HTTP requests currently being served.",
		}),
		HealthStatus: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "txshield", Name: "dependency_up",
			Help: "1 if the dependency's last health check succeeded, else 0.",
		}, []string{"dependency"}),
	}
	m.RateLimited = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "txshield", Name: "rate_limited_total", Help: "Requests rejected by the rate limiter.",
	})
	m.Analyses = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "txshield", Name: "analyses_total", Help: "Completed analyses by risk category.",
	}, []string{"category"})
	m.AnalysisDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "txshield", Name: "analysis_duration_seconds", Help: "End-to-end analysis latency.",
		Buckets: []float64{.01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30},
	})
	m.Simulations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "txshield", Name: "simulations_total", Help: "Simulations by backend, status, and completeness.",
	}, []string{"backend", "status", "completeness"})
	m.StoreErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "txshield", Name: "store_errors_total", Help: "Failed persistence operations.",
	})
	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "txshield", Name: "build_info",
		Help: "Build information; value is always 1.",
	}, []string{"version", "commit"})
	buildInfo.WithLabelValues(version, commit).Set(1)

	reg.MustRegister(
		m.HTTPRequests, m.HTTPDuration, m.HTTPInFlight, m.HealthStatus, buildInfo,
		m.RateLimited, m.Analyses, m.AnalysisDuration, m.Simulations, m.StoreErrors,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}
