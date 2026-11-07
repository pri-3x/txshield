// Package version exposes build information injected via -ldflags.
package version

// Set at build time:
//
//	go build -ldflags "-X github.com/txshield/txshield/internal/version.Version=v0.1.0 \
//	  -X github.com/txshield/txshield/internal/version.Commit=$(git rev-parse --short HEAD)"
var (
	Version = "dev"
	Commit  = "unknown"
)
