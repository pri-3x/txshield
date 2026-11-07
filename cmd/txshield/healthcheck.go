package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// runHealthcheck probes a TxShield server. It exists so the distroless
// container image (no shell, no curl) can define a Docker HEALTHCHECK.
// Only loopback/explicit URLs are probed; it is not a general HTTP client.
func runHealthcheck(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	target := fs.String("url", "http://127.0.0.1:8080/health", "health endpoint to probe")
	timeout := fs.Duration("timeout", 3*time.Second, "request timeout")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	u, err := url.Parse(*target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		fmt.Fprintln(stderr, "healthcheck: --url must be an http(s) URL")
		return ExitUsage
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		fmt.Fprintf(stderr, "healthcheck: %v\n", err)
		return ExitError
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "healthcheck: %v\n", err)
		return ExitError
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "healthcheck: status %d\n", resp.StatusCode)
		return ExitError
	}
	fmt.Fprintln(stdout, "ok")
	return ExitOK
}
