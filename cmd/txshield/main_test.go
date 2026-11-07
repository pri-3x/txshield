package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pri-3x/txshield/internal/config"
)

func TestRunDispatch(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(context.Background(), nil, &out, &errb); code != ExitUsage {
		t.Fatalf("no args: code %d", code)
	}
	if code := run(context.Background(), []string{"bogus"}, &out, &errb); code != ExitUsage {
		t.Fatalf("unknown cmd: code %d", code)
	}
	if code := run(context.Background(), []string{"help"}, &out, &errb); code != ExitOK {
		t.Fatalf("help: code %d", code)
	}
	out.Reset()
	if code := run(context.Background(), []string{"version", "--json"}, &out, &errb); code != ExitOK || !strings.Contains(out.String(), `"version"`) {
		t.Fatalf("version: code %d out %q", code, out.String())
	}
	out.Reset()
	if code := run(context.Background(), []string{"--version"}, &out, &errb); code != ExitOK || !strings.HasPrefix(out.String(), "txshield ") {
		t.Fatalf("--version: code %d out %q", code, out.String())
	}
	if code := run(context.Background(), []string{"version", "--nope"}, &out, &errb); code != ExitUsage {
		t.Fatalf("bad flag: code %d", code)
	}
}

// TestServeGracefulShutdown starts the real server on an ephemeral port,
// verifies /health, cancels the context, and checks for a clean exit.
func TestServeGracefulShutdown(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg := config.Defaults()
	cfg.HTTP.Addr = addr
	cfg.HTTP.ShutdownTimeout = 5 * time.Second
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, cfg, log) }()

	var resp *http.Response
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+"/health", nil)
		resp, err = http.DefaultClient.Do(req)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("server never became reachable: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("health = %d", resp.StatusCode)
	}

	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"healthcheck", "--url", "http://" + addr + "/health"}, &out, &errb); code != ExitOK {
		t.Fatalf("healthcheck cmd = %d: %s", code, errb.String())
	}
	if code := run(context.Background(), []string{"healthcheck", "--url", "http://" + addr + "/nope"}, &out, &errb); code != ExitError {
		t.Fatalf("healthcheck on 404 = %d, want %d", code, ExitError)
	}
	if code := run(context.Background(), []string{"healthcheck", "--url", "file:///etc/passwd"}, &out, &errb); code != ExitUsage {
		t.Fatalf("healthcheck non-http = %d, want usage", code)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not shut down")
	}
}
