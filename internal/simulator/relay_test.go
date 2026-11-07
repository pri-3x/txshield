package simulator

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestForkRelay(t *testing.T) {
	var hits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/v2/SECRETKEY" {
			t.Errorf("relay changed the upstream path: %s", r.URL.Path)
		}
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":"0x1"}`)
	}))
	defer upstream.Close()
	secret := upstream.URL + "/v2/SECRETKEY"

	r := newForkRelay(0)
	defer r.close()
	u, err := r.url(secret)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(u, "SECRETKEY") || !strings.HasPrefix(u, "http://127.0.0.1:") {
		t.Fatalf("relay URL %s", u)
	}
	if again, _ := r.url(secret); again != u {
		t.Fatal("same upstream must reuse its token")
	}

	post := func(url, body string) (int, string) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	if code, body := post(u, `{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":[]}`); code != 200 || !strings.Contains(body, `"0x1"`) {
		t.Fatalf("read not relayed: %d %s", code, body)
	}
	if code, _ := post(u, `[{"jsonrpc":"2.0","id":1,"method":"eth_getCode"},{"jsonrpc":"2.0","id":2,"method":"eth_chainId"}]`); code != 200 {
		t.Fatalf("batch read not relayed: %d", code)
	}
	before := hits.Load()
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0x00"]}`,
		`[{"jsonrpc":"2.0","id":1,"method":"eth_chainId"},{"jsonrpc":"2.0","id":2,"method":"eth_sendTransaction"}]`,
		`{"jsonrpc":"2.0","id":1,"method":"anvil_setBalance"}`,
		`{"jsonrpc":"2.0","id":1,"method":"personal_unlockAccount"}`,
		`{"jsonrpc":"2.0","id":1}`,
		`not json`,
		`[]`,
	} {
		if code, _ := post(u, body); code < 400 {
			t.Errorf("forwarded %s (%d)", body, code)
		}
	}
	if hits.Load() != before {
		t.Fatal("refused requests reached the upstream")
	}

	base := u[:strings.Index(u, "/fork/")]
	if code, _ := post(base+"/fork/"+strings.Repeat("0", 32), `{"method":"eth_chainId"}`); code != 404 {
		t.Fatalf("unknown token: %d", code)
	}
	if code, _ := post(base+"/", `{"method":"eth_chainId"}`); code != 404 {
		t.Fatalf("no token: %d", code)
	}

	// Upstream failures must not echo the upstream URL back to anvil
	// (anvil may print it).
	upstream.Close()
	if code, body := post(u, `{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}`); code != 502 || strings.Contains(body, "SECRETKEY") || strings.Contains(body, "127.0.0.1") {
		t.Fatalf("upstream failure: %d %q", code, body)
	}
}

func TestReadListenAddr(t *testing.T) {
	out := make(chan string, 1)
	banner := strings.Repeat("Available Accounts\n==================\n", 50) +
		"Listening on 0.0.0.0:1234\n" + // not loopback: ignored
		"Listening on 127.0.0.1:58948\n" +
		"eth_blockNumber\n"
	readListenAddr(strings.NewReader(banner), out)
	select {
	case got := <-out:
		if got != "127.0.0.1:58948" {
			t.Fatalf("got %s", got)
		}
	case <-time.After(time.Second):
		t.Fatal("no address")
	}
}
