package netguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestIsPublic(t *testing.T) {
	public := []string{"8.8.8.8", "1.1.1.1", "104.16.0.1", "2606:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808", "2002:808:808::1"}
	private := []string{
		"127.0.0.1", "10.0.0.1", "172.16.5.4", "192.168.1.1", "169.254.169.254", "0.0.0.0", "100.64.0.1",
		"192.0.2.1", "198.18.0.1", "240.0.0.1", "255.255.255.255", "224.0.0.1",
		"::1", "::", "fe80::1", "fc00::1", "fd00:ec2::254", "ff02::1", "2001:db8::1",
		"::ffff:127.0.0.1", "::ffff:169.254.169.254", "64:ff9b::7f00:1", "2002:7f00:1::1", "2001:0:4136:e378::1",
		"::7f00:1", "::a9fe:a9fe", "::ffff:0:7f00:1", "64:ff9b:1::a00:1", "2001:2::1", "2001:10::1", "2001:20::1", "3fff::1", "5f00::1",
	}
	for _, s := range public {
		if !IsPublic(netip.MustParseAddr(s)) {
			t.Errorf("%s should be public", s)
		}
	}
	for _, s := range private {
		if IsPublic(netip.MustParseAddr(s)) {
			t.Errorf("%s must be rejected", s)
		}
	}
}

func TestCheckURL(t *testing.T) {
	ctx := context.Background()
	for _, u := range []string{
		"http://8.8.8.8",               // not https
		"https://127.0.0.1:8545",       // loopback literal
		"https://[::1]/",               // v6 loopback
		"https://169.254.169.254/x",    // metadata
		"file:///etc/passwd",           // scheme
		"https://",                     // no host
		"https://localhost:8545",       // resolves to loopback
		"https://no-such-host.invalid", // does not resolve
	} {
		if err := CheckURL(ctx, u, nil); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
	if err := CheckURL(ctx, "https://8.8.8.8/rpc", nil); err != nil {
		t.Fatalf("public literal rejected: %v", err)
	}
}

func TestDialControlBlocksRebinding(t *testing.T) {
	d := net.Dialer{Control: DialControl}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	_, err = d.DialContext(context.Background(), "tcp", ln.Addr().String())
	if !errors.Is(err, ErrForbiddenAddress) {
		t.Fatalf("dial to loopback must be refused at connect time, got %v", err)
	}
	if DialControl("tcp", "garbage", nil) == nil {
		t.Fatal("unparseable address accepted")
	}
}
