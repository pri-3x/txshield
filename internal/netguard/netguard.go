// Package netguard prevents server-side request forgery when TxShield must
// contact a URL chosen by an API client (only when TXSHIELD_ALLOW_USER_RPC
// is enabled).
//
// Two layers:
//   - CheckURL validates the URL and every address its host resolves to.
//   - DialControl re-checks the IP actually being connected to, which
//     defeats DNS rebinding (a name that resolves to a public IP during the
//     check and to 127.0.0.1 at connect time).
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"syscall"
)

// ErrForbiddenAddress is returned for non-public destinations.
var ErrForbiddenAddress = errors.New("destination address is not a public internet address")

// blocked lists ranges that are not covered by netip's predicates.
var blocked = mustPrefixes(
	"0.0.0.0/8",          // "this network"
	"100.64.0.0/10",      // carrier-grade NAT
	"192.0.0.0/24",       // IETF protocol assignments
	"192.0.2.0/24",       // TEST-NET-1
	"198.18.0.0/15",      // benchmarking
	"198.51.100.0/24",    // TEST-NET-2
	"203.0.113.0/24",     // TEST-NET-3
	"240.0.0.0/4",        // reserved
	"255.255.255.255/32", // broadcast
	"2001:db8::/32",      // documentation
	"fec0::/10",          // deprecated site-local
	"100::/64",           // discard-only
	"::/96",              // deprecated IPv4-compatible (::a.b.c.d)
	"::ffff:0:0:0/96",    // SIIT IPv4-translated
	"64:ff9b:1::/48",     // local-use NAT64
	"2001:2::/48",        // benchmarking
	"2001:10::/28",       // ORCHID (non-routable)
	"2001:20::/28",       // ORCHIDv2 (non-routable)
	"3fff::/20",          // documentation (RFC 9637)
	"5f00::/16",          // SRv6 SIDs
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

var (
	nat64  = netip.MustParsePrefix("64:ff9b::/96")
	sixTo4 = netip.MustParsePrefix("2002::/16")
	teredo = netip.MustParsePrefix("2001::/32")
)

// IsPublic reports whether addr is a globally routable unicast address.
// IPv6 forms that embed an IPv4 address (mapped, NAT64, 6to4) are judged
// by the embedded address; Teredo is rejected outright.
func IsPublic(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	for _, p := range blocked {
		if p.Contains(addr) {
			return false
		}
	}
	if addr.Is6() {
		b := addr.As16()
		switch {
		case nat64.Contains(addr):
			return IsPublic(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
		case sixTo4.Contains(addr):
			return IsPublic(netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}))
		case teredo.Contains(addr):
			return false
		}
	}
	return true
}

// CheckURL validates a user-supplied endpoint: https only, explicit host,
// and every resolved address public.
func CheckURL(ctx context.Context, raw string, resolver *net.Resolver) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid URL")
	}
	if u.Scheme != "https" {
		return fmt.Errorf("only https URLs are accepted")
	}
	host := u.Hostname()
	if ip, err := netip.ParseAddr(host); err == nil {
		if !IsPublic(ip) {
			return ErrForbiddenAddress
		}
		return nil
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	addrs, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		return fmt.Errorf("host does not resolve")
	}
	for _, a := range addrs {
		if !IsPublic(a) {
			return ErrForbiddenAddress
		}
	}
	return nil
}

// DialControl is a net.Dialer Control hook that refuses connections to
// non-public addresses at connect time.
func DialControl(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("unparseable dial address: %w", err)
	}
	if !IsPublic(ap.Addr()) {
		return ErrForbiddenAddress
	}
	return nil
}
