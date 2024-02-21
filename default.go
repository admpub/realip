package realip

import (
	"net"
	"net/http"
	"strings"
)

var defaultConfig = New().SetIgnorePrivateIP(true)

func Default() *Config {
	return defaultConfig
}

var defaultTrustedProxies = []string{"0.0.0.0/0", "::/0"}
var defaultUnsafeTrustedIPs = []net.IP{net.ParseIP("0.0.0.0"), net.ParseIP("::")}
var defaultTrustedCIDRs = []*net.IPNet{
	{ // 0.0.0.0/0 (IPv4)
		IP:   net.IP{0x0, 0x0, 0x0, 0x0},
		Mask: net.IPMask{0x0, 0x0, 0x0, 0x0},
	},
	{ // ::/0 (IPv6)
		IP:   net.IP{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		Mask: net.IPMask{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
	},
}

// Should use canonical format of the header key s
// https://golang.org/pkg/net/http/#CanonicalHeaderKey
var headerXForwardedFor = http.CanonicalHeaderKey("X-Forwarded-For")
var headerXRealIP = http.CanonicalHeaderKey("X-Real-IP")

// RFC7239 defines a new "Forwarded: " header designed to replace the
// existing use of X-Forwarded-* headers.
// e.g. Forwarded: for=192.0.2.60;proto=https;by=203.0.113.43
var headerForwarded = http.CanonicalHeaderKey("Forwarded")

func HeaderIsXForwardedFor(headerName string) bool {
	return headerXForwardedFor == http.CanonicalHeaderKey(headerName)
}

func HeaderIsXRealIP(headerName string) bool {
	return headerXRealIP == http.CanonicalHeaderKey(headerName)
}

func HeaderForwarded(headerName string) bool {
	return headerForwarded == http.CanonicalHeaderKey(headerName)
}

func HeaderEquals(headerNameA string, headerNameB string) bool {
	return strings.EqualFold(headerNameA, headerNameB)
}

var defaultPrivateCIDRs []*net.IPNet

func init() {
	maxCidrBlocks := []string{
		"127.0.0.1/8",    // localhost
		"10.0.0.0/8",     // 24-bit block
		"172.16.0.0/12",  // 20-bit block
		"192.168.0.0/16", // 16-bit block
		"169.254.0.0/16", // link local address
		"::1/128",        // localhost IPv6
		"fc00::/7",       // unique local address IPv6
		"fe80::/10",      // link local address IPv6
	}

	defaultPrivateCIDRs = make([]*net.IPNet, len(maxCidrBlocks))
	for i, maxCidrBlock := range maxCidrBlocks {
		cidr, err := ParseCIDR(maxCidrBlock)
		if err != nil {
			panic(err)
		}
		defaultPrivateCIDRs[i] = cidr
	}
}
