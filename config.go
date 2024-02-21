package realip

import (
	"net"
	"os"
	"strings"
)

const EnvKey = `REALIP_TRUSTED_PROXIES`

func New() *Config {
	c := &Config{}
	c.Init()
	c.SetTrustedProxiesByEnv()
	return c
}

type Config struct {

	// ForwardedByClientIP if enabled, client IP will be parsed from the request's headers that
	// match those stored at `Config.RemoteIPHeaders`. If no IP was
	// fetched, it falls back to the IP obtained from
	// `Context.Request().RemoteAddress()`.
	ForwardedByClientIP bool
	// RemoteIPHeaders list of headers used to obtain the client IP when
	// `Config.ForwardedByClientIP` is `true` and
	// `Context.Request().RemoteAddress()` is matched by at least one of the
	// network origins of list defined by `Config.SetTrustedProxies()`.
	RemoteIPHeaders []string

	ignorePrivateIP bool
	trustedProxies  []string
	trustedCIDRs    []*net.IPNet
}

func (c *Config) Init() *Config {
	c.ForwardedByClientIP = true
	c.RemoteIPHeaders = []string{headerForwarded, headerXForwardedFor, headerXRealIP}
	c.ignorePrivateIP = false
	return c.TrustAll()
}

func (c *Config) SetIgnorePrivateIP(ignorePrivateIP bool) *Config {
	c.ignorePrivateIP = ignorePrivateIP
	return c
}

func (c *Config) SetForwardedByClientIP(forwardedByClientIP bool) *Config {
	c.ForwardedByClientIP = forwardedByClientIP
	return c
}

func (c *Config) SetRemoteIPHeaders(remoteIPHeaders ...string) *Config {
	c.RemoteIPHeaders = remoteIPHeaders
	return c
}

func (c *Config) AddRemoteIPHeader(remoteIPHeaders ...string) *Config {
	c.RemoteIPHeaders = append(c.RemoteIPHeaders, remoteIPHeaders...)
	return c
}

func (c *Config) IgnorePrivateIP() bool {
	return c.ignorePrivateIP
}

func (c *Config) prepareTrustedCIDRs() ([]*net.IPNet, error) {
	if c.trustedProxies == nil {
		return nil, nil
	}

	cidr := make([]*net.IPNet, 0, len(c.trustedProxies))
	for _, trustedProxy := range c.trustedProxies {
		cidrNet, err := ParseCIDR(trustedProxy)
		if err != nil {
			return cidr, err
		}
		cidr = append(cidr, cidrNet)
	}
	return cidr, nil
}

// SetTrustedProxies set a list of network origins (IPv4 addresses,
// IPv4 CIDRs, IPv6 addresses or IPv6 CIDRs) from which to trust
// request's headers that contain alternative client IP when
// `Config.ForwardedByClientIP` is `true`. `TrustedProxies`
// feature is enabled by default, and it also trusts all proxies
// by default. If you want to disable this feature, use
// Config.SetTrustedProxies(nil), then Context.ClientIP() will
// return the remote address directly.
func (c *Config) SetTrustedProxies(trustedProxies []string) error {
	c.trustedProxies = trustedProxies
	return c.parseTrustedProxies()
}

func (c *Config) TrustAll() *Config {
	c.trustedProxies = make([]string, len(defaultTrustedProxies))
	copy(c.trustedProxies, defaultTrustedProxies)
	c.trustedCIDRs = defaultTrustedCIDRs
	return c
}

func (c *Config) SetTrustedProxiesByEnv() error {
	envValue := os.Getenv(EnvKey)
	if len(envValue) == 0 {
		return nil
	}
	items := strings.Split(envValue, `,`)
	trustedProxies := make([]string, 0, len(items))
	for _, tp := range items {
		tp = strings.TrimSpace(tp)
		if len(tp) > 0 {
			trustedProxies = append(trustedProxies, tp)
		}
	}
	if len(trustedProxies) > 0 {
		return c.SetTrustedProxies(trustedProxies)
	}
	return nil
}

// IsUnsafeTrustedProxies checks if Engine.trustedCIDRs contains all IPs, it's not safe if it has (returns true)
func (c *Config) IsUnsafeTrustedProxies() bool {
	for _, ip := range defaultUnsafeTrustedIPs {
		if c.isTrustedProxy(ip) {
			return true
		}
	}
	return false
}

// parseTrustedProxies parse Engine.trustedProxies to Engine.trustedCIDRs
func (c *Config) parseTrustedProxies() error {
	trustedCIDRs, err := c.prepareTrustedCIDRs()
	c.trustedCIDRs = trustedCIDRs
	return err
}

// isTrustedProxy will check whether the IP address is included in the trusted list according to Engine.trustedCIDRs
func (c *Config) isTrustedProxy(ip net.IP) bool {
	if c.trustedCIDRs == nil {
		return false
	}
	for _, cidr := range c.trustedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateIPHeader will parse X-Forwarded-For header and return the trusted client IP address
func (c *Config) ValidateIPHeader(headerValue string, headerName string, ignorePrivateIP bool) (clientIP string, valid bool) {
	if len(headerValue) == 0 {
		return
	}
	var items []string
	if headerName == headerForwarded {
		for _, item := range strings.Split(headerValue, ";") {
			item = strings.TrimSpace(item)
			if len(item) == 0 {
				continue
			}
			if !strings.HasPrefix(item, `for=`) {
				continue
			}
			for _, vfor := range strings.Split(item, ",") {
				vfor = strings.TrimSpace(vfor)
				if len(vfor) == 0 {
					continue
				}
				if !strings.HasPrefix(vfor, `for=`) {
					continue
				}
				vfor = strings.TrimPrefix(vfor, `for=`)
				vfor = strings.Trim(vfor, `"`)
				if len(vfor) == 0 {
					continue
				}
				items = append(items, vfor)
			}
		}
	} else {
		items = strings.Split(headerValue, ",")
	}
	for i := len(items) - 1; i >= 0; i-- {
		clientIP = strings.TrimSpace(items[i])
		if len(clientIP) == 0 {
			continue
		}
		ip := net.ParseIP(clientIP)
		if ip == nil {
			break
		}
		if ignorePrivateIP {
			isPrivate, err := IsPrivateIP(ip)
			if err != nil || isPrivate {
				continue
			}
		}
		// X-Forwarded-For is appended by proxy
		// Check IPs in reverse order and stop when find untrusted proxy
		// 如果客户端伪造 IP 地址，格式为：X-Forwarded-For: 伪造的 IP 地址 1, [伪造的 IP 地址 2...], IP0(client), IP1(proxy), IP2(proxy)。
		if i == 0 || !c.isTrustedProxy(ip) {
			valid = true
			return
		}
	}
	return
}

// ClientIP implements one best effort algorithm to return the real client IP.
// It calls c.RemoteIP() under the hood, to check if the remote IP is a trusted proxy or not.
// If it is it will then try to parse the headers defined in Engine.RemoteIPHeaders (defaulting to [X-Forwarded-For, X-Real-Ip]).
// If the headers are not syntactically valid OR the remote IP does not correspond to a trusted proxy,
// the remote IP (coming from Request.RemoteAddr) is returned.
func (c *Config) ClientIP(remoteAddress string, header func(string) string) string {
	// It also checks if the remoteIP is a trusted proxy or not.
	// In order to perform this validation, it will see if the IP is contained within at least one of the CIDR blocks
	// defined by Config.SetTrustedProxies()
	remoteAddress = c.RemoteIP(remoteAddress)
	if len(remoteAddress) == 0 {
		return ""
	}
	remoteIP := net.ParseIP(remoteAddress)
	if remoteIP == nil {
		return ""
	}
	trusted := c.isTrustedProxy(remoteIP)

	if trusted && c.ForwardedByClientIP && c.RemoteIPHeaders != nil {
		for _, headerName := range c.RemoteIPHeaders {
			ip, valid := c.ValidateIPHeader(header(headerName), headerName, c.ignorePrivateIP)
			if valid {
				return ip
			}
		}
	}
	return remoteIP.String()
}

// RemoteIP parses the IP from Request.RemoteAddr, normalizes and returns the IP (without the port).
func (c *Config) RemoteIP(remoteAddress string) string {
	remoteAddress = strings.TrimSpace(remoteAddress)
	if len(remoteAddress) == 0 {
		return ""
	}
	var cutset string
	if remoteAddress[0] == '[' {
		cutset = `]:`
	} else {
		cutset = `:`
	}
	if !strings.Contains(remoteAddress, cutset) {
		return remoteAddress
	}
	ip, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		return ""
	}
	return ip
}
