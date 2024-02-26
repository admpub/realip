package realip

import (
	"net/http"
	"os"
	"testing"
)

func TestCanonicalHeaderKey(t *testing.T) {
	if http.CanonicalHeaderKey("X-Forwarded-For") != HeaderXForwardedFor {
		t.Fatalf("HeaderXForwardedFor: expected %s but get %s", http.CanonicalHeaderKey("X-Forwarded-For"), HeaderXForwardedFor)
	}
	if http.CanonicalHeaderKey("X-Real-IP") != HeaderXRealIP {
		t.Fatalf("HeaderXRealIP: expected %s but get %s", http.CanonicalHeaderKey("X-Real-IP"), HeaderXRealIP)
	}
	if http.CanonicalHeaderKey("Forwarded") != HeaderForwarded {
		t.Fatalf("HeaderForwarded: expected %s but get %s", http.CanonicalHeaderKey("Forwarded"), HeaderForwarded)
	}
}

func TestIsPrivateAddr(t *testing.T) {
	testData := map[string]bool{
		"127.0.0.0":   true,
		"10.0.0.0":    true,
		"169.254.0.0": true,
		"192.168.0.0": true,
		"::1":         true,
		"fc00::":      true,

		"172.15.0.0": false,
		"172.16.0.0": true,
		"172.31.0.0": true,
		"172.32.0.0": false,

		"147.12.56.11": false,
	}

	for addr, isLocal := range testData {
		isPrivate, err := IsPrivateAddress(addr)
		if err != nil {
			t.Errorf("fail processing %s: %v", addr, err)
		}

		if isPrivate != isLocal {
			format := "%s should "
			if !isLocal {
				format += "not "
			}
			format += "be local address"

			t.Errorf(format, addr)
		}
	}
}

func TestRealIP(t *testing.T) {
	// Create type and function for testing
	type testIP struct {
		name     string
		request  *http.Request
		expected string
	}

	newRequest := func(remoteAddr, xRealIP string, xForwardedFor ...string) *http.Request {
		h := http.Header{}
		h.Set("X-Real-IP", xRealIP)
		for _, address := range xForwardedFor {
			h.Set("X-Forwarded-For", address)
		}

		return &http.Request{
			RemoteAddr: remoteAddr,
			Header:     h,
		}
	}

	// Create test data
	publicAddr1 := "144.12.54.87"
	publicAddr2 := "119.14.55.11"
	localAddr := "127.0.0.0"

	testData := []testIP{
		{
			name:     "No header",
			request:  newRequest(publicAddr1, ""),
			expected: publicAddr1,
		}, {
			name:     "Has X-Forwarded-For",
			request:  newRequest("127.0.0.100", "", publicAddr1),
			expected: publicAddr1,
		}, {
			name:     "Has multiple X-Forwarded-For",
			request:  newRequest("127.0.0.100", "", localAddr, publicAddr1, publicAddr2),
			expected: publicAddr2,
		}, {
			name:     "Has X-Real-IP",
			request:  newRequest("127.0.0.100", publicAddr1),
			expected: publicAddr1,
		},
	}

	// Run test
	for _, v := range testData {
		if actual := FromRequest(v.request); v.expected != actual {
			t.Errorf("%s: expected %s but get %s", v.name, v.expected, actual)
		}
	}
}

func TestClientIP(t *testing.T) {
	header := func(name string) string {
		t.Logf(`----------------> %s`, name)
		switch name {
		case HeaderForwarded:
			return ``
		case HeaderXForwardedFor:
			return `119.14.55.13,119.14.55.12,119.14.55.11`
		case HeaderXRealIP:
			return `119.14.55.11`
		default:
			return ``
		}
	}
	defaultConfig.SetTrustedProxies([]string{})
	actual := defaultConfig.ClientIP(`127.0.0.1:53878`, header)
	expected := `127.0.0.1`
	if expected != actual {
		t.Errorf("TestClientIP: expected %s but get %s", expected, actual)
	}

	os.Setenv(EnvKey, `127.0.0.1,119.14.55.11`)
	defaultConfig.SetTrustedProxiesByEnv()
	actual = defaultConfig.ClientIP(`127.0.0.1:53878`, header)
	expected = `119.14.55.12`
	if expected != actual {
		t.Errorf("TestClientIP: expected %s but get %s", expected, actual)
	}

	defaultConfig.TrustAll()
	os.Setenv(EnvKey, ``)
	defaultConfig.SetTrustedProxiesByEnv()
	actual = defaultConfig.ClientIP(`127.0.0.1:53878`, header)
	expected = `119.14.55.13`
	if expected != actual {
		t.Errorf("TestClientIP: expected %s but get %s", expected, actual)
	}
}
