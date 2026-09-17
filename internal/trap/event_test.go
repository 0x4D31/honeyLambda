package trap

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSourceAddressTrust(t *testing.T) {
	c, err := decode(strings.NewReader(strings.Replace(testConfig, `"version":2`, `"version":2,"trusted_proxies":["10.0.0.0/8","2001:db8:1::/48"]`, 1)), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, peer, forwarded, want, from string }{
		{"untrusted", "192.0.2.1:1234", "1.2.3.4", "192.0.2.1", "peer"},
		{"trusted", "10.0.0.1:1234", "192.0.2.1", "192.0.2.1", "trusted_proxy"},
		{"spoofed-prefix", "10.0.0.1:1234", "1.2.3.4, 192.0.2.1", "192.0.2.1", "trusted_proxy"},
		{"chain", "10.0.0.1:1234", "1.2.3.4, 192.0.2.1, 10.0.0.2", "192.0.2.1", "trusted_proxy"},
		{"ipv6", "[2001:db8:1::1]:1234", "2001:db8:2::1", "2001:db8:2::1", "trusted_proxy"},
		{"mapped-peer", "[::ffff:192.0.2.1]:1234", "1.2.3.4", "192.0.2.1", "peer"},
		{"malformed", "10.0.0.1:1234", "unknown, 192.0.2.1", "10.0.0.1", "peer"},
		{"empty-hop", "10.0.0.1:1234", "192.0.2.1,", "10.0.0.1", "peer"},
		{"missing", "10.0.0.1:1234", "", "10.0.0.1", "peer"},
		{"oversized", "10.0.0.1:1234", strings.Repeat("1", 4097), "10.0.0.1", "peer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.peer
			r.Header.Set("X-Forwarded-For", tc.forwarded)
			_, source, from := c.source(r)
			if source != tc.want || from != tc.from {
				t.Fatalf("got %s (%s), want %s (%s)", source, from, tc.want, tc.from)
			}
		})
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r = r.WithContext(WithGatewaySource(r.Context(), "192.0.2.8"))
	_, source, from := c.source(r)
	if source != "192.0.2.8" || from != "gateway" {
		t.Fatal("gateway source was overwritten")
	}
}
