// SPDX-License-Identifier: GPL-3.0-or-later
package trap

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"
)

type Event struct {
	ConfigRevision         string      `json:"config_revision,omitempty"`
	SchemaVersion          int         `json:"schema_version"`
	ID                     string      `json:"id"`
	Time                   time.Time   `json:"time"`
	TokenID                string      `json:"token_id"`
	Note                   string      `json:"note,omitempty"`
	Request                RequestInfo `json:"request"`
	NotificationSuppressed bool        `json:"notification_suppressed"`
}

type RequestInfo struct {
	Query         string `json:"query,omitempty"`
	Method        string `json:"method"`
	Path          string `json:"path"`
	Host          string `json:"host"`
	PeerIP        string `json:"peer_ip,omitempty"`
	SourceIP      string `json:"source_ip,omitempty"`
	SourceIPFrom  string `json:"source_ip_from"`
	UserAgent     string `json:"user_agent,omitempty"`
	ContentType   string `json:"content_type,omitempty"`
	BodyBase64    string `json:"body_base64,omitempty"`
	BodyTruncated bool   `json:"body_truncated,omitempty"`
	BodyReadError bool   `json:"body_read_error,omitempty"`
}

// RandomID returns a cryptographically random 128-bit value, also suitable for
// an unguessable token path or query value. It does not register a token.
func RandomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

type sourceKey struct{}

// WithGatewaySource is for trusted adapters, never for request headers. A
// gateway's asserted peer can still be a proxy, not the original user.
func WithGatewaySource(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, sourceKey{}, ip)
}

func (c *Config) source(r *http.Request) (peer, source, provenance string) {
	if raw, ok := r.Context().Value(sourceKey{}).(string); ok {
		ip, err := netip.ParseAddr(raw)
		if err != nil {
			return "", "", "gateway_unavailable"
		}
		return ip.Unmap().String(), ip.Unmap().String(), "gateway"
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "", "", "peer_unavailable"
	}
	ip = ip.Unmap()
	peer = ip.String()
	if !c.trusted(ip) {
		return peer, peer, "peer"
	}
	header := strings.Join(r.Header.Values("X-Forwarded-For"), ",")
	if header == "" || len(header) > 4096 {
		return peer, peer, "peer"
	}
	parts := strings.Split(header, ",")
	chain := make([]netip.Addr, len(parts))
	for i, part := range parts {
		addr, err := netip.ParseAddr(strings.TrimSpace(part))
		if err != nil || addr.Zone() != "" {
			return peer, peer, "peer"
		}
		chain[i] = addr.Unmap()
	}
	current := ip
	for i := len(chain) - 1; i >= 0 && c.trusted(current); i-- {
		current = chain[i]
	}
	return peer, current.String(), "trusted_proxy"
}

func (c *Config) trusted(ip netip.Addr) bool {
	for _, prefix := range c.proxies {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func bounded(s string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	for !utf8.ValidString(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s
}
