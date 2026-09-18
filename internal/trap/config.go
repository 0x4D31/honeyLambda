// SPDX-License-Identifier: GPL-3.0-or-later
package trap

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	maxConfigBytes   = 4 << 20
	maxResponseBytes = 1 << 20
	maxCaptureBytes  = 64 << 10
	maxTargetBytes   = 8 << 10
)

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
var envName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

type Config struct {
	Schema           string               `json:"$schema,omitempty"`
	Responses        map[string]*Response `json:"responses,omitempty"`
	Version          int                  `json:"version"`
	DefaultResponse  Response             `json:"default_response"`
	Tokens           []Token              `json:"tokens"`
	Alerts           AlertConfig          `json:"alerts"`
	CaptureBodyBytes int                  `json:"capture_body_bytes"`
	TrustedProxies   []string             `json:"trusted_proxies,omitempty"`
	proxies          []netip.Prefix
}

type Token struct {
	ID               string            `json:"id"`
	Path             string            `json:"path"`
	Query            map[string]string `json:"query,omitempty"`
	Note             string            `json:"note,omitempty"`
	Response         *Response         `json:"response,omitempty"`
	ResponseRef      string            `json:"response_ref,omitempty"`
	resolvedResponse *Response
}

type Response struct {
	Status      int    `json:"status,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Body        string `json:"body,omitempty"`
	BodyBase64  string `json:"body_base64,omitempty"`
	BodyFile    string `json:"body_file,omitempty"`
	data        []byte
}

type AlertConfig struct {
	SlackURLEnv     string `json:"slack_url_env,omitempty"`
	WebhookURLEnv   string `json:"webhook_url_env,omitempty"`
	TimeoutMS       int    `json:"timeout_ms,omitempty"`
	CooldownSeconds *int   `json:"cooldown_seconds,omitempty"`
}

// Load validates configuration and snapshots response assets once. Paths in the
// config are relative to its directory, never to an incoming request.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()
	return decode(f, filepath.Dir(path))
}

func decode(r io.Reader, dir string) (*Config, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if len(b) > maxConfigBytes {
		return nil, errors.New("config exceeds 4 MiB")
	}
	var c Config
	if err := strictJSON(b, &c); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if err := c.validate(dir); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) validate(dir string) error {
	if c.Version != 2 {
		return errors.New("config version must be 2; see docs/migration.md")
	}
	if len(c.Tokens) == 0 || len(c.Tokens) > 10000 {
		return errors.New("configure between 1 and 10000 tokens")
	}
	if c.CaptureBodyBytes < 0 || c.CaptureBodyBytes > maxCaptureBytes {
		return errors.New("capture_body_bytes must be between 0 and 65536")
	}
	if c.Alerts.TimeoutMS == 0 {
		c.Alerts.TimeoutMS = 2000
	}
	if c.Alerts.TimeoutMS < 1 || c.Alerts.TimeoutMS > 5000 {
		return errors.New("alerts.timeout_ms must be between 1 and 5000")
	}
	if c.Alerts.CooldownSeconds == nil {
		seconds := 60
		c.Alerts.CooldownSeconds = &seconds
	}
	if *c.Alerts.CooldownSeconds < 0 || *c.Alerts.CooldownSeconds > 86400 {
		return errors.New("alerts.cooldown_seconds must be between 0 and 86400")
	}
	for _, name := range []string{c.Alerts.SlackURLEnv, c.Alerts.WebhookURLEnv} {
		if name != "" && (!envName.MatchString(name) || reservedEnv(name)) {
			return errors.New("alert URL settings must name non-reserved environment variables")
		}
	}
	if c.Alerts.SlackURLEnv != "" && c.Alerts.SlackURLEnv == c.Alerts.WebhookURLEnv {
		return errors.New("notification destinations must use distinct environment variable names")
	}
	for _, cidr := range c.TrustedProxies {
		p, err := netip.ParsePrefix(cidr)
		if err != nil || p.Bits() == 0 || p.Addr().Is4In6() {
			return errors.New("trusted_proxies requires explicit IPv4/IPv6 CIDRs, excluding /0 and mapped IPv6")
		}
		c.proxies = append(c.proxies, p.Masked())
	}
	if err := c.DefaultResponse.prepare(dir); err != nil {
		return fmt.Errorf("default_response: %w", err)
	}
	totalResponseBytes := len(c.DefaultResponse.data)
	ids := make(map[string]bool)
	selectors := make(map[string]string)
	if len(c.Responses) > 1000 {
		return errors.New("configure at most 1000 named responses")
	}
	for name, response := range c.Responses {
		if !identifier.MatchString(name) || response == nil {
			return fmt.Errorf("invalid named response %q", name)
		}
		if err := response.prepare(dir); err != nil {
			return fmt.Errorf("response %s: %w", name, err)
		}
		totalResponseBytes += len(response.data)
	}
	if totalResponseBytes > 16<<20 {
		return errors.New("combined response bodies exceed 16 MiB")
	}
	for i := range c.Tokens {
		t := &c.Tokens[i]
		if !identifier.MatchString(t.ID) || ids[t.ID] {
			return errors.New("token IDs must be unique, 1-128 characters: letters, digits, dot, underscore or hyphen")
		}
		ids[t.ID] = true
		u, err := url.ParseRequestURI(t.Path)
		if err != nil || !strings.HasPrefix(t.Path, "/") || strings.HasPrefix(t.Path, "//") || strings.ContainsAny(t.Path, "?#") || len(t.Path) > 2048 || u.EscapedPath() != t.Path {
			return fmt.Errorf("token %s: path must be an absolute escaped path without query or fragment (max 2048 bytes)", t.ID)
		}
		if len(t.Note) > 1024 {
			return fmt.Errorf("token %s: note exceeds 1024 bytes", t.ID)
		}
		q := make(url.Values)
		for key, value := range t.Query {
			if key == "" {
				return fmt.Errorf("token %s: query key cannot be empty", t.ID)
			}
			q.Set(key, value)
		}
		if len(t.Path)+1+len(q.Encode()) > maxTargetBytes {
			return fmt.Errorf("token %s: URL selector exceeds 8192 bytes", t.ID)
		}
		selector := t.Path + "\x00" + q.Encode()
		if previous, exists := selectors[selector]; exists {
			return fmt.Errorf("tokens %s and %s have identical selectors", previous, t.ID)
		}
		selectors[selector] = t.ID
		if t.ResponseRef != "" {
			if t.Response != nil {
				return fmt.Errorf("token %s: use response or response_ref, not both", t.ID)
			}
			response, exists := c.Responses[t.ResponseRef]
			if !exists {
				return fmt.Errorf("token %s: unknown response_ref %q", t.ID, t.ResponseRef)
			}
			t.resolvedResponse = response
		}
		if t.Response != nil {
			if err := t.Response.prepare(dir); err != nil {
				return fmt.Errorf("token %s response: %w", t.ID, err)
			}
			totalResponseBytes += len(t.Response.data)
			if totalResponseBytes > 16<<20 {
				return errors.New("combined response bodies exceed 16 MiB")
			}
		}
	}
	return nil
}

// Deployment and process settings must not be overwritten by notification URLs.
func reservedEnv(name string) bool {
	return name == "PORT" || name == "HONEY_CONFIG" || name == "HONEY_DEPLOYMENT_REVISION" || strings.HasPrefix(name, "HONEY_REMOTE_") || strings.HasPrefix(name, "AWS_") || strings.HasPrefix(name, "K_")
}

func (r *Response) prepare(dir string) error {
	if r.Status == 0 {
		r.Status = 200
	}
	if r.Status < 200 || r.Status > 599 {
		return errors.New("status must be between 200 and 599")
	}
	if r.ContentType == "" {
		r.ContentType = "text/plain; charset=utf-8"
	}
	if strings.ContainsAny(r.ContentType, "\r\n") {
		return errors.New("invalid content_type")
	}
	if _, _, err := mime.ParseMediaType(r.ContentType); err != nil {
		return errors.New("invalid content_type")
	}
	n := 0
	for _, s := range []string{r.Body, r.BodyBase64, r.BodyFile} {
		if s != "" {
			n++
		}
	}
	if n > 1 {
		return errors.New("use only one of body, body_base64 or body_file")
	}
	r.data = []byte(r.Body)
	if r.BodyBase64 != "" {
		var err error
		r.data, err = base64.StdEncoding.DecodeString(r.BodyBase64)
		if err != nil {
			return errors.New("invalid body_base64")
		}
	}
	if r.BodyFile != "" {
		if dir == "" {
			return errors.New("remote config cannot use body_file; use export to inline assets")
		}
		path := r.BodyFile
		if !filepath.IsAbs(path) {
			path = filepath.Join(dir, path)
		}
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open body_file: %w", err)
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("body_file must be a regular file")
		}
		r.data, err = io.ReadAll(io.LimitReader(f, maxResponseBytes+1))
		if err != nil {
			return fmt.Errorf("read body_file: %w", err)
		}
	}
	if len(r.data) > maxResponseBytes {
		return errors.New("response body exceeds 1 MiB")
	}
	if (r.Status == 204 || r.Status == 205 || r.Status == 304) && len(r.data) != 0 {
		return errors.New("status 204/205/304 cannot have a body")
	}
	return nil
}
