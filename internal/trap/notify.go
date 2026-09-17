// SPDX-License-Identifier: GPL-3.0-or-later
package trap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"
)

type notifier struct {
	kind   string
	url    string
	client *http.Client
}

func makeNotifiers(c AlertConfig) ([]*notifier, error) {
	var out []*notifier
	for _, setting := range []struct{ kind, env string }{{"slack", c.SlackURLEnv}, {"webhook", c.WebhookURLEnv}} {
		if setting.env == "" {
			continue
		}
		raw := os.Getenv(setting.env)
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
			return nil, fmt.Errorf("%s must contain an HTTPS URL without userinfo or fragment", setting.env)
		}
		out = append(out, &notifier{kind: setting.kind, url: raw, client: &http.Client{
			Timeout:       time.Duration(c.TimeoutMS) * time.Millisecond,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		}})
	}
	return out, nil
}

func (n *notifier) send(ctx context.Context, event Event) error {
	var payload any = event
	if n.kind == "slack" {
		// The fallback text is static. All variable fields use plain_text blocks,
		// so even <!channel> or a forged Slack link remains inert text.
		text := fmt.Sprintf("Token: %s\nSource: %s (%s)\nMethod: %s\nNote: %s\nEvent: %s\nTime: %s",
			event.TokenID, event.Request.SourceIP, event.Request.SourceIPFrom, event.Request.Method, event.Note, event.ID, event.Time.Format(time.RFC3339))
		payload = map[string]any{
			"text": "Honeytoken requested", "unfurl_links": false, "unfurl_media": false,
			"blocks": []any{map[string]any{"type": "section", "text": map[string]any{"type": "plain_text", "text": text}}},
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return errors.New("encode_failed")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return errors.New("request_failed")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "honeyLambda/2")
	resp, err := n.client.Do(req)
	if err != nil {
		return errors.New("delivery_failed")
	}
	defer resp.Body.Close()
	// Do not consume or log an untrusted response body. Closing without draining
	// can sacrifice connection reuse, but bounds time/memory for large responses.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("http_status_%d", resp.StatusCode)
	}
	return nil
}
