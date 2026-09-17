// SPDX-License-Identifier: GPL-3.0-or-later
package trap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

type Handler struct {
	config           *Config
	byPath           map[string][]*Token
	events           *json.Encoder
	log              *slog.Logger
	notifiers        []*notifier
	mu               sync.Mutex
	lastNotification map[string]time.Time
}

// New takes a validated Config returned by Load. Do not mutate it afterwards.
// Event writes are serialized; each matched request is recorded even during
// cooldown or when every notification destination fails.
func New(c *Config, events io.Writer, log *slog.Logger) (*Handler, error) {
	if c == nil || c.Version != 2 || c.Alerts.CooldownSeconds == nil || events == nil || log == nil {
		return nil, errors.New("validated config, event writer and logger are required")
	}
	notifiers, err := makeNotifiers(c.Alerts)
	if err != nil {
		return nil, err
	}
	h := &Handler{config: c, byPath: make(map[string][]*Token), events: json.NewEncoder(events), log: log, notifiers: notifiers, lastNotification: make(map[string]time.Time)}
	for i := range c.Tokens {
		t := &c.Tokens[i]
		h.byPath[t.Path] = append(h.byPath[t.Path], t)
	}
	return h, nil
}

func (h *Handler) match(r *http.Request) *Token {
	path := r.URL.EscapedPath()
	if len(path)+1+len(r.URL.RawQuery) > maxTargetBytes {
		return nil
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil
	}
	var match *Token
	for _, t := range h.byPath[path] {
		matched := true
		for key, value := range t.Query {
			values := query[key]
			if len(values) != 1 || values[0] != value {
				matched = false
				break
			}
		}
		if matched {
			if match != nil {
				return nil
			}
			match = t
		}
	}
	return match
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	response := &h.config.DefaultResponse
	if token := h.match(r); token != nil {
		if token.Response != nil {
			response = token.Response
		}
		h.record(r, token)
	}
	w.Header().Set("Content-Type", response.ContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if response.Status != 204 && response.Status != 304 {
		w.Header().Set("Content-Length", strconv.Itoa(len(response.data)))
	}
	w.WriteHeader(response.Status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(response.data)
	}
}

func (h *Handler) record(r *http.Request, token *Token) {
	id, err := RandomID()
	if err != nil {
		h.log.Error("event_id_failed", "token_id", token.ID)
		return
	}
	peer, source, provenance := h.config.source(r)
	event := Event{SchemaVersion: 1, ID: id, Time: time.Now().UTC(), TokenID: token.ID, Note: token.Note, Request: RequestInfo{
		Method: bounded(r.Method, 32), Path: token.Path, Query: r.URL.RawQuery, Host: bounded(r.Host, 256), PeerIP: peer, SourceIP: source, SourceIPFrom: provenance,
		UserAgent: bounded(r.UserAgent(), 512), ContentType: bounded(r.Header.Get("Content-Type"), 256),
	}}
	if limit := h.config.CaptureBodyBytes; limit > 0 && r.Body != nil {
		body, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
		event.Request.BodyReadError = err != nil
		event.Request.BodyTruncated = len(body) > limit
		if len(body) > limit {
			body = body[:limit]
		}
		event.Request.BodyBase64 = base64.StdEncoding.EncodeToString(body)
	}
	h.mu.Lock()
	if len(h.notifiers) > 0 {
		cooldown := time.Duration(*h.config.Alerts.CooldownSeconds) * time.Second
		last, exists := h.lastNotification[token.ID]
		event.NotificationSuppressed = exists && event.Time.Sub(last) < cooldown
		if !event.NotificationSuppressed {
			h.lastNotification[token.ID] = event.Time
		}
	}
	err = h.events.Encode(event)
	h.mu.Unlock()
	if err != nil {
		h.log.Error("event_write_failed", "event_id", id, "token_id", token.ID)
	}
	if event.NotificationSuppressed || len(h.notifiers) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(h.config.Alerts.TimeoutMS)*time.Millisecond)
	defer cancel()
	var wg sync.WaitGroup
	for _, n := range h.notifiers {
		wg.Add(1)
		go func(n *notifier) {
			defer wg.Done()
			if err := n.send(ctx, event); err != nil {
				h.log.Error("notification_failed", "event_id", id, "token_id", token.ID, "sink", n.kind, "reason", err.Error())
			}
		}(n)
	}
	wg.Wait()
}
