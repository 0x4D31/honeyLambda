// SPDX-License-Identifier: GPL-3.0-or-later
package trap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type RemoteOptions struct {
	URL     string
	Token   string
	Refresh time.Duration
	Timeout time.Duration
}

// RemoteOptionsFromEnv keeps deployment/channel settings out of the service document.
func RemoteOptionsFromEnv() (RemoteOptions, error) {
	options := RemoteOptions{URL: os.Getenv("HONEY_REMOTE_CONFIG_URL"), Token: os.Getenv("HONEY_REMOTE_CONFIG_TOKEN")}
	for _, setting := range []struct {
		name   string
		target *time.Duration
		unit   time.Duration
	}{
		{"HONEY_REMOTE_REFRESH_SECONDS", &options.Refresh, time.Second},
		{"HONEY_REMOTE_TIMEOUT_MS", &options.Timeout, time.Millisecond},
	} {
		if raw, exists := os.LookupEnv(setting.name); exists {
			value, err := strconv.Atoi(raw)
			if err != nil || value < 1 || value > 86400 {
				return options, fmt.Errorf("invalid %s", setting.name)
			}
			*setting.target = time.Duration(value) * setting.unit
		}
	}
	err := options.validate()
	return options, err
}

func (o *RemoteOptions) validate() error {
	if o.URL == "" {
		if o.Token != "" || o.Refresh != 0 || o.Timeout != 0 {
			return errors.New("remote settings require HONEY_REMOTE_CONFIG_URL")
		}
		return nil
	}
	if strings.ContainsAny(o.Token, "\r\n") {
		return errors.New("remote config bearer token cannot contain newlines")
	}
	u, err := url.Parse(o.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return errors.New("remote config URL must use HTTPS without userinfo or fragment")
	}
	if o.Refresh == 0 {
		o.Refresh = time.Minute
	}
	if o.Timeout == 0 {
		o.Timeout = 2 * time.Second
	}
	if o.Refresh < 5*time.Second || o.Refresh > 24*time.Hour {
		return errors.New("remote refresh must be between 5 and 86400 seconds")
	}
	if o.Timeout < 100*time.Millisecond || o.Timeout > 5*time.Second {
		return errors.New("remote timeout must be between 100 and 5000 milliseconds")
	}
	return nil
}

type Receiver struct {
	current     atomic.Pointer[Handler]
	options     RemoteOptions
	client      *http.Client
	events      io.Writer
	log         *slog.Logger
	refreshMu   sync.Mutex
	nextRefresh time.Time
	etag        string
}

// NewReceiver always has a validated local bootstrap. The first request also
// attempts a remote refresh; no unbounded network call occurs during cold start.
func NewReceiver(c *Config, options RemoteOptions, events io.Writer, log *slog.Logger) (*Receiver, error) {
	if err := options.validate(); err != nil {
		return nil, err
	}
	if events == nil {
		return nil, errors.New("event writer is required")
	}
	writer := &lockedWriter{writer: events}
	h, err := New(c, writer, log)
	if err != nil {
		return nil, err
	}
	r := &Receiver{options: options, events: writer, log: log, client: &http.Client{
		Timeout:       options.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}}
	r.current.Store(h)
	return r, nil
}

func (r *Receiver) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	if r.options.URL != "" {
		r.refresh(request.Context())
	}
	r.current.Load().ServeHTTP(w, request)
}

func (r *Receiver) refresh(ctx context.Context) {
	// One request performs a due refresh. Other requests keep using the old
	// immutable handler; none wait on a network call owned by another request.
	if !r.refreshMu.TryLock() {
		return
	}
	defer r.refreshMu.Unlock()
	now := time.Now()
	if now.Before(r.nextRefresh) {
		return
	}
	r.nextRefresh = now.Add(r.options.Refresh)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.options.Timeout)
	defer cancel()
	if err := r.fetch(ctx); err != nil {
		r.log.Error("remote_config_refresh_failed", "reason", err.Error(), "config_revision", r.current.Load().revision)
	}
}

func (r *Receiver) fetch(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, r.options.URL, nil)
	if err != nil {
		return errors.New("request_failed")
	}
	request.Header.Set("Accept", "application/json")
	if r.options.Token != "" {
		request.Header.Set("Authorization", "Bearer "+r.options.Token)
	}
	if r.etag != "" {
		request.Header.Set("If-None-Match", r.etag)
	}
	response, err := r.client.Do(request)
	if err != nil {
		return errors.New("fetch_failed")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		if r.etag == "" {
			return errors.New("unexpected_not_modified")
		}
		return nil
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("http_status_%d", response.StatusCode)
	}
	// An empty asset directory rejects body_file before attempting any file I/O.
	config, err := decode(response.Body, "")
	if err != nil {
		return fmt.Errorf("invalid_config: %w", err)
	}
	active := r.current.Load()
	if config.revision() != active.revision {
		next, err := New(config, r.events, r.log)
		if err != nil {
			return fmt.Errorf("invalid_notification_settings: %w", err)
		}
		r.current.Store(next)
		r.log.Info("remote_config_applied", "config_revision", next.revision, "tokens", len(config.Tokens))
	}
	// Never cache an ETag for an invalid snapshot; a corrected object must retry.
	r.etag = response.Header.Get("ETag")
	return nil
}

type lockedWriter struct {
	mu     sync.Mutex
	writer io.Writer
}

func (w *lockedWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writer.Write(data)
}
