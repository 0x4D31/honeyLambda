package trap

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestNotifierFailuresAreIsolated(t *testing.T) {
	for _, status := range []int{200, 302, 429, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			h, events := testHandler(t, testConfig)
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" {
					t.Error("bad notification request")
				}
				var event Event
				if err := json.NewDecoder(r.Body).Decode(&event); err != nil || event.TokenID != "doc" {
					t.Error("bad webhook event")
				}
				w.Header().Set("Location", "/redirect")
				w.WriteHeader(status)
			}))
			defer server.Close()
			client := server.Client()
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			h.notifiers = []*notifier{{kind: "webhook", url: server.URL, client: client}}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("GET", "/v1/get-pass?user=jack", nil))
			if calls.Load() != 1 || w.Code != 200 || w.Body.Len() != 4 || events.Len() == 0 {
				t.Fatal("delivery changed the decoy response or followed a redirect")
			}
		})
	}
}

func TestDeliveryDeadlineAndErrorRedaction(t *testing.T) {
	h, events := testHandler(t, testConfig)
	h.config.Alerts.TimeoutMS = 20
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, errors.New("https://example.org/SECRET: timed out")
	})}
	n := &notifier{kind: "webhook", url: "https://example.org/SECRET", client: client}
	h.notifiers = []*notifier{n}
	start := time.Now()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/t/random", nil))
	if time.Since(start) > time.Second || w.Code != 404 || events.Len() == 0 {
		t.Fatal("notification timeout did not isolate failure")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := n.send(ctx, Event{})
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("unsafe error: %v", err)
	}
}

func TestConcurrentCooldownDoesNotDropEvents(t *testing.T) {
	h, events := testHandler(t, testConfig)
	var calls atomic.Int32
	h.notifiers = []*notifier{{kind: "webhook", url: "https://example.org", client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}}}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/t/random", nil))
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("got %d notifications", calls.Load())
	}
	d := json.NewDecoder(events)
	suppressed := 0
	for i := 0; i < 50; i++ {
		var e Event
		if err := d.Decode(&e); err != nil {
			t.Fatal(err)
		}
		if e.NotificationSuppressed {
			suppressed++
		}
	}
	if suppressed != 49 {
		t.Fatalf("suppressed %d; want 49", suppressed)
	}
}

func TestSlackUsesPlainText(t *testing.T) {
	n := &notifier{kind: "slack", url: "https://example.org", client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var payload struct {
			Text   string `json:"text"`
			Blocks []struct {
				Text struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"text"`
			} `json:"blocks"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload.Text != "Honeytoken requested" || len(payload.Blocks) != 1 || payload.Blocks[0].Text.Type != "plain_text" || !strings.Contains(payload.Blocks[0].Text.Text, "<!channel>") {
			t.Fatal("Slack variable content is not plain text")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}}
	if err := n.send(context.Background(), Event{Note: "<!channel> <https://example.org|click>"}); err != nil {
		t.Fatal(err)
	}
}

func TestNotificationSettings(t *testing.T) {
	for _, raw := range []string{"", "http://example.org/SECRET", "https://user:SECRET@example.org", "https://example.org/#SECRET", "%SECRET"} {
		t.Setenv("HONEY_TEST_URL", raw)
		_, err := makeNotifiers(AlertConfig{WebhookURLEnv: "HONEY_TEST_URL", TimeoutMS: 100})
		if err == nil || strings.Contains(err.Error(), "SECRET") {
			t.Fatalf("invalid or leaked setting: %v", err)
		}
	}
	t.Setenv("HONEY_TEST_URL", "https://example.org/SECRET")
	ns, err := makeNotifiers(AlertConfig{WebhookURLEnv: "HONEY_TEST_URL", TimeoutMS: 100})
	if err != nil || len(ns) != 1 {
		t.Fatalf("valid webhook: %v", err)
	}
	if err := ns[0].client.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatal("redirects enabled")
	}
}
