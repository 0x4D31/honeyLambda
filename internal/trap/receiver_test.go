package trap

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func receiverForTest(t *testing.T, transport http.RoundTripper) (*Receiver, *bytes.Buffer) {
	t.Helper()
	c, err := decode(strings.NewReader(`{"version":2,"default_response":{"body":"old"},"tokens":[{"id":"old","path":"/old"}]}`), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var events bytes.Buffer
	r, err := NewReceiver(c, RemoteOptions{URL: "https://config.example/service.json", Token: "test-bearer", Timeout: 100 * time.Millisecond}, &events, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	r.client.Transport = transport
	return r, &events
}

func remoteResponse(status int, body, etag string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Etag": []string{etag}}, Body: io.NopCloser(strings.NewReader(body))}
}

const remoteConfig = `{"version":2,"default_response":{"body":"new"},"tokens":[{"id":"new","path":"/new"}]}`

func due(r *Receiver) { r.refreshMu.Lock(); r.nextRefresh = time.Time{}; r.refreshMu.Unlock() }
func request(r *Receiver, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	return w
}

func TestRemoteRefreshLastGoodAndETag(t *testing.T) {
	replies := []struct {
		status     int
		body, etag string
	}{
		{200, remoteConfig, `"v1"`},
		{304, "", `"v1"`},
		{200, `{"version":2,"tokens":[]}`, `"invalid"`},
		{503, "unavailable", ""},
		{200, remoteConfig, `"v2"`},
	}
	calls := 0
	r, events := receiverForTest(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "Bearer test-bearer" {
			t.Error("missing bearer token")
		}
		if calls > 0 && req.Header.Get("If-None-Match") != `"v1"` {
			t.Error("cached invalid ETag")
		}
		reply := replies[calls]
		calls++
		return remoteResponse(reply.status, reply.body, reply.etag), nil
	}))
	original := r.current.Load()
	if request(r, "/new").Body.String() != "new" || r.current.Load() == original {
		t.Fatal("config did not refresh")
	}
	active := r.current.Load()
	request(r, "/new")
	if calls != 1 {
		t.Fatal("fetched on every request")
	}
	for range replies[1:] {
		due(r)
		if request(r, "/new").Body.String() != "new" || r.current.Load() != active {
			t.Fatal("lost last valid config or reset unchanged handler")
		}
	}
	decoder := json.NewDecoder(events)
	for i := 0; i < 6; i++ {
		var event Event
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		if event.TokenID != "new" || event.ConfigRevision != active.revision {
			t.Fatal("wrong active revision")
		}
	}
	if r.etag != `"v2"` {
		t.Fatal("new valid ETag not accepted")
	}
}

func TestConcurrentRefreshKeepsServing(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	r, events := receiverForTest(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		close(entered)
		<-release
		return remoteResponse(200, remoteConfig, `"v1"`), nil
	}))
	finished := make(chan struct{})
	go func() { request(r, "/new"); close(finished) }()
	<-entered
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if request(r, "/old").Body.String() != "old" {
				t.Error("request did not use active snapshot")
			}
		}()
	}
	wg.Wait()
	close(release)
	<-finished
	if calls.Load() != 1 {
		t.Fatal("concurrent refresh stampede")
	}
	decoder := json.NewDecoder(events)
	for i := 0; i < 31; i++ {
		var event Event
		if err := decoder.Decode(&event); err != nil {
			t.Fatal("event writes interleaved:", err)
		}
	}
}

func TestRemoteRejectsInvalidSnapshotsAndBoundsTimeout(t *testing.T) {
	for _, reply := range []struct {
		status int
		body   string
	}{
		{304, ""}, {302, ""},
		{200, `{"version":2,"default_response":{"body_file":"/etc/passwd"},"tokens":[{"id":"x","path":"/"}]}`},
		{200, strings.Repeat(" ", maxConfigBytes+1)},
		{200, `{"version":2,"alerts":{"webhook_url_env":"UNSET_URL"},"tokens":[{"id":"x","path":"/"}]}`},
	} {
		t.Setenv("UNSET_URL", "")
		r, _ := receiverForTest(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
			return remoteResponse(reply.status, reply.body, `"bad"`), nil
		}))
		before := r.current.Load()
		request(r, "/old")
		if r.current.Load() != before || r.etag != "" {
			t.Fatal("activated invalid remote config")
		}
	}
	r, _ := receiverForTest(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}))
	start := time.Now()
	if request(r, "/old").Body.String() != "old" || time.Since(start) > time.Second {
		t.Fatal("fetch timeout prevented serving bootstrap")
	}
}

func TestRemoteOptions(t *testing.T) {
	for _, options := range []RemoteOptions{
		{Token: "orphan"}, {URL: "http://example.org"}, {URL: "https://user@example.org"},
		{URL: "https://example.org#fragment"}, {URL: "https://example.org", Refresh: time.Second},
		{URL: "https://example.org", Timeout: 6 * time.Second},
	} {
		if err := options.validate(); err == nil {
			t.Fatal("invalid remote options accepted")
		}
	}
}

func TestClientCancellationDoesNotCancelNotification(t *testing.T) {
	h, _ := testHandler(t, testConfig)
	called := false
	h.notifiers = []*notifier{{kind: "webhook", url: "https://example.org", client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		called = true
		if r.Context().Err() != nil {
			t.Error("client disconnect cancelled notification")
		}
		if _, ok := r.Context().Deadline(); !ok {
			t.Error("notification lacks deadline")
		}
		return remoteResponse(200, "", ""), nil
	})}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/t/random", nil).WithContext(ctx))
	if !called {
		t.Fatal("notification skipped")
	}
}

func TestRemoteHTTPSAndRedirects(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		if req.Header.Get("Authorization") != "Bearer test-bearer" {
			t.Error("missing HTTP bearer token")
		}
		if req.URL.Path == "/redirect" {
			http.Redirect(w, req, "/config", http.StatusFound)
			return
		}
		w.Header().Set("ETag", `"https-v1"`)
		_, _ = io.WriteString(w, remoteConfig)
	}))
	defer server.Close()
	r, _ := receiverForTest(t, server.Client().Transport)
	r.options.URL = server.URL + "/redirect"
	if request(r, "/old").Body.String() != "old" || calls.Load() != 1 {
		t.Fatal("remote fetch followed a redirect")
	}
	r.options.URL = server.URL + "/config"
	due(r)
	if request(r, "/new").Body.String() != "new" || r.etag != `"https-v1"` {
		t.Fatal("HTTPS config did not activate")
	}
}
