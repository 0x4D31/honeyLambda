package trap

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

const testConfig = `{"version":2,"default_response":{"status":404,"body":"missing"},"tokens":[{"id":"doc","path":"/v1/get-pass","query":{"user":"jack"},"note":"secret.doc","response":{"content_type":"image/png","body_base64":"AAEC/w=="}},{"id":"page","path":"/v1/get-pass","query":{"page":"2"}},{"id":"path","path":"/t/random"}]}`

func testHandler(t *testing.T, config string) (*Handler, *bytes.Buffer) {
	t.Helper()
	c, err := decode(strings.NewReader(config), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var events bytes.Buffer
	h, err := New(c, &events, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return h, &events
}

func TestMatchingAndResponses(t *testing.T) {
	for _, tc := range []struct {
		name, target, token string
		status              int
	}{
		{"known", "/v1/get-pass?user=jack", "doc", 200},
		{"reordered", "/v1/get-pass?z=1&user=jack&x=2", "doc", 200},
		{"query-decoding", "/v1/get-pass?user=%6Aack", "doc", 200},
		{"other-token", "/v1/get-pass?page=2", "page", 404},
		{"unknown", "/v1/get-pass?user=jill", "", 404},
		{"missing-query", "/v1/get-pass", "", 404},
		{"duplicate", "/v1/get-pass?user=jack&user=jack", "", 404},
		{"duplicate-mixed", "/v1/get-pass?user=no&user=jack", "", 404},
		{"ambiguous", "/v1/get-pass?user=jack&page=2", "", 404},
		{"malformed", "/v1/get-pass?user=jack&bad=%zz", "", 404},
		{"semicolon", "/v1/get-pass?user=jack;x=2", "", 404},
		{"path-only", "/t/random?ignored=true", "path", 404},
		{"path-exact", "/t/%72andom", "", 404},
		{"no-cleaning", "/t/../t/random", "", 404},
		{"no-redirect", "/t//random", "", 404},
		{"trailing-slash", "/t/random/", "", 404},
		{"oversized-target", "/v1/get-pass?user=jack&x=" + strings.Repeat("x", 8192), "", 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, events := testHandler(t, testConfig)
			r := httptest.NewRequest(http.MethodGet, tc.target, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status %d; want %d", w.Code, tc.status)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing no-store")
			}
			if tc.token == "" {
				if events.Len() != 0 {
					t.Fatal("unexpected event")
				}
				return
			}
			var event Event
			if err := json.Unmarshal(events.Bytes(), &event); err != nil {
				t.Fatal(err)
			}
			if event.TokenID != tc.token || event.SchemaVersion != 1 || len(event.ID) != 32 || event.Time.IsZero() {
				t.Fatalf("bad event: %+v", event)
			}
			if tc.token == "doc" && !bytes.Equal(w.Body.Bytes(), []byte{0, 1, 2, 255}) {
				t.Fatal("binary response changed")
			}
		})
	}
}

func TestMethodsAndRequestMetadata(t *testing.T) {
	for _, method := range []string{"HEAD", "POST", "OPTIONS", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			h, events := testHandler(t, testConfig)
			r := httptest.NewRequest(method, "/v1/get-pass?user=jack&extra=context", strings.NewReader("request-body"))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if events.Len() == 0 {
				t.Fatal("method did not trigger")
			}
			if !strings.Contains(events.String(), "extra=context") {
				t.Fatal("missing query metadata")
			}
			if method == "HEAD" && (w.Body.Len() != 0 || w.Header().Get("Content-Length") != "4") {
				t.Fatal("bad HEAD response")
			}
		})
	}
}

func TestBoundedBodyCapture(t *testing.T) {
	for _, size := range []int{0, 3, 4, 5, 10000} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			cfg := strings.Replace(testConfig, `"version":2`, `"version":2,"capture_body_bytes":4`, 1)
			h, events := testHandler(t, cfg)
			r := httptest.NewRequest("POST", "/t/random", bytes.NewReader(bytes.Repeat([]byte{255}, size)))
			h.ServeHTTP(httptest.NewRecorder(), r)
			var e Event
			if err := json.Unmarshal(events.Bytes(), &e); err != nil {
				t.Fatal(err)
			}
			body, err := base64.StdEncoding.DecodeString(e.Request.BodyBase64)
			if err != nil || len(body) != min(size, 4) || e.Request.BodyTruncated != (size > 4) {
				t.Fatalf("bad capture: %+v", e.Request)
			}
		})
	}
}

func TestConcurrentEventLines(t *testing.T) {
	h, events := testHandler(t, testConfig)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/t/random", nil))
		}()
	}
	wg.Wait()
	d := json.NewDecoder(events)
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		var event Event
		if err := d.Decode(&event); err != nil {
			t.Fatal(err)
		}
		if ids[event.ID] {
			t.Fatal("duplicate event ID")
		}
		ids[event.ID] = true
	}
	if err := d.Decode(new(Event)); err != io.EOF {
		t.Fatalf("trailing event data: %v", err)
	}
}

func FuzzRequestMatching(f *testing.F) {
	for _, query := range []string{"user=jack", "user=jack&user=x", "%zz", "page=2", "user=jack;"} {
		f.Add(query)
	}
	f.Fuzz(func(t *testing.T, query string) {
		h, _ := testHandler(t, testConfig)
		r := httptest.NewRequest("GET", "/v1/get-pass", nil)
		r.URL.RawQuery = query
		h.ServeHTTP(httptest.NewRecorder(), r)
	})
}
