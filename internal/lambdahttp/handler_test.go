package lambdahttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/0x4D31/honeyLambda/v2/internal/trap"
	"github.com/aws/aws-lambda-go/events"
)

func event() events.APIGatewayV2HTTPRequest {
	return events.APIGatewayV2HTTPRequest{
		Version: "2.0", RawPath: "/pixel", RawQueryString: "extra=1&token=abc",
		Headers:        map[string]string{"host": "example.org", "x-forwarded-for": "1.2.3.4"},
		RequestContext: events.APIGatewayV2HTTPRequestContext{HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{Method: "GET", SourceIP: "192.0.2.2"}},
	}
}

func TestReceiverThroughLambda(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(file, []byte(`{"version":2,"capture_body_bytes":4,"tokens":[{"id":"pixel","path":"/pixel","query":{"token":"abc"},"response":{"content_type":"image/png","body_base64":"AAEC/w=="}}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := trap.Load(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"GET", "POST", "HEAD"} {
		t.Run(method, func(t *testing.T) {
			var logs bytes.Buffer
			h, err := trap.New(c, &logs, slog.New(slog.NewJSONHandler(io.Discard, nil)))
			if err != nil {
				t.Fatal(err)
			}
			e := event()
			e.RequestContext.HTTP.Method = method
			e.Body = base64.StdEncoding.EncodeToString([]byte{255, 0, 1, 2, 3})
			e.IsBase64Encoded = true
			response, err := Handler(h)(context.Background(), e)
			if err != nil {
				t.Fatal(err)
			}
			body, err := base64.StdEncoding.DecodeString(response.Body)
			if err != nil || !response.IsBase64Encoded || response.StatusCode != 200 {
				t.Fatalf("bad response: %+v, %v", response, err)
			}
			if method == "HEAD" {
				if len(body) != 0 {
					t.Fatal("HEAD body returned")
				}
			} else if !bytes.Equal(body, []byte{0, 1, 2, 255}) {
				t.Fatal("binary response changed")
			}
			var record trap.Event
			if err := json.Unmarshal(logs.Bytes(), &record); err != nil {
				t.Fatal(err)
			}
			if record.Request.SourceIP != "192.0.2.2" || record.Request.SourceIPFrom != "gateway" || record.Request.Query != e.RawQueryString {
				t.Fatalf("bad metadata: %+v", record.Request)
			}
			if record.Request.BodyBase64 != "/wABAg==" || !record.Request.BodyTruncated {
				t.Fatal("base64 request body not captured correctly")
			}
		})
	}
}

func TestRawQueryPathAndHeaders(t *testing.T) {
	e := event()
	e.RawPath = "/%2Fpixel"
	e.RawQueryString = "token=abc&token=def"
	e.Cookies = []string{"a=1", "b=2"}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != e.RawPath || len(r.URL.Query()["token"]) != 2 || r.Host != "example.org" || r.Header.Get("Cookie") != "a=1; b=2" {
			t.Fatalf("lossy request conversion: %+v", r)
		}
		w.Header().Add("Set-Cookie", "x=1")
		w.Header().Add("Set-Cookie", "y=2")
		w.WriteHeader(204)
	})
	r, err := Handler(h)(context.Background(), e)
	if err != nil || r.StatusCode != 204 || len(r.Cookies) != 2 {
		t.Fatalf("bad conversion: %+v %v", r, err)
	}
}

func TestMalformedEvents(t *testing.T) {
	for _, mutate := range []func(*events.APIGatewayV2HTTPRequest){
		func(e *events.APIGatewayV2HTTPRequest) { e.Version = "1.0" },
		func(e *events.APIGatewayV2HTTPRequest) { e.RequestContext.HTTP.Method = "" },
		func(e *events.APIGatewayV2HTTPRequest) { e.RawPath = "https://example.org" },
		func(e *events.APIGatewayV2HTTPRequest) { e.RawPath = "/bad%zz" },
		func(e *events.APIGatewayV2HTTPRequest) { e.RawPath = "/path#fragment" },
		func(e *events.APIGatewayV2HTTPRequest) { e.Body = "%bad"; e.IsBase64Encoded = true },
	} {
		e := event()
		mutate(&e)
		_, err := Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("invalid event reached receiver") }))(context.Background(), e)
		if err == nil {
			t.Fatal("invalid event accepted")
		}
	}
}
