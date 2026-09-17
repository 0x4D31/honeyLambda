// SPDX-License-Identifier: GPL-3.0-or-later
// Package lambdahttp adapts Function URL and HTTP API payload-v2 events to the
// same HTTP handler used by the standalone server.
package lambdahttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/0x4D31/honeyLambda/v2/internal/trap"
	"github.com/aws/aws-lambda-go/events"
)

func Handler(h http.Handler) func(context.Context, events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	return func(ctx context.Context, event events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
		if event.Version != "2.0" {
			return events.APIGatewayV2HTTPResponse{}, errors.New("expected a Function URL or HTTP API payload-v2 event")
		}
		if !strings.HasPrefix(event.RawPath, "/") || strings.HasPrefix(event.RawPath, "//") || strings.ContainsAny(event.RawPath, "?#") || event.RequestContext.HTTP.Method == "" {
			return events.APIGatewayV2HTTPResponse{}, errors.New("invalid HTTP event path or method")
		}
		// Lambda limits synchronous invocation payloads to 6 MiB. This additional
		// bound also makes the adapter safe to call outside the Lambda runtime.
		if len(event.Body) > 6<<20 {
			return events.APIGatewayV2HTTPResponse{}, errors.New("event body exceeds 6 MiB")
		}
		body := []byte(event.Body)
		if event.IsBase64Encoded {
			var err error
			body, err = base64.StdEncoding.DecodeString(event.Body)
			if err != nil {
				return events.APIGatewayV2HTTPResponse{}, errors.New("invalid base64 event body")
			}
		}
		target := event.RawPath
		if event.RawQueryString != "" {
			target += "?" + event.RawQueryString
		}
		ctx = trap.WithGatewaySource(ctx, event.RequestContext.HTTP.SourceIP)
		r, err := http.NewRequestWithContext(ctx, event.RequestContext.HTTP.Method, target, bytes.NewReader(body))
		if err != nil {
			return events.APIGatewayV2HTTPResponse{}, errors.New("invalid HTTP event request")
		}
		r.RequestURI = target
		for key, value := range event.Headers {
			r.Header.Set(key, value)
		}
		if len(event.Cookies) > 0 {
			r.Header.Set("Cookie", strings.Join(event.Cookies, "; "))
		}
		r.Host = r.Header.Get("Host")
		if r.Host == "" {
			r.Host = event.RequestContext.DomainName
		}
		if r.UserAgent() == "" {
			r.Header.Set("User-Agent", event.RequestContext.HTTP.UserAgent)
		}
		defer r.Body.Close()
		w := &responseWriter{header: make(http.Header)}
		h.ServeHTTP(w, r)
		if w.status == 0 {
			w.status = http.StatusOK
		}
		headers := make(map[string]string)
		for key, values := range w.header {
			if key != "Set-Cookie" {
				headers[key] = strings.Join(values, ",")
			}
		}
		responseBody := w.body.Bytes()
		if r.Method == http.MethodHead {
			responseBody = nil
		}
		return events.APIGatewayV2HTTPResponse{
			StatusCode: w.status, Headers: headers, Cookies: w.header.Values("Set-Cookie"),
			Body: base64.StdEncoding.EncodeToString(responseBody), IsBase64Encoded: true,
		}, nil
	}
}

type responseWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (w *responseWriter) Header() http.Header { return w.header }
func (w *responseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *responseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(p)
}
