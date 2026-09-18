package trap

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStrictConfigKeys(t *testing.T) {
	for _, input := range []string{
		`{"version":2,"version":2,"tokens":[{"id":"a","path":"/a"}]}`,
		`{"Version":2,"tokens":[{"id":"a","path":"/a"}]}`,
		`{"version":2,"tokens":[{"id":"a","path":"/a","Path":"/b"}]}`,
		`{"version":2,"tokens":[{"id":"a","path":"/a","query":{"x":"1","x":"2"}}]}`,
		`{"version":2,"tokens":[{"id":"a","path":"/a","response":null}]}`,
		`{"version":2,"tokens":[{"id":"a","path":"/a","response":{"body":"","body_base64":"YQ=="}}]}`,
		`{"version":2,"tokens":[{"id":"a","path":"/a"}],"alerts":{"webhook_url_env":"HONEY_CONFIG"}}`,
		`{"version":2,"tokens":[{"id":"a","path":"/a"}],"alerts":{"slack_url_env":"URL","webhook_url_env":"URL"}}`,
		`{"version":2,"tokens":[{"id":"a","path":"/a","response":{"status":205,"body":"invalid"}}]}`,
		strings.Replace(testConfig, "secret.doc", "invalid\xff", 1),
	} {
		if _, err := decode(strings.NewReader(input), t.TempDir()); err == nil {
			t.Fatalf("accepted %q", input)
		}
	}
}

func TestNamedResponseRoundTrips(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pixel.bin"), []byte{0, 255, 128}, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := decode(strings.NewReader(`{"version":2,"responses":{"pixel":{"content_type":"image/png","body_file":"pixel.bin"}},"tokens":[{"id":"a","path":"/a","response_ref":"pixel"},{"id":"b","path":"/b","response_ref":"pixel"}]}`), dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Tokens[0].resolvedResponse != c.Tokens[1].resolvedResponse {
		t.Fatal("responses were not shared")
	}
	exported, err := c.Export()
	if err != nil {
		t.Fatal(err)
	}
	remote, err := decode(bytes.NewReader(exported), "")
	if err != nil {
		t.Fatal(err)
	}
	files, err := c.Bundle()
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(target, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	bundled, err := Load(filepath.Join(target, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, config := range []*Config{c, remote, bundled} {
		if config.revision() != c.revision() {
			t.Fatal("packaging changed config revision")
		}
		h, err := New(config, io.Discard, slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/b", nil))
		if !bytes.Equal(w.Body.Bytes(), []byte{0, 255, 128}) || w.Header().Get("Content-Type") != "image/png" {
			t.Fatal("response bytes changed")
		}
	}
	var wire map[string]any
	if err := json.Unmarshal(exported, &wire); err != nil {
		t.Fatal(err)
	}
	if _, ok := wire["responses"].(map[string]any)["pixel"]; !ok {
		t.Fatal("named response lost")
	}
	for _, input := range []string{
		`{"version":2,"tokens":[{"id":"a","path":"/a","response_ref":"missing"}]}`,
		`{"version":2,"responses":{"a":{}},"tokens":[{"id":"a","path":"/a","response_ref":"a","response":{}}]}`,
	} {
		if _, err := decode(strings.NewReader(input), dir); err == nil {
			t.Fatal("invalid reference accepted")
		}
	}
}
