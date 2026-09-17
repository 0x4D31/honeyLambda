package trap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInvalidConfig(t *testing.T) {
	for _, tc := range []struct{ name, config string }{
		{"old-version", `{"version":1}`},
		{"null", `null`},
		{"unknown-field", strings.Replace(testConfig, `"version":2`, `"version":2,"typo":1`, 1)},
		{"trailing", testConfig + ` {}`},
		{"empty", `{"version":2,"tokens":[]}`},
		{"duplicate-id", strings.Replace(testConfig, `"id":"page"`, `"id":"doc"`, 1)},
		{"duplicate-selector", `{"version":2,"tokens":[{"id":"a","path":"/t","query":{"a":"b","c":"d"}},{"id":"b","path":"/t","query":{"c":"d","a":"b"}}]}`},
		{"bad-path", strings.Replace(testConfig, `"/t/random"`, `"/t/random?x=1"`, 1)},
		{"unescaped-path", strings.Replace(testConfig, `"/t/random"`, `"/t/a b"`, 1)},
		{"invalid-escape", strings.Replace(testConfig, `"/t/random"`, `"/t/%zz"`, 1)},
		{"oversized-capture", strings.Replace(testConfig, `"version":2`, `"version":2,"capture_body_bytes":65537`, 1)},
		{"negative-capture", strings.Replace(testConfig, `"version":2`, `"version":2,"capture_body_bytes":-1`, 1)},
		{"bad-timeout", strings.Replace(testConfig, `"version":2`, `"version":2,"alerts":{"timeout_ms":9999}`, 1)},
		{"bad-cooldown", strings.Replace(testConfig, `"version":2`, `"version":2,"alerts":{"cooldown_seconds":-1}`, 1)},
		{"literal-secret", strings.Replace(testConfig, `"version":2`, `"version":2,"alerts":{"slack_url_env":"https://example.org/secret"}`, 1)},
		{"trust-all", strings.Replace(testConfig, `"version":2`, `"version":2,"trusted_proxies":["0.0.0.0/0"]`, 1)},
		{"bad-proxy", strings.Replace(testConfig, `"version":2`, `"version":2,"trusted_proxies":["wrong"]`, 1)},
		{"status", strings.Replace(testConfig, `"status":404`, `"status":101`, 1)},
		{"body-with-204", strings.Replace(testConfig, `"status":404`, `"status":204`, 1)},
		{"conflicting-bodies", strings.Replace(testConfig, `"body":"missing"`, `"body":"missing","body_base64":"YQ=="`, 1)},
		{"bad-base64", strings.Replace(testConfig, `AAEC/w==`, `%%%`, 1)},
		{"header-injection", strings.Replace(testConfig, `image/png`, `text/plain\r\nX-Foo: bar`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decode(strings.NewReader(tc.config), t.TempDir()); err == nil {
				t.Fatal("accepted invalid config")
			}
		})
	}
}

func TestResponseAssetsAndLimits(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "body.bin"), []byte{0, 255}, 0600); err != nil {
		t.Fatal(err)
	}
	config := `{"version":2,"default_response":{"body_file":"body.bin"},"tokens":[{"id":"a","path":"/a"}]}`
	c, err := decode(strings.NewReader(config), dir)
	if err != nil || len(c.DefaultResponse.data) != 2 {
		t.Fatalf("relative asset: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "body.bin")); err != nil {
		t.Fatal(err)
	}
	if len(c.DefaultResponse.data) != 2 {
		t.Fatal("asset was not snapshotted")
	}
	if _, err := decode(strings.NewReader(config), dir); err == nil {
		t.Fatal("missing asset accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "body.bin"), make([]byte, maxResponseBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := decode(strings.NewReader(config), dir); err == nil {
		t.Fatal("oversized response accepted")
	}
	if _, err := decode(strings.NewReader(strings.Repeat(" ", maxConfigBytes+1)), dir); err == nil {
		t.Fatal("oversized config accepted")
	}
}
