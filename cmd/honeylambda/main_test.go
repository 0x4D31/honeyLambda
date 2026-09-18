package main

import (
	"github.com/0x4D31/honeyLambda/v2/internal/trap"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckAndBundleDoNotRequireNotificationCredentials(t *testing.T) {
	t.Setenv("TEST_HONEY_WEBHOOK", "")
	dir := t.TempDir()
	config := filepath.Join(dir, "service.json")
	if err := os.WriteFile(config, []byte(`{"version":2,"alerts":{"webhook_url_env":"TEST_HONEY_WEBHOOK"},"tokens":[{"id":"a","path":"/a"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"check", "-config", config}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "portable")
	if err := run([]string{"bundle", "-config", config, "-out", out}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"check", "-config", filepath.Join(out, "config.json")}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"bundle", "-config", config, "-out", out}); err == nil {
		t.Fatal("bundle overwrote an existing directory")
	}
	if err := run([]string{"serve", "-config", config}); err == nil {
		t.Fatal("serve accepted missing notification credentials")
	}
}

func TestInitAndURLs(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "config.json")
	if err := run([]string{"init", "-out", config}); err != nil {
		t.Fatal(err)
	}
	c, err := trap.Load(config)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Tokens) != 1 || !strings.HasPrefix(c.Tokens[0].Path, "/t/") || len(c.Tokens[0].Path) != 35 {
		t.Fatal("init did not generate an unpredictable token")
	}
	if err := run([]string{"init", "-out", config}); err == nil {
		t.Fatal("init overwrote existing config")
	}
	c.Tokens[0].Path = "/a/../%2F"
	c.Tokens[0].Query = map[string]string{"key": "a b&=", "z": "2"}
	urls, err := tokenURLs(c, "https://receiver.example/")
	if err != nil || urls[c.Tokens[0].ID] != "https://receiver.example/a/../%2F?key=a+b%26%3D&z=2" {
		t.Fatalf("bad URL: %v %v", urls, err)
	}
	for _, endpoint := range []string{"", "//example.org", "https://user@example.org", "https://example.org?x=1", "https://example.org#fragment"} {
		if _, err := tokenURLs(c, endpoint); err == nil {
			t.Fatal("invalid endpoint accepted:", endpoint)
		}
	}
}
