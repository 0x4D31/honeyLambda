package main

import (
	"os"
	"path/filepath"
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
