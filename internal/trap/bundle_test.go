package trap

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundlePortableAndIndependent(t *testing.T) {
	source, destination := t.TempDir(), t.TempDir()
	body := []byte{0, 255, 128, 10}
	if err := os.WriteFile(filepath.Join(source, "pixel"), body, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := decode(strings.NewReader(`{"version":2,"default_response":{"body_file":"pixel"},"alerts":{"webhook_url_env":"UNSET_NOTIFICATION_URL"},"tokens":[{"id":"a","path":"/a","response":{"body_file":"pixel"}}]}`), source)
	if err != nil {
		t.Fatal(err)
	}
	files, err := c.Bundle()
	if err != nil || len(files) != 2 {
		t.Fatalf("bundle/deduplication: %d files, %v", len(files), err)
	}
	if c.DefaultResponse.BodyFile != "pixel" || c.Tokens[0].Response.BodyFile != "pixel" {
		t.Fatal("bundle mutated original config")
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(destination, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.RemoveAll(source); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Load(filepath.Join(destination, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reloaded.DefaultResponse.data, body) || !bytes.Equal(reloaded.Tokens[0].Response.data, body) {
		t.Fatal("bundle changed binary response")
	}
	for name := range files {
		if name != "config.json" {
			files[name][0] = 42
		}
	}
	if !bytes.Equal(c.DefaultResponse.data, body) {
		t.Fatal("bundle shares response storage")
	}
}
