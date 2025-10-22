package p11proxy

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/pelicanplatform/pelican/server_structs"
)

func TestStartDisabledGraceful(t *testing.T) {
	// Force disable via param by temporarily overriding viper env via an env var is not trivial here;
	// instead, just call Start and expect graceful disable because startServer returns disabled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p, err := Start(ctx, Options{}, server_structs.CacheType)
	if err != nil {
		t.Fatalf("Start returned error: %v", err)
	}
	if p == nil {
		t.Fatalf("Start returned nil proxy")
	}
	if p.Info().Enabled {
		t.Fatalf("Expected helper to be auto-disabled in default build, got enabled")
	}
}

func TestWriteOpenSSLConf(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "o.cnf")
	engine := "/usr/lib/x86_64-linux-gnu/engines-3/pkcs11.so"
	module := "/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so"
	if err := writeOpenSSLConf(conf, engine, module); err != nil {
		t.Fatalf("writeOpenSSLConf failed: %v", err)
	}
	b, err := os.ReadFile(conf)
	if err != nil {
		t.Fatalf("cannot read conf: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, engine) || !strings.Contains(s, module) {
		t.Fatalf("openssl conf missing paths: %s", s)
	}
}

func TestPKCS11URLShape(t *testing.T) {
	url := "pkcs11:token=pelican-tls;object=server-key;type=private"
	re := regexp.MustCompile(`^pkcs11:token=[^;]+;object=[^;]+;type=private$`)
	if !re.MatchString(url) {
		t.Fatalf("unexpected pkcs11 url shape: %s", url)
	}
}
