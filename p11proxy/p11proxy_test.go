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

func TestWriteOpenSSLConfEngine(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "openssl-engine.cnf")
	engine := "/usr/lib/x86_64-linux-gnu/engines-3/pkcs11.so"
	module := "/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so"
	if err := writeOpenSSLConfEngine(conf, engine, module); err != nil {
		t.Fatalf("writeOpenSSLConfEngine failed: %v", err)
	}
	b, err := os.ReadFile(conf)
	if err != nil {
		t.Fatalf("cannot read conf: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, engine) || !strings.Contains(s, module) {
		t.Fatalf("openssl conf missing paths: %s", s)
	}
	// Verify ENGINE-specific sections
	if !strings.Contains(s, "engines = engine_section") {
		t.Fatalf("openssl conf missing engines section: %s", s)
	}
	if !strings.Contains(s, "engine_id = pkcs11") {
		t.Fatalf("openssl conf missing engine_id: %s", s)
	}
}

func TestWriteOpenSSLConfProvider(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "openssl-provider.cnf")
	provider := "/usr/lib64/ossl-modules/pkcs11.so"
	module := "/usr/lib64/pkcs11/p11-kit-client.so"
	if err := writeOpenSSLConfProvider(conf, provider, module); err != nil {
		t.Fatalf("writeOpenSSLConfProvider failed: %v", err)
	}
	b, err := os.ReadFile(conf)
	if err != nil {
		t.Fatalf("cannot read conf: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, provider) || !strings.Contains(s, module) {
		t.Fatalf("openssl conf missing paths: %s", s)
	}
	// Verify Provider-specific sections
	if !strings.Contains(s, "providers = provider_section") {
		t.Fatalf("openssl conf missing providers section: %s", s)
	}
	// Verify both default and pkcs11 providers are activated
	if !strings.Contains(s, "default = default_section") {
		t.Fatalf("openssl conf missing default provider: %s", s)
	}
	if !strings.Contains(s, "pkcs11 = pkcs11_section") {
		t.Fatalf("openssl conf missing pkcs11 provider: %s", s)
	}
	// Verify both are activated
	defaultActivated := strings.Contains(s, "[default_section]") && strings.Contains(s, "activate = 1")
	pkcs11Activated := strings.Contains(s, "[pkcs11_section]") && strings.Contains(s, "activate = 1")
	if !defaultActivated || !pkcs11Activated {
		t.Fatalf("openssl conf providers not properly activated: %s", s)
	}
}

func TestPKCS11URLShape(t *testing.T) {
	url := "pkcs11:token=pelican-tls;object=server-key;type=private"
	re := regexp.MustCompile(`^pkcs11:token=[^;]+;object=[^;]+;type=private$`)
	if !re.MatchString(url) {
		t.Fatalf("unexpected pkcs11 url shape: %s", url)
	}
}
