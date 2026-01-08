package p11proxy

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// TestDetectPKCS11Mode_Provider tests that Provider mode is selected when available
func TestDetectPKCS11Mode_Provider(t *testing.T) {
	tmpDir := t.TempDir()
	providerPath := filepath.Join(tmpDir, "pkcs11.so")
	enginePath := filepath.Join(tmpDir, "pkcs11-engine.so")

	// Create mock provider file
	err := os.WriteFile(providerPath, []byte("mock"), 0644)
	require.NoError(t, err)

	opts := Options{
		ProviderModulePath: providerPath,
		EngineDynamicPath:  enginePath, // Even if engine is provided, provider should win
	}

	result, err := detectPKCS11Mode(opts)

	require.NoError(t, err)
	assert.Equal(t, modeProvider, result.Mode)
	assert.Equal(t, providerPath, result.ProviderPath)
	assert.Equal(t, enginePath, result.EnginePath)
}

// TestDetectPKCS11Mode_Engine tests that ENGINE mode is selected when Provider is not available
func TestDetectPKCS11Mode_Engine(t *testing.T) {
	tmpDir := t.TempDir()
	enginePath := filepath.Join(tmpDir, "pkcs11-engine.so")
	nonexistentProvider := filepath.Join(tmpDir, "nonexistent-provider.so")

	// Create mock engine file
	err := os.WriteFile(enginePath, []byte("mock"), 0644)
	require.NoError(t, err)

	opts := Options{
		EngineDynamicPath:  enginePath,
		ProviderModulePath: nonexistentProvider, // Explicitly set to nonexistent to disable auto-detection
	}

	result, err := detectPKCS11Mode(opts)

	require.NoError(t, err)
	assert.Equal(t, modeEngine, result.Mode)
	assert.Equal(t, enginePath, result.EnginePath)
	assert.Equal(t, nonexistentProvider, result.ProviderPath)
}

// TestDetectPKCS11Mode_NeitherAvailable tests error when neither Provider nor ENGINE are available
func TestDetectPKCS11Mode_NeitherAvailable(t *testing.T) {
	tmpDir := t.TempDir()
	nonexistentProvider := filepath.Join(tmpDir, "nonexistent-provider.so")
	nonexistentEngine := filepath.Join(tmpDir, "nonexistent-engine.so")

	opts := Options{
		ProviderModulePath: nonexistentProvider, // Explicitly set to nonexistent to disable auto-detection
		EngineDynamicPath:  nonexistentEngine,   // Explicitly set to nonexistent to disable auto-detection
	}

	result, err := detectPKCS11Mode(opts)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no PKCS#11 integration found")
	assert.Equal(t, pkcs11Mode(0), result.Mode) // Should be zero value
}

// TestDetectPKCS11Mode_ProviderPreferred tests that Provider is preferred over ENGINE
func TestDetectPKCS11Mode_ProviderPreferred(t *testing.T) {
	tmpDir := t.TempDir()
	providerPath := filepath.Join(tmpDir, "pkcs11-provider.so")
	enginePath := filepath.Join(tmpDir, "pkcs11-engine.so")

	// Create both mock files
	err := os.WriteFile(providerPath, []byte("mock provider"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(enginePath, []byte("mock engine"), 0644)
	require.NoError(t, err)

	opts := Options{
		ProviderModulePath: providerPath,
		EngineDynamicPath:  enginePath,
	}

	result, err := detectPKCS11Mode(opts)

	require.NoError(t, err)
	assert.Equal(t, modeProvider, result.Mode, "Provider should be preferred when both are available")
	assert.Equal(t, providerPath, result.ProviderPath)
	assert.Equal(t, enginePath, result.EnginePath)
}

// TestDetectPKCS11Mode_AutoDetection tests auto-detection fallback
func TestDetectPKCS11Mode_AutoDetection(t *testing.T) {
	// This test would pass if the system has actual PKCS#11 modules installed
	// In CI/test environments without these modules, it should error
	opts := Options{} // Empty options trigger auto-detection

	result, err := detectPKCS11Mode(opts)

	// We can't assert success/failure since it depends on the environment
	// But we can check that if it succeeds, it returns a valid mode
	if err == nil {
		assert.True(t, result.Mode == modeProvider || result.Mode == modeEngine,
			"If auto-detection succeeds, it should return a valid mode")
		if result.Mode == modeProvider {
			assert.NotEmpty(t, result.ProviderPath, "Provider mode should have non-empty ProviderPath")
		} else {
			assert.NotEmpty(t, result.EnginePath, "Engine mode should have non-empty EnginePath")
		}
	} else {
		// If it fails, it should have a meaningful error
		assert.Contains(t, err.Error(), "no PKCS#11 integration found")
	}
}

// TestEscapePKCS11 tests the PKCS#11 URL escaping per RFC 7512
func TestEscapePKCS11(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no special characters",
			input:    "simple",
			expected: "simple",
		},
		{
			name:     "semicolon",
			input:    "token;label",
			expected: "token%3Blabel",
		},
		{
			name:     "equals",
			input:    "key=value",
			expected: "key%3Dvalue",
		},
		{
			name:     "percent",
			input:    "100%",
			expected: "100%25",
		},
		{
			name:     "colon",
			input:    "uri:path",
			expected: "uri%3Apath",
		},
		{
			name:     "comma",
			input:    "a,b,c",
			expected: "a%2Cb%2Cc",
		},
		{
			name:     "space",
			input:    "my token",
			expected: "my%20token",
		},
		{
			name:     "multiple special chars",
			input:    "a=b;c:d,e %f",
			expected: "a%3Db%3Bc%3Ad%2Ce%20%25f",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := escapePKCS11(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
