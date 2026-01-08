package param

import (
	"sort"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func TestAllParameterNamesContainsKnownKeys(t *testing.T) {
	if len(allParameterNames) == 0 {
		t.Fatalf("allParameterNames is empty; generator may not have run")
	}
	if !sort.StringsAreSorted(allParameterNames) {
		t.Fatalf("allParameterNames must be sorted")
	}

	want := []string{
		"Origin.FederationPrefix",
		"TLSSkipVerify",
		"Cache.Port",
	}

	for _, key := range want {
		idx := sort.SearchStrings(allParameterNames, key)
		if idx >= len(allParameterNames) || allParameterNames[idx] != key {
			t.Fatalf("expected key %q in allParameterNames", key)
		}
	}
}

func TestDecodeConfigIncludesEnvOnlyOverrides(t *testing.T) {
	t.Setenv("PELICAN_ORIGIN_FEDERATIONPREFIX", "/test")
	t.Setenv("PELICAN_TLSSKIPVERIFY", "true")

	v := viper.New()
	// Match the relevant parts of Pelican's viper setup for env imports.
	v.SetEnvPrefix("pelican")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	cfg, err := DecodeConfig(v)
	if err != nil {
		t.Fatalf("DecodeConfig returned error: %v", err)
	}
	if cfg == nil {
		t.Fatalf("DecodeConfig returned nil config")
	}
	if got := cfg.Origin.FederationPrefix; got != "/test" {
		t.Fatalf("expected Origin.FederationPrefix=\"/test\", got %q", got)
	}
	if got := cfg.TLSSkipVerify; got != true {
		t.Fatalf("expected TLSSkipVerify=true, got %v", got)
	}

	// Sanity check that these values are not present in v.AllSettings() without binding.
	// This guards the original regression: env-only overrides weren't being picked up
	// when the snapshot was decoded from AllSettings().
	v2 := viper.New()
	v2.SetEnvPrefix("pelican")
	v2.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v2.AutomaticEnv()
	// Unbound env overrides typically won't appear in AllSettings(); we don't assert
	// exact structure, just that the specific keys are absent.
	settings := v2.AllSettings()
	if originAny, ok := settings["origin"]; ok {
		if originMap, ok := originAny.(map[string]any); ok {
			if _, ok := originMap["federationprefix"]; ok {
				// If viper changes behavior in the future and includes env-only overrides in
				// AllSettings by default, this is no longer a meaningful regression test.
				t.Fatalf("viper.AllSettings() unexpectedly includes env-only override for origin.federationprefix; update this test")
			}
		}
	}
}

func TestDecodeConfigIncludesFlagOverrides(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.StringSlice("module", nil, "")
	if err := fs.Set("module", "director,registry"); err != nil {
		t.Fatalf("failed to set module flag: %v", err)
	}

	v := viper.New()
	if err := v.BindPFlag("Server.Modules", fs.Lookup("module")); err != nil {
		t.Fatalf("failed to bind flag: %v", err)
	}

	cfg, err := DecodeConfig(v)
	if err != nil {
		t.Fatalf("DecodeConfig returned error: %v", err)
	}
	if cfg == nil {
		t.Fatalf("DecodeConfig returned nil config")
	}
	got := cfg.Server.Modules
	if len(got) != 2 || got[0] != "director" || got[1] != "registry" {
		t.Fatalf("expected Server.Modules=[director registry], got %v", got)
	}
}
