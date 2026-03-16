/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

package param

import (
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/byte_rate"
)

func TestSetAndGet(t *testing.T) {
	// Reset viper and config before test
	viper.Reset()
	defer viper.Reset()

	// Test setting a value
	err := Set("TestKey", "TestValue")
	require.NoError(t, err)

	// Verify the value was set in viper
	assert.Equal(t, "TestValue", viper.GetString("TestKey"))

	// Verify the config was updated
	config, err := GetUnmarshaledConfig()
	require.NoError(t, err)
	assert.NotNil(t, config)
}

func TestMultiSet(t *testing.T) {
	// Reset viper and config before test
	viper.Reset()
	defer viper.Reset()

	// Test setting multiple values at once
	err := MultiSet(map[string]interface{}{
		"Key1": "Value1",
		"Key2": 42,
		"Key3": true,
	})
	require.NoError(t, err)

	// Verify the values were set
	assert.Equal(t, "Value1", viper.GetString("Key1"))
	assert.Equal(t, 42, viper.GetInt("Key2"))
	assert.Equal(t, true, viper.GetBool("Key3"))

	// Verify the config was updated
	config, err := GetUnmarshaledConfig()
	require.NoError(t, err)
	assert.NotNil(t, config)
}

func TestReset(t *testing.T) {
	// Set some values
	viper.Set("TestKey1", "Value1")
	viper.Set("TestKey2", "Value2")

	// Reset
	err := Reset()
	require.NoError(t, err)

	// Verify viper was reset
	assert.Empty(t, viper.GetString("TestKey1"))
	assert.Empty(t, viper.GetString("TestKey2"))

	// Verify config was cleared
	config := viperConfig.Load()
	assert.Nil(t, config)
}

func TestConcurrentSetAndGet(t *testing.T) {
	// Reset before test
	viper.Reset()
	defer viper.Reset()

	// Test concurrent Set operations
	var wg sync.WaitGroup
	numGoroutines := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(val int) {
			defer wg.Done()
			key := "ConcurrentKey"
			_ = Set(key, val)
		}(i)
	}

	wg.Wait()

	// Verify that we can still get a valid config
	config, err := GetUnmarshaledConfig()
	require.NoError(t, err)
	assert.NotNil(t, config)
}

func TestUnmarshalConfig(t *testing.T) {
	// Reset before test
	viper.Reset()
	defer viper.Reset()

	// Set some test values
	viper.Set("TestString", "hello")
	viper.Set("TestInt", 42)
	viper.Set("TestBool", true)

	// Unmarshal (global-only)
	config, err := UnmarshalConfig()
	require.NoError(t, err)
	require.NotNil(t, config)

	// Verify config was stored atomically
	loadedConfig, err := GetUnmarshaledConfig()
	require.NoError(t, err)
	assert.Equal(t, config, loadedConfig)
}

func TestAccessorFunctionsUseAtomicConfig(t *testing.T) {
	// Reset before test
	viper.Reset()
	defer viper.Reset()

	// Set some values using the config struct
	viper.Set("Cache.Port", 8443)
	viper.Set("Cache.EnableBroker", true)
	viper.Set("Cache.DataLocation", "/tmp/cache")
	viper.Set("Cache.SelfTestInterval", time.Minute*5)

	// Unmarshal to populate the atomic config
	_, err := UnmarshalConfig()
	require.NoError(t, err)

	// Test that accessor functions read from the atomic config
	assert.Equal(t, 8443, Cache_Port.GetInt())
	assert.Equal(t, true, Cache_EnableBroker.GetBool())
	assert.Equal(t, "/tmp/cache", Cache_DataLocation.GetString())
	assert.Equal(t, time.Minute*5, Cache_SelfTestInterval.GetDuration())
}

func TestDecodeConfigDoesNotMutateAtomicConfig(t *testing.T) {
	// Reset before test
	viper.Reset()
	defer viper.Reset()

	// Populate global atomic config with one value
	viper.Set("Cache.Port", 9000)
	_, err := UnmarshalConfig()
	require.NoError(t, err)

	// Create a separate viper with different values and decode it
	local := viper.New()
	local.Set("Cache.Port", 1234)
	decoded, err := DecodeConfig(local)
	require.NoError(t, err)
	require.NotNil(t, decoded)
	assert.Equal(t, 1234, decoded.Cache.Port)

	// Ensure atomic cache still reflects global viper's value
	stored, err := GetUnmarshaledConfig()
	require.NoError(t, err)
	assert.Equal(t, 9000, stored.Cache.Port)
}

func TestGetOrCreateConfig(t *testing.T) {
	// Reset before test
	viper.Reset()
	defer viper.Reset()

	// Clear the atomic config
	viperConfig.Store(nil)

	// Set test values in viper
	viper.Set("Cache.Port", 9000)
	viper.Set("Cache.DataLocation", "/test/path")

	// Call getOrCreateConfig - should create config from viper
	config := getOrCreateConfig()
	require.NotNil(t, config)

	// Verify the config has the values from viper
	assert.Equal(t, 9000, config.Cache.Port)
	assert.Equal(t, "/test/path", config.Cache.DataLocation)

	// Verify it's now stored in the atomic pointer
	storedConfig := viperConfig.Load()
	assert.Equal(t, config, storedConfig)
}

func TestAccessorFunctionsWithNoConfig(t *testing.T) {
	// Reset before test
	viper.Reset()
	defer viper.Reset()

	// Clear the atomic config
	viperConfig.Store(nil)

	// Set values in viper
	viper.Set("Cache.Port", 7000)

	// Accessor should work even without explicit UnmarshalConfig call
	// because getOrCreateConfig will create it
	port := Cache_Port.GetInt()
	assert.Equal(t, 7000, port)

	// Verify config was created and stored
	config := viperConfig.Load()
	require.NotNil(t, config)
	assert.Equal(t, 7000, config.Cache.Port)
}

func TestIsRuntimeConfigurable(t *testing.T) {
	// Test the package-level function with a parameter that has runtime_configurable: true
	assert.True(t, IsRuntimeConfigurable("Logging.Level"), "Logging.Level should be runtime configurable")

	// Test with a parameter that has runtime_configurable: false
	assert.False(t, IsRuntimeConfigurable("TLSSkipVerify"), "TLSSkipVerify should not be runtime configurable")

	// Test with a parameter that doesn't specify runtime_configurable (should default to false)
	assert.False(t, IsRuntimeConfigurable("Cache.Port"), "Cache.Port should default to not runtime configurable")

	// Test with a non-existent parameter
	assert.False(t, IsRuntimeConfigurable("NonExistent.Parameter"), "Non-existent parameter should return false")
}

func TestParamIsRuntimeConfigurable(t *testing.T) {
	// Test the method on different param types
	assert.True(t, Logging_Level.IsRuntimeConfigurable(), "Logging.Level should be runtime configurable")
	assert.False(t, TLSSkipVerify.IsRuntimeConfigurable(), "TLSSkipVerify should not be runtime configurable")
	assert.False(t, Cache_Port.IsRuntimeConfigurable(), "Cache.Port should not be runtime configurable")
}

func TestGetRuntimeConfigurable(t *testing.T) {
	// Test that GetRuntimeConfigurable returns a valid map
	runtimeConfigMap := GetRuntimeConfigurable()
	require.NotNil(t, runtimeConfigMap, "GetRuntimeConfigurable should return a non-nil map")

	// Verify specific entries
	loggingLevel, exists := runtimeConfigMap["Logging.Level"]
	assert.True(t, exists, "Logging.Level should exist in the map")
	assert.True(t, loggingLevel, "Logging.Level should be true in the map")

	tlsSkipVerify, exists := runtimeConfigMap["TLSSkipVerify"]
	assert.True(t, exists, "TLSSkipVerify should exist in the map")
	assert.False(t, tlsSkipVerify, "TLSSkipVerify should be false in the map")
}

// Test various parameter types to ensure they return correct environment variable names
func TestGetEnvVarName(t *testing.T) {
	// Define an interface to generalize over different param for ease of testing -- this probably
	// should have been done at the package level from the getgo ¯\_(ツ)_/¯
	type param interface {
		GetEnvVarName() string
		GetName() string
	}

	testCases := []struct {
		name     string
		param    param
		expected string
	}{
		{
			name:     "test-string-param",
			param:    Cache_Port,
			expected: "PELICAN_CACHE_PORT",
		},
		{
			name:     "test-single-word-param",
			param:    TLSSkipVerify,
			expected: "PELICAN_TLSSKIPVERIFY",
		},
		{
			name:     "test-bool-and-nested-param",
			param:    Origin_EnableListings,
			expected: "PELICAN_ORIGIN_ENABLELISTINGS",
		},
		{
			name:     "test-string-slice-param",
			param:    ConfigLocations,
			expected: "PELICAN_CONFIGLOCATIONS",
		},
		{
			name:     "test-duration-param",
			param:    Cache_SelfTestInterval,
			expected: "PELICAN_CACHE_SELFTESTINTERVAL",
		},
		{
			name:     "test-object-param",
			param:    Registry_Institutions,
			expected: "PELICAN_REGISTRY_INSTITUTIONS",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			envVar := tc.param.GetEnvVarName()
			assert.Equal(t, tc.expected, envVar, "%s should map to %s", tc.param.GetName(), tc.expected)
		})
	}
}

func TestCallbackRegistration(t *testing.T) {
	// Reset before test
	require.NoError(t, Reset())
	defer func() {
		require.NoError(t, Reset())
	}()

	// Track callback invocations
	callbackInvoked := make(chan bool, 1)

	// Register a callback
	RegisterCallback("test1", func(oldConfig, newConfig *Config) {
		// For this test, we'll just signal that the callback was invoked
		callbackInvoked <- true
	})

	// Set a value to trigger callback
	err := Set("TestKey", "TestValue")
	require.NoError(t, err)

	// Wait for callback to be invoked (with timeout)
	select {
	case <-callbackInvoked:
	// Success
	case <-time.After(1 * time.Second):
		t.Fatal("Callback was not invoked")
	}
}

func TestCallbackWithConfigChanges(t *testing.T) {
	// Reset before test
	require.NoError(t, Reset())
	defer func() {
		require.NoError(t, Reset())
	}()

	// Track callback invocations with actual config values
	callbackInvoked := make(chan bool, 1)
	var receivedOldConfig, receivedNewConfig *Config

	// Register a callback that captures the configs
	RegisterCallback("test2", func(oldConfig, newConfig *Config) {
		receivedOldConfig = oldConfig
		receivedNewConfig = newConfig
		callbackInvoked <- true
	})

	// Set initial value
	err := Set("Logging.Level", "info")
	require.NoError(t, err)

	// Wait for first callback
	select {
	case <-callbackInvoked:
	// First callback received
	case <-time.After(1 * time.Second):
		t.Fatal("First callback was not invoked")
	}

	// Change the value
	err = Set("Logging.Level", "debug")
	require.NoError(t, err)

	// Wait for second callback
	select {
	case <-callbackInvoked:
		// Second callback received - verify old and new configs differ
		assert.NotNil(t, receivedOldConfig)
		assert.NotNil(t, receivedNewConfig)
		// The configs should be different instances
		assert.NotEqual(t, receivedOldConfig, receivedNewConfig)
	case <-time.After(1 * time.Second):
		t.Fatal("Second callback was not invoked")
	}
}

// TestStringToSliceHookFunc tests that the custom hook function correctly handles
// both comma-separated and whitespace-separated strings for slice fields.
// This is important for supporting YAML >- folding style in config files.
func TestStringToSliceHookFunc(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "comma-separated",
			input:    "a,b,c",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "comma-separated-with-spaces",
			input:    "a, b, c",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "whitespace-separated",
			input:    "a b c",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "newline-separated",
			input:    "a\nb\nc",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "tab-separated",
			input:    "a\tb\tc",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "cilogon-subjects-space-separated",
			input:    "http://cilogon.org/serverE/users/123 http://cilogon.org/serverA/users/456",
			expected: []string{"http://cilogon.org/serverE/users/123", "http://cilogon.org/serverA/users/456"},
		},
		{
			name:     "cilogon-subjects-comma-separated",
			input:    "http://cilogon.org/serverE/users/123,http://cilogon.org/serverA/users/456",
			expected: []string{"http://cilogon.org/serverE/users/123", "http://cilogon.org/serverA/users/456"},
		},
		{
			name:     "single-value",
			input:    "single",
			expected: []string{"single"},
		},
		{
			name:     "empty-string",
			input:    "",
			expected: []string{},
		},
		{
			name:     "mixed-whitespace",
			input:    "  a   b  \n  c  ",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "comma-separated-with-double-quotes",
			input:    `"a","b","c"`,
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "comma-separated-with-single-quotes",
			input:    `'a','b','c'`,
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "comma-separated-with-mixed-quotes",
			input:    `"a",'b',"c"`,
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "space-separated-with-double-quotes",
			input:    `"a" "b" "c"`,
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "space-separated-with-single-quotes",
			input:    `'a' 'b' 'c'`,
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "comma-separated-with-quotes-and-spaces",
			input:    `"a", "b", "c"`,
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "preferred-caches-with-plus-and-quotes",
			input:    `"https://cache1.com:8443","https://cache2.com:8443","+"`,
			expected: []string{"https://cache1.com:8443", "https://cache2.com:8443", "+"},
		},
		{
			name:     "preferred-caches-space-separated-with-quotes",
			input:    `"https://cache1.com:8443" "https://cache2.com:8443" "+"`,
			expected: []string{"https://cache1.com:8443", "https://cache2.com:8443", "+"},
		},
		{
			name:     "preferred-caches-comma-separated-with-quotes",
			input:    `https://cache1.com:8443,https://cache2.com:8443,+`,
			expected: []string{"https://cache1.com:8443", "https://cache2.com:8443", "+"},
		},
		{
			name:     "quotes-with-spaces-inside",
			input:    `"a b","c d"`,
			expected: []string{"a b", "c d"},
		},
		{
			name:     "partial-quotes",
			input:    `"a",b,"c"`,
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "entire-string-double-quoted",
			input:    `"cache1 cache2 +"`,
			expected: []string{"cache1", "cache2", "+"},
		},
		{
			name:     "entire-string-single-quoted",
			input:    `'cache1 cache2 +'`,
			expected: []string{"cache1", "cache2", "+"},
		},
		{
			name:     "entire-string-quoted-with-comma",
			input:    `"cache1,cache2,+"`,
			expected: []string{"cache1", "cache2", "+"},
		},
		{
			name:     "nested-quotes-docker-env-style",
			input:    `'"cache1" "cache2" "+"'`,
			expected: []string{"cache1", "cache2", "+"},
		},
		{
			name:     "double-quoted-elements-in-quoted-string",
			input:    `"cache1" "cache2" "+"`,
			expected: []string{"cache1", "cache2", "+"},
		},
		{
			name:     "single-quoted-elements-in-quoted-string",
			input:    `'cache1' 'cache2' '+'`,
			expected: []string{"cache1", "cache2", "+"},
		},
		{
			name:     "mixed-quotes-complex",
			input:    `'"a"" "b"" "c"'`,
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "docker-env-file-style-with-spaces",
			input:    `"https://cache1.com:8443 https://cache2.com:8443 +"`,
			expected: []string{"https://cache1.com:8443", "https://cache2.com:8443", "+"},
		},
		{
			name:     "docker-env-file-style-with-commas",
			input:    `"https://cache1.com:8443,https://cache2.com:8443,+"`,
			expected: []string{"https://cache1.com:8443", "https://cache2.com:8443", "+"},
		},
	}

	hook := stringToSliceHookFunc()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Call the hook function
			result, err := hook.(func(f, t reflect.Kind, data interface{}) (interface{}, error))(
				reflect.String,
				reflect.Slice,
				tc.input,
			)
			require.NoError(t, err)

			// Verify the result
			resultSlice, ok := result.([]string)
			require.True(t, ok, "Result should be []string")
			assert.Equal(t, tc.expected, resultSlice)
		})
	}
}

// TestDecodeConfigWithYAMLFoldingStyle tests that DecodeConfig correctly handles
// YAML >- folding style for UIAdminUsers (and other string slice fields).
// These tests use actual YAML files to verify the full parsing flow.
func TestDecodeConfigWithYAMLFoldingStyle(t *testing.T) {
	user1 := "http://cilogon.org/serverE/users/123"
	user2 := "http://cilogon.org/serverA/users/456"

	t.Run("yaml-folding-style-with-actual-yaml", func(t *testing.T) {
		viper.Reset()
		defer viper.Reset()

		// Create a temporary YAML file with >- folding style
		// This is exactly what users might write in their pelican.yaml
		yamlContent := `Server:
  UIAdminUsers: >-
    http://cilogon.org/serverE/users/123
    http://cilogon.org/serverA/users/456
`
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "pelican.yaml")
		err := os.WriteFile(configPath, []byte(yamlContent), 0644)
		require.NoError(t, err)

		// Parse the YAML file using viper
		v := viper.New()
		v.SetConfigFile(configPath)
		err = v.ReadInConfig()
		require.NoError(t, err)

		// Log what viper sees (useful for debugging)
		rawValue := v.Get("Server.UIAdminUsers")
		t.Logf("Raw viper value type: %T", rawValue)
		t.Logf("Raw viper value: %v", rawValue)

		// Decode into Config struct
		cfg, err := DecodeConfig(v)
		require.NoError(t, err)

		// Verify the config has two separate elements
		t.Logf("Decoded UIAdminUsers: %v (len=%d)", cfg.Server.UIAdminUsers, len(cfg.Server.UIAdminUsers))
		assert.Len(t, cfg.Server.UIAdminUsers, 2, "Should have two admin users")
		assert.Contains(t, cfg.Server.UIAdminUsers, user1)
		assert.Contains(t, cfg.Server.UIAdminUsers, user2)
	})

	t.Run("yaml-list-style-with-actual-yaml", func(t *testing.T) {
		viper.Reset()
		defer viper.Reset()

		// Create a YAML file with proper list syntax
		yamlContent := `Server:
  UIAdminUsers:
    - "http://cilogon.org/serverE/users/123"
    - "http://cilogon.org/serverA/users/456"
`
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "pelican.yaml")
		err := os.WriteFile(configPath, []byte(yamlContent), 0644)
		require.NoError(t, err)

		v := viper.New()
		v.SetConfigFile(configPath)
		err = v.ReadInConfig()
		require.NoError(t, err)

		cfg, err := DecodeConfig(v)
		require.NoError(t, err)

		assert.Len(t, cfg.Server.UIAdminUsers, 2, "Should have two admin users")
		assert.Contains(t, cfg.Server.UIAdminUsers, user1)
		assert.Contains(t, cfg.Server.UIAdminUsers, user2)
	})

	t.Run("yaml-inline-list-with-actual-yaml", func(t *testing.T) {
		viper.Reset()
		defer viper.Reset()

		// Create a YAML file with inline list syntax (JSON-style)
		yamlContent := `Server:
  UIAdminUsers: ["http://cilogon.org/serverE/users/123", "http://cilogon.org/serverA/users/456"]
`
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "pelican.yaml")
		err := os.WriteFile(configPath, []byte(yamlContent), 0644)
		require.NoError(t, err)

		v := viper.New()
		v.SetConfigFile(configPath)
		err = v.ReadInConfig()
		require.NoError(t, err)

		cfg, err := DecodeConfig(v)
		require.NoError(t, err)

		assert.Len(t, cfg.Server.UIAdminUsers, 2, "Should have two admin users")
		assert.Contains(t, cfg.Server.UIAdminUsers, user1)
		assert.Contains(t, cfg.Server.UIAdminUsers, user2)
	})

	t.Run("yaml-literal-block-style-with-actual-yaml", func(t *testing.T) {
		viper.Reset()
		defer viper.Reset()

		// Create a YAML file with literal block style (|-)
		// This preserves newlines, so each user is on its own line
		yamlContent := `Server:
  UIAdminUsers: |-
    http://cilogon.org/serverE/users/123
    http://cilogon.org/serverA/users/456
`
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "pelican.yaml")
		err := os.WriteFile(configPath, []byte(yamlContent), 0644)
		require.NoError(t, err)

		v := viper.New()
		v.SetConfigFile(configPath)
		err = v.ReadInConfig()
		require.NoError(t, err)

		// Log what viper sees
		rawValue := v.Get("Server.UIAdminUsers")
		t.Logf("Raw viper value type: %T", rawValue)
		t.Logf("Raw viper value: %q", rawValue)

		cfg, err := DecodeConfig(v)
		require.NoError(t, err)

		// Literal block style preserves newlines, which our hook splits on
		t.Logf("Decoded UIAdminUsers: %v (len=%d)", cfg.Server.UIAdminUsers, len(cfg.Server.UIAdminUsers))
		assert.Len(t, cfg.Server.UIAdminUsers, 2, "Should have two admin users")
		assert.Contains(t, cfg.Server.UIAdminUsers, user1)
		assert.Contains(t, cfg.Server.UIAdminUsers, user2)
	})

	t.Run("yaml-comma-separated-string-with-actual-yaml", func(t *testing.T) {
		viper.Reset()
		defer viper.Reset()

		// Create a YAML file with comma-separated string
		yamlContent := `Server:
  UIAdminUsers: "http://cilogon.org/serverE/users/123,http://cilogon.org/serverA/users/456"
`
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "pelican.yaml")
		err := os.WriteFile(configPath, []byte(yamlContent), 0644)
		require.NoError(t, err)

		v := viper.New()
		v.SetConfigFile(configPath)
		err = v.ReadInConfig()
		require.NoError(t, err)

		cfg, err := DecodeConfig(v)
		require.NoError(t, err)

		assert.Len(t, cfg.Server.UIAdminUsers, 2, "Should have two admin users")
		assert.Contains(t, cfg.Server.UIAdminUsers, user1)
		assert.Contains(t, cfg.Server.UIAdminUsers, user2)
	})
}

func TestByteRateDecoding(t *testing.T) {
	t.Run("decode-human-readable-rate", func(t *testing.T) {
		viper.Reset()
		defer viper.Reset()

		// Create a YAML file with human-readable byte rate
		yamlContent := `Origin:
  TransferRateLimit: 10MB/s
`
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "pelican.yaml")
		err := os.WriteFile(configPath, []byte(yamlContent), 0644)
		require.NoError(t, err)

		v := viper.New()
		v.SetConfigFile(configPath)
		err = v.ReadInConfig()
		require.NoError(t, err)

		cfg, err := DecodeConfig(v)
		require.NoError(t, err)

		// 10MB/s should be 10 * 1048576 (MiB) = 10485760 bytes/second
		expected := byte_rate.ByteRate(10 * 1048576)
		assert.Equal(t, expected, cfg.Origin.TransferRateLimit, "Should decode 10MB/s correctly")
	})

	t.Run("decode-bits-per-second", func(t *testing.T) {
		viper.Reset()
		defer viper.Reset()

		yamlContent := `Origin:
  TransferRateLimit: 100Mbps
`
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "pelican.yaml")
		err := os.WriteFile(configPath, []byte(yamlContent), 0644)
		require.NoError(t, err)

		v := viper.New()
		v.SetConfigFile(configPath)
		err = v.ReadInConfig()
		require.NoError(t, err)

		cfg, err := DecodeConfig(v)
		require.NoError(t, err)

		// 100Mbps = 100 * 1048576 / 8 = 13107200 bytes/second
		expected := byte_rate.ByteRate(100 * 1048576 / 8)
		assert.Equal(t, expected, cfg.Origin.TransferRateLimit, "Should decode 100Mbps correctly")
	})

	t.Run("decode-zero-rate", func(t *testing.T) {
		viper.Reset()
		defer viper.Reset()

		yamlContent := `Origin:
  TransferRateLimit: 0MB/s
`
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "pelican.yaml")
		err := os.WriteFile(configPath, []byte(yamlContent), 0644)
		require.NoError(t, err)

		v := viper.New()
		v.SetConfigFile(configPath)
		err = v.ReadInConfig()
		require.NoError(t, err)

		cfg, err := DecodeConfig(v)
		require.NoError(t, err)

		assert.Equal(t, byte_rate.ByteRate(0), cfg.Origin.TransferRateLimit, "Should handle zero rate")
	})

	t.Run("decode-invalid-rate-should-error", func(t *testing.T) {
		viper.Reset()
		defer viper.Reset()

		yamlContent := `Origin:
  TransferRateLimit: invalid-rate
`
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "pelican.yaml")
		err := os.WriteFile(configPath, []byte(yamlContent), 0644)
		require.NoError(t, err)

		v := viper.New()
		v.SetConfigFile(configPath)
		err = v.ReadInConfig()
		require.NoError(t, err)

		_, err = DecodeConfig(v)
		assert.Error(t, err, "Should error on invalid rate format")
	})

	t.Run("decode-with-viper-set", func(t *testing.T) {
		viper.Reset()
		defer viper.Reset()

		v := viper.New()
		v.Set("Origin.TransferRateLimit", "5GB/s")

		cfg, err := DecodeConfig(v)
		require.NoError(t, err)

		// 5GB/s = 5 * 1073741824 = 5368709120 bytes/second
		expected := byte_rate.ByteRate(5 * 1073741824)
		assert.Equal(t, expected, cfg.Origin.TransferRateLimit, "Should decode rate set via viper.Set")
	})

	t.Run("accessor-function-with-byterate", func(t *testing.T) {
		viper.Reset()
		defer viper.Reset()

		// Clear the atomic config
		viperConfig.Store(nil)

		// Set value directly in viper
		viper.Set("Origin.TransferRateLimit", "50MB/s")

		// Accessor should work even without explicit config creation
		// because getOrCreateConfig will create it
		rateLimit := Origin_TransferRateLimit.GetByteRate()
		expected := byte_rate.ByteRate(50 * 1048576)
		assert.Equal(t, expected, rateLimit, "Accessor should return correct byte rate value")

		// Verify config was created and stored
		config := viperConfig.Load()
		require.NotNil(t, config)
		assert.Equal(t, expected, config.Origin.TransferRateLimit)
	})
}
