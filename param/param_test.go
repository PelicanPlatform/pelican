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
	"sync"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
