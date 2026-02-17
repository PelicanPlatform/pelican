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
	"reflect"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/mitchellh/mapstructure"

	"github.com/pkg/errors"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/byte_rate"
)

var (
	viperConfig atomic.Pointer[Config]
	configMutex sync.Mutex
	callbacks   map[string]ConfigCallback
	callbackMux sync.RWMutex
)

// ConfigCallback is a function that is called when configuration changes.
// It receives the old and new configuration.
type ConfigCallback func(oldConfig, newConfig *Config)

func init() {
	callbacks = make(map[string]ConfigCallback)
}

// Refresh reloads the atomic cached configuration from viper's *global* instance.
//
// The param accessors read from an atomic cached `Config` struct for performance.
// Any code that mutates configuration via global viper APIs (SetDefault, Set,
// MergeConfig, MergeInConfig, ReadConfig, etc.) should call Refresh afterwards to
// keep param getters consistent with viper.
//
// Note: the cached config is global process state; Refresh intentionally does not
// accept a viper instance to avoid implying that refreshing from a non-global viper
// is safe.
func Refresh() (*Config, error) {
	return UnmarshalConfig()
}

// BindAllParameters binds all known configuration keys to environment variables.
//
// Viper's AutomaticEnv() allows env vars to override Get* calls. However,
// Viper's AllSettings() (which we use to build a snapshot Config) does not
// necessarily include env-only values unless the key is explicitly bound.
//
// By binding all known keys, we ensure env overrides are reflected in the
// snapshot and therefore in generated `param.*` getters.
func BindAllParameters(v *viper.Viper) {
	if v == nil {
		return
	}

	for _, key := range allParameterNames {
		_ = v.BindEnv(key)
	}
}

// stringToSliceHookFunc returns a DecodeHookFunc that converts strings to slices
// by splitting on commas or whitespace. This handles both:
//   - Comma-separated: "a,b,c" → ["a", "b", "c"]
//   - Whitespace-separated: "a b c" → ["a", "b", "c"] (supports YAML >- folding style)
//   - Mixed: "a, b c" → ["a", "b", "c"]
//
// The function supports both comma and space as separators. If the string contains
// commas, it splits on commas (and trims whitespace from each element).
// Otherwise, it splits on whitespace.
// Surrounding quotes (both single and double) are trimmed from the entire string
// first (to handle Docker env files where quotes are preserved), and then from each
// element after splitting.
// Empty strings after splitting are filtered out.
func stringToSliceHookFunc() mapstructure.DecodeHookFunc {
	return func(f reflect.Kind, t reflect.Kind, data interface{}) (interface{}, error) {
		if f != reflect.String || t != reflect.Slice {
			return data, nil
		}

		raw := data.(string)
		if raw == "" {
			return []string{}, nil
		}

		// First, trim surrounding quotes from the entire string (handles Docker env files
		// where quotes are preserved as-is, unlike shell which strips them)
		raw = strings.Trim(raw, `"'`)

		var result []string

		// If the string contains commas, split on commas (standard behavior)
		if strings.Contains(raw, ",") {
			parts := strings.Split(raw, ",")
			for _, part := range parts {
				// Trim whitespace first
				trimmed := strings.TrimSpace(part)
				// Trim surrounding quotes (both single and double) from each element
				trimmed = strings.Trim(trimmed, `"'`)
				if trimmed != "" {
					result = append(result, trimmed)
				}
			}
		} else {
			// Otherwise, split on whitespace (handles YAML >- folding style)
			parts := strings.Fields(raw)
			for _, part := range parts {
				// Trim surrounding quotes (both single and double) from each element
				trimmed := strings.Trim(part, `"'`)
				if trimmed != "" {
					result = append(result, trimmed)
				}
			}
		}

		return result, nil
	}
}

// stringToByteRateHookFunc returns a DecodeHookFunc that converts strings to byte rates
// representing bytes per second. It supports human-readable rate formats like:
//   - "10MB/s", "100Mbps", "1.5GiB/m"
//
// Empty string or "0" returns 0 (no rate limiting).
// For strings that don't look like byte rates (don't contain rate units), returns data unchanged
// so other hooks or default conversions can handle them.
func stringToByteRateHookFunc() mapstructure.DecodeHookFunc {
	return func(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
		// Only convert string to int or ByteRate
		byteRateType := reflect.TypeOf(byte_rate.ByteRate(0))
		if f.Kind() != reflect.String || (t.Kind() != reflect.Int && t != byteRateType) {
			return data, nil
		}

		raw, ok := data.(string)
		if !ok {
			return data, nil
		}

		// Empty or "0" means no rate limiting
		if raw == "" || raw == "0" {
			if t == byteRateType {
				return byte_rate.ByteRate(0), nil
			}
			return 0, nil
		}

		// Check if this looks like a byte rate string (contains common rate units)
		// If it doesn't contain rate units, pass it through unchanged for normal int parsing
		lowerRaw := strings.ToLower(strings.TrimSpace(raw))
		hasRateUnits := strings.Contains(lowerRaw, "b/s") ||
			strings.Contains(lowerRaw, "bps") ||
			strings.Contains(lowerRaw, "bit/s") ||
			strings.Contains(lowerRaw, "byte/s") ||
			strings.HasSuffix(lowerRaw, "/s") ||
			strings.HasSuffix(lowerRaw, "/m") ||
			strings.HasSuffix(lowerRaw, "/h")

		if !hasRateUnits {
			// Doesn't look like a rate string, pass it through unchanged
			return data, nil
		}

		// Parse the rate string
		rate, err := byte_rate.ParseRate(raw)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse byte rate '%s'", raw)
		}

		if t == byteRateType {
			return rate, nil
		}
		// Return as integer bytes per second for int targets
		return int(rate), nil
	}
}

// DecodeConfig decodes the provided viper instance into a new Config struct.
//
// Unlike UnmarshalConfig/Refresh, this does NOT update the global atomic cache.
// It is intended for tooling paths that construct a temporary viper instance for
// comparison/printing.
func DecodeConfig(v *viper.Viper) (*Config, error) {
	if v == nil {
		return nil, errors.New("nil viper instance")
	}
	BindAllParameters(v)
	newConfig := new(Config)
	settings := v.AllSettings()
	mergeKnownKeyOverrides(settings, v)
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName:          "mapstructure",
		WeaklyTypedInput: true,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			stringToSliceHookFunc(),
			stringToByteRateHookFunc(),
		),
		MatchName: func(mapKey, fieldName string) bool {
			return strings.EqualFold(mapKey, fieldName)
		},
		Result: newConfig,
	})
	if err != nil {
		return nil, err
	}
	if err := decoder.Decode(settings); err != nil {
		return nil, err
	}
	return newConfig, nil
}

func mergeKnownKeyOverrides(settings map[string]any, v *viper.Viper) {
	if v == nil || settings == nil {
		return
	}

	for _, key := range allParameterNames {
		// Viper's AllSettings() may omit values coming exclusively from bindings
		// (for example, keys bound to Cobra/pflag flags). To keep the decoded
		// snapshot consistent with viper.Get(), explicitly overlay all known keys.
		val := v.Get(key)
		if val == nil {
			continue
		}
		setLowercasePath(settings, strings.Split(key, "."), val)
	}
}

func setLowercasePath(root map[string]any, path []string, val any) {
	if len(path) == 0 {
		return
	}

	m := root
	for i := range len(path) - 1 {
		k := strings.ToLower(path[i])
		nextAny, ok := m[k]
		if ok {
			if nextMap, ok := nextAny.(map[string]any); ok {
				m = nextMap
				continue
			}
		}
		next := make(map[string]any)
		m[k] = next
		m = next
	}

	leaf := strings.ToLower(path[len(path)-1])
	m[leaf] = val
}

// UnmarshalConfig refreshes the global atomic cached configuration from viper's
// *global* instance.
func UnmarshalConfig() (*Config, error) {
	return decodeAndStoreConfig(viper.GetViper())
}

func decodeAndStoreConfig(v *viper.Viper) (*Config, error) {
	configMutex.Lock()
	defer configMutex.Unlock()
	if v == nil {
		return nil, errors.New("nil viper instance")
	}
	newConfig, err := DecodeConfig(v)
	if err != nil {
		return nil, err
	}
	oldConfig := viperConfig.Load()
	viperConfig.Store(newConfig)

	// Invoke callbacks with old and new config
	invokeCallbacks(oldConfig, newConfig)

	return newConfig, nil
}

// Return the unmarshaled viper config struct as a pointer
func GetUnmarshaledConfig() (*Config, error) {
	config := viperConfig.Load()
	if config == nil {
		return nil, errors.New("Config hasn't been unmarshaled yet.")
	}
	return config, nil
}

// Helper function to set a parameter field entry in configWithType
func setField(fieldType reflect.Type, value interface{}) reflect.Value {
	field := reflect.New(fieldType).Elem()
	sliceInterfaceType := reflect.TypeOf([]interface{}(nil))

	// Check if the type of the value is nil
	if reflect.TypeOf(value) == nil {
		// If the value is nil, it is a object-type config without value
		field.FieldByName("Type").SetString("[]object")
	} else {
		if reflect.TypeOf(value) == sliceInterfaceType {
			field.FieldByName("Type").SetString("[]object")
		} else {
			field.FieldByName("Type").SetString(reflect.TypeOf(value).String())
		}
		field.FieldByName("Value").Set(reflect.ValueOf(value))
	}

	return field
}

// Helper function to convert config struct to configWithType struct using reflection
func convertStruct(srcVal, destVal reflect.Value) {
	// If the source or destination is a pointer, get the underlying element
	if srcVal.Kind() == reflect.Ptr {
		srcVal = srcVal.Elem()
	}
	if destVal.Kind() == reflect.Ptr {
		destVal = destVal.Elem()
	}

	for i := 0; i < srcVal.NumField(); i++ {
		srcField := srcVal.Field(i)
		destField := destVal.FieldByName(srcVal.Type().Field(i).Name)

		// Check if the field is a struct and handle recursively
		if srcField.Kind() == reflect.Struct {
			nestedSrc := srcField
			nestedDest := destField

			// Make sure nestedDest is addressable
			if !nestedDest.CanSet() {
				nestedDest = reflect.New(nestedDest.Type()).Elem()
			}

			convertStruct(nestedSrc, nestedDest)
			destField.Set(nestedDest) // Set the converted struct back
		} else {
			// Handle non-struct fields
			if destField.CanSet() {
				destFieldType := destField.Type()
				convertedField := setField(destFieldType, srcField.Interface())
				destField.Set(convertedField)
			}
		}
	}
}

// Convert a config struct to configWithType struct
func ConvertToConfigWithType(rawConfig *Config) *configWithType {
	typedConfig := configWithType{}

	srcVal := reflect.ValueOf(rawConfig).Elem()
	destVal := reflect.ValueOf(&typedConfig).Elem()
	convertStruct(srcVal, destVal)
	return &typedConfig
}

// getOrCreateConfig returns the current config or creates one from viper if it doesn't exist.
// This helper is used by the generated accessor functions to ensure we always have a config.
func getOrCreateConfig() *Config {
	config := viperConfig.Load()
	if config != nil {
		return config
	}

	// Config doesn't exist yet, create one from viper
	configMutex.Lock()
	defer configMutex.Unlock()

	// Double-check after acquiring lock
	config = viperConfig.Load()
	if config != nil {
		return config
	}

	// Create new config from viper.
	//
	// Important: `viper.Unmarshal` does not reliably include values set only via
	// `SetDefault` in all cases; however `AllSettings()` does include merged
	// defaults/config/env. Decode from that to avoid returning an empty config.
	newConfig := new(Config)
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName:          "mapstructure",
		WeaklyTypedInput: true,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			stringToSliceHookFunc(),
			stringToByteRateHookFunc(),
		),
		MatchName: func(mapKey, fieldName string) bool {
			return strings.EqualFold(mapKey, fieldName)
		},
		Result: newConfig,
	})
	if err != nil {
		return new(Config)
	}
	if err := decoder.Decode(viper.GetViper().AllSettings()); err != nil {
		return new(Config)
	}

	viperConfig.Store(newConfig)
	return newConfig
}

// Set sets a parameter value in both viper and the config struct.
// This function is thread-safe and will update the atomic config pointer.
func Set(key string, value interface{}) error {
	return MultiSet(map[string]interface{}{key: value})
}

// MultiSet sets multiple parameter values in both viper and the config struct.
// This function is thread-safe and will update the atomic config pointer.
// It is more efficient than calling Set multiple times as it only updates
// the config object once.
func MultiSet(keyValues map[string]interface{}) error {
	configMutex.Lock()
	defer configMutex.Unlock()

	// Set all values in viper
	for key, value := range keyValues {
		viper.Set(key, value)
	}

	// Create new config from updated viper
	newConfig := new(Config)
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName:          "mapstructure",
		WeaklyTypedInput: true,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			stringToSliceHookFunc(),
			stringToByteRateHookFunc(),
		),
		MatchName: func(mapKey, fieldName string) bool {
			return strings.EqualFold(mapKey, fieldName)
		},
		Result: newConfig,
	})
	if err != nil {
		return err
	}
	if err := decoder.Decode(viper.GetViper().AllSettings()); err != nil {
		return err
	}

	// Update atomic pointer and invoke callbacks
	oldConfig := viperConfig.Load()
	viperConfig.Store(newConfig)
	invokeCallbacks(oldConfig, newConfig)
	return nil
}

// Reset resets the viper configuration and creates a new config struct.
// This function is thread-safe and will update the atomic config pointer.
func Reset() error {
	configMutex.Lock()
	defer configMutex.Unlock()

	// Reset viper
	viper.Reset()

	// Clear the config
	viperConfig.Store(nil)
	return nil
}

// RegisterCallback registers a callback function that will be called when
// configuration is updated. The callback receives the old and new configuration.
// This is useful for modules that need to react to configuration changes at runtime.
// The key parameter is used to identify the callback and prevent duplicate registrations.
// If a callback with the same key is already registered, it will be replaced.
func RegisterCallback(key string, cb ConfigCallback) {
	callbackMux.Lock()
	defer callbackMux.Unlock()
	callbacks[key] = cb
}

// ClearCallbacks clears all registered callbacks.
// This is primarily intended for testing.
func ClearCallbacks() {
	callbackMux.Lock()
	defer callbackMux.Unlock()
	callbacks = make(map[string]ConfigCallback)
}

// invokeCallbacks calls all registered callbacks with the old and new configuration.
// This should be called while holding configMutex.
func invokeCallbacks(oldConfig, newConfig *Config) {
	callbackMux.RLock()
	defer callbackMux.RUnlock()

	for _, cb := range callbacks {
		// Call each callback in a goroutine to avoid blocking config updates
		// if a callback takes time to execute
		go cb(oldConfig, newConfig)
	}
}
