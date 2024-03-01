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

package registry

import (
	"testing"

	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateCustomFields(t *testing.T) {

	oldConfig := customRegFieldsConfigs

	setMockConfig := func(config []customRegFieldsConfig) {
		customRegFieldsConfigs = config
	}

	t.Cleanup(func() {
		customRegFieldsConfigs = oldConfig
	})

	t.Run("empty-configuration-and-custom-fields", func(t *testing.T) {
		setMockConfig([]customRegFieldsConfig{})
		customFields := make(map[string]interface{})

		valid, err := validateCustomFields(customFields, false)
		require.NoError(t, err, "Should not have an error with empty config and custom fields")
		assert.True(t, valid, "Validation should pass with empty config and custom fields")
	})
	t.Run("configuration-not-set-non-empty-custom-fields", func(t *testing.T) {
		setMockConfig(nil)
		customFields := map[string]interface{}{"field1": "value1"}

		_, err := validateCustomFields(customFields, false)
		require.Error(t, err, "Expected an error when config is not set, but custom fields are non-empty")
	})
	t.Run("required-field-missing-in-custom-fields", func(t *testing.T) {
		setMockConfig([]customRegFieldsConfig{
			{Name: "requiredField", Type: "string", Required: true},
		})
		customFields := map[string]interface{}{"otherField": "value"}

		valid, err := validateCustomFields(customFields, false)
		require.Error(t, err, "Expected an error when a required field is missing")
		assert.False(t, valid, "Validation should fail when a required field is missing")
	})
	t.Run("type-mismatch-in-custom-fields", func(t *testing.T) {
		setMockConfig([]customRegFieldsConfig{
			{Name: "stringField", Type: "string"},
		})
		customFields := map[string]interface{}{"stringField": 123} // Incorrect type

		valid, err := validateCustomFields(customFields, false)
		require.Error(t, err, "Expected an error due to type mismatch")
		assert.False(t, valid, "Validation should fail due to type mismatch")
	})
	t.Run("invalid-datetime-field-value", func(t *testing.T) {
		setMockConfig([]customRegFieldsConfig{
			{Name: "datetimeField", Type: "datetime"},
		})
		customFields := map[string]interface{}{"datetimeField": "not-a-timestamp"}

		valid, err := validateCustomFields(customFields, false)
		require.Error(t, err, "Expected an error due to invalid datetime value")
		assert.False(t, valid, "Validation should fail due to invalid datetime value")
	})
	t.Run("enum-field-with-invalid-option", func(t *testing.T) {
		setMockConfig([]customRegFieldsConfig{
			{Name: "enumField", Type: "enum", Options: []registrationFieldOption{{ID: "option1"}, {ID: "option2"}}},
		})
		customFields := map[string]interface{}{"enumField": "invalidOption"}

		valid, err := validateCustomFields(customFields, false)
		require.Error(t, err, "Expected an error due to invalid enum value")
		assert.False(t, valid, "Validation should fail due to invalid enum value")
	})
	t.Run("additional-fields-in-custom-fields-with-exactmatch-false", func(t *testing.T) {
		setMockConfig([]customRegFieldsConfig{
			{Name: "field1", Type: "string"},
		})
		customFields := map[string]interface{}{"field1": "value1", "extraField": "extraValue"}

		valid, err := validateCustomFields(customFields, false)
		require.NoError(t, err, "No error expected with extra fields when exactMatch is false")
		assert.True(t, valid, "Validation should pass with extra fields when exactMatch is false")

	})
	t.Run("additional-fields-in-custom-fields-with-exactmatch-true", func(t *testing.T) {
		setMockConfig([]customRegFieldsConfig{
			{Name: "field1", Type: "string"},
		})
		customFields := map[string]interface{}{"field1": "value1", "extraField": "extraValue"}

		valid, err := validateCustomFields(customFields, true)
		require.Error(t, err, "Expected an error due to extra fields when exactMatch is true")
		assert.False(t, valid, "Validation should fail with extra fields when exactMatch is true")
	})
	t.Run("all-valid-fields-with-exactmatch-true", func(t *testing.T) {
		setMockConfig([]customRegFieldsConfig{
			{Name: "field1", Type: "string"},
			{Name: "field2", Type: "int"},
		})
		customFields := map[string]interface{}{"field1": "value1", "field2": 10}

		valid, err := validateCustomFields(customFields, true)
		require.NoError(t, err, "No error expected with all valid fields and exactMatch true")
		assert.True(t, valid, "Validation should pass with all valid fields and exactMatch true")
	})
	t.Run("field-present-in-custom-fields-but-not-required-in-config", func(t *testing.T) {
		setMockConfig([]customRegFieldsConfig{
			{Name: "requiredField", Type: "string", Required: true},
			{Name: "optionalField", Type: "int", Required: false},
		})
		customFields := map[string]interface{}{"requiredField": "value", "optionalField": 5}

		valid, err := validateCustomFields(customFields, false)
		require.NoError(t, err, "No error expected with optional field present")
		assert.True(t, valid, "Validation should pass with optional field present")
	})
	t.Run("invalid-field-type-in-configuration", func(t *testing.T) {
		setMockConfig([]customRegFieldsConfig{
			{Name: "unsupportedField", Type: "unsupportedType"},
		})
		customFields := map[string]interface{}{"unsupportedField": "value"}

		valid, err := validateCustomFields(customFields, false)
		require.Error(t, err, "Expected an error due to unsupported field type in config")
		assert.False(t, valid, "Validation should fail due to unsupported field type in config")
	})
	t.Run("null-or-invalid-custom-fields-map", func(t *testing.T) {
		setMockConfig([]customRegFieldsConfig{
			{Name: "field1", Type: "string"},
		})
		var customFields map[string]interface{} // Invalid (nil) map

		valid, err := validateCustomFields(customFields, false)
		require.Error(t, err, "Expected an error with invalid (nil) custom fields map")
		assert.False(t, valid, "Validation should fail with invalid (nil) custom fields map")
	})
}

func TestValidateKeyChaining(t *testing.T) {
	viper.Reset()
	setupMockRegistryDB(t)
	defer func() {
		resetNamespaceDB(t)
		teardownMockNamespaceDB(t)
		viper.Reset()
	}()

	_, jwksFoo, jwksStrFoo, err := test_utils.GenerateJWK()
	require.NoError(t, err)

	jwkFoo, ok := jwksFoo.Key(0)
	require.True(t, ok)
	require.NotNil(t, jwkFoo)

	_, jwksBar, jwksStrBar, err := test_utils.GenerateJWK()
	require.NoError(t, err)

	jwkBar, ok := jwksBar.Key(0)
	require.True(t, ok)
	require.NotNil(t, jwkBar)

	_, jwksCache, jwksStrCache, err := test_utils.GenerateJWK()
	require.NoError(t, err)

	jwkCache, ok := jwksCache.Key(0)
	require.True(t, ok)
	require.NotNil(t, jwkCache)

	_, jwksMockNew, _, err := test_utils.GenerateJWK()
	require.NoError(t, err)

	jwkMockNew, ok := jwksMockNew.Key(0)
	require.True(t, ok)
	require.NotNil(t, jwkMockNew)

	err = insertMockDBData([]Namespace{
		mockNamespace("/foo", jwksStrFoo, "", AdminMetadata{}),
		mockNamespace("/bar", jwksStrBar, "", AdminMetadata{}),
		mockNamespace("/cache/randomCache", jwksStrCache, "", AdminMetadata{}),
	})

	require.NoError(t, err)

	t.Run("off-param-no-check", func(t *testing.T) {
		viper.Set("Registry.RequireKeyChaining", false)
		validErr, serverErr := validateKeyChaining("/foo/barz", jwkFoo)
		assert.NoError(t, serverErr)
		assert.NoError(t, validErr)
	})

	t.Run("on-param-does-check", func(t *testing.T) {
		viper.Set("Registry.RequireKeyChaining", true)
		validErr, serverErr := validateKeyChaining("/foo/barz", jwkFoo)
		// Same public key as /foo shouldn't give error
		assert.NoError(t, serverErr)
		assert.NoError(t, validErr)

		validErr, serverErr = validateKeyChaining("/foo/barz", jwkMockNew)
		// Same public key as /foo shouldn't give error
		assert.NoError(t, serverErr)
		assert.Error(t, validErr)
		assert.Contains(t, validErr.Error(), "Cannot register a namespace that is suffixed or prefixed by an already-registered namespace unless the incoming public key matches a registered key")
	})

	t.Run("on-param-ignore-cache", func(t *testing.T) {
		viper.Set("Registry.RequireKeyChaining", true)
		validErr, serverErr := validateKeyChaining("/cache/newCache", jwkCache)
		// Same public key as /cache/randomCache shouldn't give error
		assert.NoError(t, serverErr)
		assert.NoError(t, validErr)

		validErr, serverErr = validateKeyChaining("/cache/newKey", jwkMockNew)
		// Different public key as /cache/randomCache shouldn't give error
		assert.NoError(t, serverErr)
		assert.NoError(t, validErr)
	})
}
