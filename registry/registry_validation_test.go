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
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jellydator/ttlcache/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

func TestValidateCustomFields(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	setMockConfig := func(config []registrationField) {
		registrationFields = config
		// This is just to get around with the testings
		// we only check the len of customRegFieldsConfigs to make sure the custom fields are
		// configured, but the actual registration configuration will be read from registrationFields
		customRegFieldsConfigs = make([]customRegFieldsConfig, len(config))
	}

	t.Cleanup(func() {
		registrationFields = nil
		customRegFieldsConfigs = nil
	})

	t.Run("empty-configuration-and-custom-fields", func(t *testing.T) {
		setMockConfig([]registrationField{})
		customFields := make(map[string]interface{})

		valid, err := validateCustomFields(customFields)
		require.NoError(t, err, "Should not have an error with empty config and custom fields")
		assert.True(t, valid, "Validation should pass with empty config and custom fields")
	})
	t.Run("configuration-not-set-non-empty-custom-fields", func(t *testing.T) {
		setMockConfig(nil)
		customFields := map[string]interface{}{"field1": "value1"}

		_, err := validateCustomFields(customFields)
		require.Error(t, err, "Expected an error when config is not set, but custom fields are non-empty")
		assert.Equal(t, "Bad configuration, Registry.CustomRegistrationFields is not set while validate against custom fields", err.Error())
	})
	t.Run("required-field-missing-in-custom-fields", func(t *testing.T) {
		setMockConfig([]registrationField{
			{Name: "custom_fields.required_field", DisplayedName: "Required Field", Type: "string", Required: true},
		})
		customFields := map[string]interface{}{"other_field": "value"}

		valid, err := validateCustomFields(customFields)
		require.Error(t, err, "Expected an error when a required field is missing")
		assert.Equal(t, `"Required Field" is required`, err.Error())
		assert.False(t, valid, "Validation should fail when a required field is missing")
	})
	t.Run("type-mismatch-in-custom-fields", func(t *testing.T) {
		setMockConfig([]registrationField{
			{Name: "custom_fields.string_field", Type: "string", DisplayedName: "String Field"},
		})
		customFields := map[string]interface{}{"string_field": 123} // Incorrect type

		valid, err := validateCustomFields(customFields)
		require.Error(t, err, "Expected an error due to type mismatch")
		assert.Equal(t, `"String Field" is expected to be a string, but got 123`, err.Error())
		assert.False(t, valid, "Validation should fail due to type mismatch")
	})
	t.Run("invalid-datetime-field-value", func(t *testing.T) {
		setMockConfig([]registrationField{
			{Name: "custom_fields.datetime_field", Type: "datetime", DisplayedName: "Datetime Field"},
		})
		customFields := map[string]interface{}{"datetime_field": "not-a-timestamp"}

		valid, err := validateCustomFields(customFields)
		require.Error(t, err, "Expected an error due to invalid datetime value")
		assert.Equal(t, `"Datetime Field" is expected to be a Unix timestamp, but got not-a-timestamp`, err.Error())
		assert.False(t, valid, "Validation should fail due to invalid datetime value")
	})
	t.Run("enum-field-with-invalid-option", func(t *testing.T) {
		setMockConfig([]registrationField{
			{Name: "custom_fields.enum_field", Type: "enum", DisplayedName: "Enum Field", Options: []registrationFieldOption{{ID: "option1"}, {ID: "option2"}}},
		})
		customFields := map[string]interface{}{"enum_field": "invalidOption"}

		valid, err := validateCustomFields(customFields)
		require.Error(t, err, "Expected an error due to invalid enum value")
		assert.Contains(t, err.Error(), `"Enum Field" is an enumeration type, but the value (ID) is not in the options.`)
		assert.False(t, valid, "Validation should fail due to invalid enum value")
	})
	t.Run("enum-field-with-empty-options", func(t *testing.T) {
		setMockConfig([]registrationField{
			{Name: "custom_fields.enum_field", Type: "enum", DisplayedName: "Enum Field"},
		})
		customFields := map[string]interface{}{"enum_field": "random_option"}

		valid, err := validateCustomFields(customFields)
		require.Error(t, err, "Expected an error due to invalid enum value")
		assert.Contains(t, err.Error(), `Bad configuration, the custom field "Enum Field" has empty options`)
		assert.False(t, valid, "Validation should fail due to invalid enum value")
	})
	t.Run("enum-field-with-optionsUrl", func(t *testing.T) {
		optionsCache.Set(
			"https://mock.com/options",
			[]registrationFieldOption{{Name: "Option 1", ID: "option1"}},
			ttlcache.DefaultTTL,
		)
		setMockConfig([]registrationField{
			{Name: "custom_fields.enum_field", Type: "enum", DisplayedName: "Enum Field", OptionsUrl: "https://mock.com/options"},
		})
		customFields := map[string]interface{}{"enum_field": "option1"}

		valid, err := validateCustomFields(customFields)
		require.NoError(t, err, "Expected an error due to invalid enum value")
		assert.True(t, valid, "Validation should fail due to invalid enum value")
	})
	t.Run("extra-fields-in-custom-fields", func(t *testing.T) {
		setMockConfig([]registrationField{
			{Name: "custom_fields.field1", Type: "string"},
		})
		customFields := map[string]interface{}{"field1": "value1", "extraField": "extraValue"}

		valid, err := validateCustomFields(customFields)
		require.Error(t, err, "Expected an error due to extra fields when exactMatch is true")
		assert.Equal(t, `"extraField" is not a valid custom field`, err.Error())
		assert.False(t, valid, "Validation should fail with extra fields when exactMatch is true")
	})
	t.Run("all-valid-fields", func(t *testing.T) {
		setMockConfig([]registrationField{
			{Name: "custom_fields.field1", Type: "string"},
			{Name: "custom_fields.field2", Type: "int"},
		})
		customFields := map[string]interface{}{"field1": "value1", "field2": 10}

		valid, err := validateCustomFields(customFields)
		require.NoError(t, err, "No error expected with all valid fields and exactMatch true")
		assert.True(t, valid, "Validation should pass with all valid fields and exactMatch true")
	})
	t.Run("field-present-in-custom-fields-but-not-required-in-config", func(t *testing.T) {
		setMockConfig([]registrationField{
			{Name: "custom_fields.required_field", Type: "string", Required: true},
			{Name: "custom_fields.optional_field", Type: "int", Required: false},
		})
		customFields := map[string]interface{}{"required_field": "value", "optional_field": 5}

		valid, err := validateCustomFields(customFields)
		require.NoError(t, err, "No error expected with optional field present")
		assert.True(t, valid, "Validation should pass with optional field present")
	})
	t.Run("invalid-field-type-in-configuration", func(t *testing.T) {
		setMockConfig([]registrationField{
			{Name: "custom_fields.unsupported_field", DisplayedName: "Unsupported Field", Type: "unsupportedType"},
		})
		customFields := map[string]interface{}{"unsupported_field": "value"}

		valid, err := validateCustomFields(customFields)
		require.Error(t, err, "Expected an error due to unsupported field type in config")
		assert.Equal(t, `field "Unsupported Field" has unsupported type unsupportedType`, err.Error())
		assert.False(t, valid, "Validation should fail due to unsupported field type in config")
	})
	t.Run("null-or-invalid-custom-fields-map-without-required-fields", func(t *testing.T) {
		setMockConfig([]registrationField{
			{Name: "custom_fields.field1", Type: "string"},
		})
		var customFields map[string]interface{} // Invalid (nil) map

		valid, err := validateCustomFields(customFields)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("null-or-invalid-custom-fields-map-with-required-fields", func(t *testing.T) {
		setMockConfig([]registrationField{
			{Name: "custom_fields.field1", Type: "string", DisplayedName: "Field 1", Required: true},
		})
		var customFields map[string]interface{} // Invalid (nil) map

		valid, err := validateCustomFields(customFields)
		require.Error(t, err)
		assert.Equal(t, `"Field 1" is required`, err.Error())
		assert.False(t, valid)
	})
}

func TestValidateKeyChaining(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	setupMockRegistryDB(t)
	defer func() {
		resetMockRegistryDB(t)
		teardownMockRegistryDB(t)
		server_utils.ResetTestState()
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

	err = insertMockDBData([]server_structs.Registration{
		mockNamespace("/foo", jwksStrFoo, "", server_structs.AdminMetadata{}),
		mockNamespace("/bar", jwksStrBar, "", server_structs.AdminMetadata{}),
		mockNamespace("/cache/randomCache", jwksStrCache, "", server_structs.AdminMetadata{}),
	})

	require.NoError(t, err)

	t.Run("off-param-no-check", func(t *testing.T) {
		require.NoError(t, param.Registry_RequireKeyChaining.Set(false))
		superspaces, subspaces, _, _, err := namespaceSupSubChecks("/foo/barz")
		assert.NoError(t, err)
		assert.Len(t, superspaces, 1)
		assert.Empty(t, subspaces)

		_, _, validErr, serverErr := validateKeyChaining("/foo/barz", jwkFoo)
		assert.NoError(t, serverErr)
		assert.NoError(t, validErr)
	})

	t.Run("on-param-does-check", func(t *testing.T) {
		require.NoError(t, param.Registry_RequireKeyChaining.Set(true))
		_, _, validErr, serverErr := validateKeyChaining("/foo/barz", jwkFoo)
		// Same public key as /foo shouldn't give error
		assert.NoError(t, serverErr)
		assert.NoError(t, validErr)

		_, _, validErr, serverErr = validateKeyChaining("/foo/barz", jwkMockNew)
		// Same public key as /foo shouldn't give error
		assert.NoError(t, serverErr)
		assert.Error(t, validErr)
		assert.Contains(t, validErr.Error(), "Cannot register a namespace that is suffixed or prefixed by an already-registered namespace unless the incoming public key matches a registered key")
	})

	t.Run("on-param-ignore-cache", func(t *testing.T) {
		require.NoError(t, param.Registry_RequireKeyChaining.Set(true))
		superspaces, subspaces, _, _, err := namespaceSupSubChecks("/cache/newCache")
		assert.NoError(t, err)
		assert.Empty(t, superspaces)
		assert.Empty(t, subspaces)

		_, _, validErr, serverErr := validateKeyChaining("/cache/newCache", jwkCache)
		// Same public key as /cache/randomCache shouldn't give error
		assert.NoError(t, serverErr)
		assert.NoError(t, validErr)

		_, _, validErr, serverErr = validateKeyChaining("/cache/newKey", jwkMockNew)
		// Different public key as /cache/randomCache shouldn't give error
		assert.NoError(t, serverErr)
		assert.NoError(t, validErr)
	})

	t.Run("super-sub-space-edge-case-check", func(t *testing.T) {
		// A namespace's super/sub spaces should not contain itself
		superspaces, subspaces, _, _, err := namespaceSupSubChecks("/foo")
		assert.NoError(t, err)
		assert.Empty(t, superspaces)
		assert.Empty(t, subspaces)

		// A complicated namespace
		superspaces, subspaces, _, _, err = namespaceSupSubChecks("/foo/bar/baz")
		assert.NoError(t, err)
		assert.Len(t, superspaces, 1)
		assert.Contains(t, superspaces, "/foo")
		assert.Empty(t, subspaces)
	})
}

func TestValidatePrefix(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	t.Run("root-origin-prefix-returns-err", func(t *testing.T) {
		_, err := validatePrefix("/origins/")
		require.Error(t, err)
		assert.Equal(t, "Origin prefix is missing hostname", err.Error())
	})

	t.Run("root-cache-prefix-returns-err", func(t *testing.T) {
		_, err := validatePrefix("/caches/")
		require.Error(t, err)
		assert.Equal(t, "Cache prefix is missing sitename", err.Error())
	})

	t.Run("dup-origin-prefix-returns-err", func(t *testing.T) {
		_, err := validatePrefix("/origins/origins/foo")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Duplicated origin prefix")
	})

	t.Run("dup-cache-prefix-returns-err", func(t *testing.T) {
		_, err := validatePrefix("/caches/caches/bar")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Duplicated cache prefix")
	})

	t.Run("correct-origin-prefix", func(t *testing.T) {
		got, err := validatePrefix("/origins/foo")
		require.NoError(t, err)
		assert.Equal(t, "/origins/foo", got)

		got, err = validatePrefix("/origins/example.org")
		require.NoError(t, err)
		assert.Equal(t, "/origins/example.org", got)

		got, err = validatePrefix("/origins/192.168.5.21")
		require.NoError(t, err)
		assert.Equal(t, "/origins/192.168.5.21", got)
	})

	t.Run("correct-cache-prefix", func(t *testing.T) {
		got, err := validatePrefix("/caches/foo")
		require.NoError(t, err)
		assert.Equal(t, "/caches/foo", got)

		got, err = validatePrefix("/caches/example.org")
		require.NoError(t, err)
		assert.Equal(t, "/caches/example.org", got)

		got, err = validatePrefix("/caches/192.168.5.21")
		require.NoError(t, err)
		assert.Equal(t, "/caches/192.168.5.21", got)
	})
}

func TestValidateAuthState(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	const exampleIssuer = "https://issuer.example.org"
	readOnly := server_structs.Capabilities{Reads: true}
	public := server_structs.Capabilities{PublicReads: true}
	oauth := func(issuer string) server_structs.TokenGenResponse {
		return server_structs.TokenGenResponse{Strategy: server_structs.OAuthStrategy, MaxScopeDepth: 3, CredentialIssuer: issuer}
	}
	issuer := func(url string, basePaths []string, restricted []string) server_structs.TokenIssuerResponse {
		return server_structs.TokenIssuerResponse{IssuerUrl: url, BasePaths: basePaths, RestrictedPaths: restricted}
	}
	// manyRestrictedPaths builds a read-only state whose issuer lists n
	// restricted paths, to drive the serialized size past or under the limit.
	manyRestrictedPaths := func(n int) *server_structs.NamespaceAuthState {
		paths := make([]string, n)
		for i := range paths {
			paths[i] = fmt.Sprintf("/foo/bar/restricted-path-number-%04d", i)
		}
		return &server_structs.NamespaceAuthState{
			Capabilities: readOnly,
			TokenIssuer:  []server_structs.TokenIssuerResponse{issuer(exampleIssuer, []string{"/foo"}, paths)},
		}
	}

	tests := []struct {
		name    string
		prefix  string
		state   *server_structs.NamespaceAuthState
		wantErr string                             // substring of the error; empty means the state is valid
		want    *server_structs.NamespaceAuthState // normalized state, when it differs from the input
	}{
		{
			name:   "nil-state-is-valid",
			prefix: "/foo",
		},
		{
			name:   "nil-state-is-valid-on-an-origin-registration",
			prefix: "/origins/example.org",
		},
		{
			name:    "rejects-an-origin-registration",
			prefix:  "/origins/example.org",
			state:   &server_structs.NamespaceAuthState{Capabilities: public},
			wantErr: "not on an origin or cache registration",
		},
		{
			name:    "rejects-a-cache-registration",
			prefix:  "/caches/example.org",
			state:   &server_structs.NamespaceAuthState{Capabilities: public},
			wantErr: "not on an origin or cache registration",
		},
		{
			name:   "public-read-implies-read",
			prefix: "/foo",
			state:  &server_structs.NamespaceAuthState{Capabilities: public},
			want:   &server_structs.NamespaceAuthState{Capabilities: server_structs.Capabilities{PublicReads: true, Reads: true}},
		},
		{
			// An origin that allows public reads and authenticated writes
			// advertises exactly this; caches ignore the issuers of a public
			// namespace, so the state is accepted.
			name:   "public-read-with-token-issuers-is-accepted",
			prefix: "/foo",
			state: &server_structs.NamespaceAuthState{
				Capabilities:    server_structs.Capabilities{PublicReads: true, Writes: true},
				TokenGeneration: []server_structs.TokenGenResponse{oauth(exampleIssuer)},
				TokenIssuer:     []server_structs.TokenIssuerResponse{issuer(exampleIssuer, []string{"/foo"}, nil)},
			},
			want: &server_structs.NamespaceAuthState{
				Capabilities:    server_structs.Capabilities{PublicReads: true, Reads: true, Writes: true},
				TokenGeneration: []server_structs.TokenGenResponse{oauth(exampleIssuer)},
				TokenIssuer:     []server_structs.TokenIssuerResponse{issuer(exampleIssuer, []string{"/foo"}, nil)},
			},
		},
		{
			name:   "read-with-issuers-is-accepted-unchanged",
			prefix: "/foo",
			state: &server_structs.NamespaceAuthState{
				Capabilities:    readOnly,
				TokenGeneration: []server_structs.TokenGenResponse{oauth(exampleIssuer)},
				TokenIssuer:     []server_structs.TokenIssuerResponse{issuer(exampleIssuer, []string{"/foo"}, []string{"/foo/bar"})},
			},
		},
		{
			name:   "zero-token-generation-entry-is-dropped",
			prefix: "/foo",
			state: &server_structs.NamespaceAuthState{
				Capabilities:    public,
				TokenGeneration: []server_structs.TokenGenResponse{{}},
			},
			want: &server_structs.NamespaceAuthState{
				Capabilities:    server_structs.Capabilities{PublicReads: true, Reads: true},
				TokenGeneration: []server_structs.TokenGenResponse{},
			},
		},
		{
			name:   "zero-token-generation-entry-is-dropped-beside-a-real-one",
			prefix: "/foo",
			state: &server_structs.NamespaceAuthState{
				Capabilities:    readOnly,
				TokenGeneration: []server_structs.TokenGenResponse{{}, oauth(exampleIssuer)},
			},
			want: &server_structs.NamespaceAuthState{
				Capabilities:    readOnly,
				TokenGeneration: []server_structs.TokenGenResponse{oauth(exampleIssuer)},
			},
		},
		{
			name:   "unknown-token-generation-strategy",
			prefix: "/foo",
			state: &server_structs.NamespaceAuthState{
				Capabilities:    readOnly,
				TokenGeneration: []server_structs.TokenGenResponse{{Strategy: "oauth2", CredentialIssuer: exampleIssuer}},
			},
			wantErr: `tokenGeneration[0]: unsupported strategy "oauth2"`,
		},
		{
			name:   "token-generation-entry-with-an-issuer-but-no-strategy",
			prefix: "/foo",
			state: &server_structs.NamespaceAuthState{
				Capabilities:    readOnly,
				TokenGeneration: []server_structs.TokenGenResponse{{CredentialIssuer: exampleIssuer}},
			},
			wantErr: `tokenGeneration[0]: unsupported strategy ""`,
		},
		{
			name:   "vault-strategy-is-rejected",
			prefix: "/foo",
			state: &server_structs.NamespaceAuthState{
				Capabilities:    readOnly,
				TokenGeneration: []server_structs.TokenGenResponse{{Strategy: server_structs.VaultStrategy, VaultServer: "vault.example.org", CredentialIssuer: exampleIssuer}},
			},
			wantErr: `tokenGeneration[0]: unsupported strategy "Vault"`,
		},
		{
			name:   "vault-server-is-rejected-with-oauth2",
			prefix: "/foo",
			state: &server_structs.NamespaceAuthState{
				Capabilities:    readOnly,
				TokenGeneration: []server_structs.TokenGenResponse{{Strategy: server_structs.OAuthStrategy, VaultServer: "vault.example.org", CredentialIssuer: exampleIssuer}},
			},
			wantErr: `tokenGeneration[0]: vaultServer must be empty`,
		},
		{
			name:   "token-generation-issuer-must-be-https",
			prefix: "/foo",
			state: &server_structs.NamespaceAuthState{
				Capabilities:    readOnly,
				TokenGeneration: []server_structs.TokenGenResponse{oauth("http://issuer.example.org")},
			},
			wantErr: `tokenGeneration[0]: issuer "http://issuer.example.org" must be an absolute https url`,
		},
		{
			name:   "token-generation-issuer-must-be-absolute",
			prefix: "/foo",
			state: &server_structs.NamespaceAuthState{
				Capabilities:    readOnly,
				TokenGeneration: []server_structs.TokenGenResponse{oauth("issuer.example.org")},
			},
			wantErr: `must be an absolute https url`,
		},
		{
			name:   "token-issuer-must-be-https",
			prefix: "/foo",
			state: &server_structs.NamespaceAuthState{
				Capabilities: readOnly,
				TokenIssuer:  []server_structs.TokenIssuerResponse{issuer("http://issuer.example.org", []string{"/foo"}, nil)},
			},
			wantErr: `tokenIssuer[0]: issuer "http://issuer.example.org" must be an absolute https url`,
		},
		{
			name:   "token-issuer-must-not-be-empty",
			prefix: "/foo",
			state: &server_structs.NamespaceAuthState{
				Capabilities: readOnly,
				TokenIssuer:  []server_structs.TokenIssuerResponse{issuer("", []string{"/foo"}, nil)},
			},
			wantErr: "tokenIssuer[0]: issuer is empty",
		},
		{
			name:   "token-issuer-needs-a-base-path",
			prefix: "/foo",
			state: &server_structs.NamespaceAuthState{
				Capabilities: readOnly,
				TokenIssuer:  []server_structs.TokenIssuerResponse{issuer(exampleIssuer, nil, nil)},
			},
			wantErr: "needs at least one base path",
		},
		{
			name:   "base-path-must-be-absolute",
			prefix: "/foo",
			state: &server_structs.NamespaceAuthState{
				Capabilities: readOnly,
				TokenIssuer:  []server_structs.TokenIssuerResponse{issuer(exampleIssuer, []string{"foo"}, nil)},
			},
			wantErr: "tokenIssuer[0].basePaths[0]: Path prefix must be absolute",
		},
		{
			name:   "base-path-outside-the-prefix",
			prefix: "/foo",
			state: &server_structs.NamespaceAuthState{
				Capabilities: readOnly,
				TokenIssuer:  []server_structs.TokenIssuerResponse{issuer(exampleIssuer, []string{"/foo", "/other"}, nil)},
			},
			wantErr: `tokenIssuer[0].basePaths[1]: base path "/other" is outside the registered prefix /foo`,
		},
		{
			name:   "base-path-sharing-a-string-prefix-is-still-outside",
			prefix: "/foo",
			state: &server_structs.NamespaceAuthState{
				Capabilities: readOnly,
				TokenIssuer:  []server_structs.TokenIssuerResponse{issuer(exampleIssuer, []string{"/foox"}, nil)},
			},
			wantErr: `base path "/foox" is outside the registered prefix /foo`,
		},
		{
			name:   "base-path-above-the-prefix-is-outside",
			prefix: "/foo/bar",
			state: &server_structs.NamespaceAuthState{
				Capabilities: readOnly,
				TokenIssuer:  []server_structs.TokenIssuerResponse{issuer(exampleIssuer, []string{"/foo"}, nil)},
			},
			wantErr: `base path "/foo" is outside the registered prefix /foo/bar`,
		},
		{
			name:   "base-path-with-a-dot-dot-component-is-rejected",
			prefix: "/foo",
			state: &server_structs.NamespaceAuthState{
				Capabilities: readOnly,
				TokenIssuer:  []server_structs.TokenIssuerResponse{issuer(exampleIssuer, []string{"/foo/../etc"}, nil)},
			},
			wantErr: "tokenIssuer[0].basePaths[0]: Path component cannot be '..'",
		},
		{
			name:   "base-path-with-a-dot-component-is-rejected",
			prefix: "/foo",
			state: &server_structs.NamespaceAuthState{
				Capabilities: readOnly,
				TokenIssuer:  []server_structs.TokenIssuerResponse{issuer(exampleIssuer, []string{"/foo/./bar"}, nil)},
			},
			wantErr: "tokenIssuer[0].basePaths[0]: Path component cannot be '.'",
		},
		{
			name:   "empty-base-path-is-rejected",
			prefix: "/foo",
			state: &server_structs.NamespaceAuthState{
				Capabilities: readOnly,
				TokenIssuer:  []server_structs.TokenIssuerResponse{issuer(exampleIssuer, []string{""}, nil)},
			},
			wantErr: "tokenIssuer[0].basePaths[0]: Path prefix may not be empty",
		},
		{
			name:   "base-paths-are-normalized-like-a-prefix",
			prefix: "/foo",
			state: &server_structs.NamespaceAuthState{
				Capabilities: readOnly,
				TokenIssuer:  []server_structs.TokenIssuerResponse{issuer(exampleIssuer, []string{"/foo/bar/", "/foo//baz/x"}, nil)},
			},
			want: &server_structs.NamespaceAuthState{
				Capabilities: readOnly,
				TokenIssuer:  []server_structs.TokenIssuerResponse{issuer(exampleIssuer, []string{"/foo/bar", "/foo/baz/x"}, nil)},
			},
		},
		{
			name:   "restricted-path-must-be-absolute",
			prefix: "/foo",
			state: &server_structs.NamespaceAuthState{
				Capabilities: readOnly,
				TokenIssuer:  []server_structs.TokenIssuerResponse{issuer(exampleIssuer, []string{"/foo"}, []string{"foo/bar"})},
			},
			wantErr: "tokenIssuer[0].restrictedPaths[0]: Path prefix must be absolute",
		},
		{
			name:   "restricted-path-outside-every-base-path",
			prefix: "/foo",
			state: &server_structs.NamespaceAuthState{
				Capabilities: readOnly,
				TokenIssuer:  []server_structs.TokenIssuerResponse{issuer(exampleIssuer, []string{"/foo/bar"}, []string{"/foo/baz"})},
			},
			wantErr: `tokenIssuer[0].restrictedPaths[0]: restricted path "/foo/baz" is not under any base path of issuer https://issuer.example.org`,
		},
		{
			name:   "restricted-path-equal-to-a-base-path-is-accepted",
			prefix: "/foo",
			state: &server_structs.NamespaceAuthState{
				Capabilities: readOnly,
				TokenIssuer:  []server_structs.TokenIssuerResponse{issuer(exampleIssuer, []string{"/foo/bar"}, []string{"/foo/bar"})},
			},
		},
		{
			name:   "restricted-paths-are-normalized-like-a-prefix",
			prefix: "/foo",
			state: &server_structs.NamespaceAuthState{
				Capabilities: readOnly,
				TokenIssuer:  []server_structs.TokenIssuerResponse{issuer(exampleIssuer, []string{"/foo"}, []string{"/foo/bar/"})},
			},
			want: &server_structs.NamespaceAuthState{
				Capabilities: readOnly,
				TokenIssuer:  []server_structs.TokenIssuerResponse{issuer(exampleIssuer, []string{"/foo"}, []string{"/foo/bar"})},
			},
		},
		{
			name:   "state-under-the-size-limit-is-accepted",
			prefix: "/foo",
			state:  manyRestrictedPaths(150),
		},
		{
			name:    "state-over-the-size-limit-is-rejected",
			prefix:  "/foo",
			state:   manyRestrictedPaths(250),
			wantErr: "the limit is 8192",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var before *server_structs.NamespaceAuthState
			if tc.state != nil {
				raw, err := json.Marshal(tc.state)
				require.NoError(t, err)
				before = &server_structs.NamespaceAuthState{}
				require.NoError(t, json.Unmarshal(raw, before))
			}

			err := validateAuthState(tc.prefix, tc.state)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)

			if tc.state == nil {
				return
			}
			serialized, err := json.Marshal(tc.state)
			require.NoError(t, err)
			assert.LessOrEqual(t, len(serialized), maxAuthStateBytes)
			if tc.want != nil {
				assert.Equal(t, tc.want, tc.state)
			} else {
				assert.Equal(t, before, tc.state, "a valid state that needs no normalization must come back unchanged")
			}
		})
	}

	t.Run("size-limit-cases-bracket-the-limit", func(t *testing.T) {
		under, err := json.Marshal(manyRestrictedPaths(150))
		require.NoError(t, err)
		over, err := json.Marshal(manyRestrictedPaths(250))
		require.NoError(t, err)
		assert.LessOrEqual(t, len(under), maxAuthStateBytes)
		assert.Greater(t, len(over), maxAuthStateBytes)
	})
}
