package registry

import (
	"testing"

	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
