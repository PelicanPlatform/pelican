package broker

import (
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCacheHostnameFromToken(t *testing.T) {
	viper.Reset()

	viper.Set("Federation.RegistryUrl", "https://your-registry.com")

	tok, err := jwt.NewBuilder().
		Issuer(`https://your-registry.com/api/v1.0/registry/caches/https://cache.com`).
		IssuedAt(time.Now()).
		Build()
	require.NoError(t, err)
	tokByte, err := jwt.Sign(tok, jwt.WithInsecureNoSignature())
	require.NoError(t, err)

	hostname, err := getCacheHostnameFromToken(tokByte)
	require.NoError(t, err)
	assert.Equal(t, "https://cache.com", hostname)
}
