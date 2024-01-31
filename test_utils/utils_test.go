package test_utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateJWK tests the GenerateJWK function.
func TestGenerateJWK(t *testing.T) {
	jwkKey, jwks, jwksString, err := GenerateJWK()
	require.NoErrorf(t, err, "Failed to generate JWK and JWKS: %v", err)
	assert.NotNil(t, jwkKey)
	assert.NotNil(t, jwks)
	assert.NotEmpty(t, jwksString)
}
