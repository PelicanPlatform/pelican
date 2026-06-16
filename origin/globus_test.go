package origin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/server_utils"
)

func TestGetGlobusBackendConfigSingleCollectionMultiExport(t *testing.T) {
	globusExports = map[string]*globusExport{
		"abc123": {
			HttpsServer:       "https://globus.example",
			TokenFile:         "/tokens/abc123.tok",
			TransferTokenFile: "/tokens/abc123.transfer.tok",
		},
	}

	config, err := GetGlobusBackendConfig([]server_utils.OriginExport{
		{FederationPrefix: "/first/ns", StoragePrefix: "/foo", GlobusCollectionID: "abc123"},
		{FederationPrefix: "/second/ns", StoragePrefix: "/bar", GlobusCollectionID: "abc123"},
	})
	require.NoError(t, err)
	require.NotNil(t, config)
	assert.Equal(t, "abc123", config.CollectionID)
	assert.Equal(t, "https://globus.example", config.HttpsServer)
	assert.Equal(t, "/tokens/abc123.tok", config.TokenFile)
	assert.Equal(t, "/tokens/abc123.transfer.tok", config.TransferTokenFile)
	assert.Equal(t, []GlobusExportPathConfig{
		{FederationPrefix: "/first/ns", StoragePrefix: "/foo"},
		{FederationPrefix: "/second/ns", StoragePrefix: "/bar"},
	}, config.Exports)
}

func TestGetGlobusBackendConfigRejectsMultipleCollections(t *testing.T) {
	globusExports = map[string]*globusExport{
		"abc123": {HttpsServer: "https://globus.example"},
		"def456": {HttpsServer: "https://globus.example"},
	}

	config, err := GetGlobusBackendConfig([]server_utils.OriginExport{
		{FederationPrefix: "/first/ns", StoragePrefix: "/foo", GlobusCollectionID: "abc123"},
		{FederationPrefix: "/second/ns", StoragePrefix: "/bar", GlobusCollectionID: "def456"},
	})
	require.Error(t, err)
	assert.Nil(t, config)
	assert.Contains(t, err.Error(), "multiple Globus collections are not supported")
}
