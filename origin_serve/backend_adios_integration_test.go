package origin_serve

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAdiosIntegrationEndToEnd simulates an end-to-end ADIOS transfer scenario
func TestAdiosIntegrationEndToEnd(t *testing.T) {
	// Set up a mock upstream ADIOS service that returns data
	// Use HTTP, not HTTPS for testing to avoid TLS cert verification issues
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate returning ADIOS data
		sampleData := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(sampleData)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(sampleData)
	}))
	defer upstreamServer.Close()

	// Create ADIOS backend pointing to mock service
	backend := newAdiosBackend(AdiosBackendOptions{
		ServiceURL:    upstreamServer.URL,
		StoragePrefix: "/test/data",
		AuthTokenFile: "",
	})

	// Test OpenFile for single variable
	fileSystem := backend.FileSystem()
	file, err := fileSystem.OpenFile(context.Background(), "/test/data/file.bp/temperature/s0n1b0r0", os.O_RDONLY, 0)
	require.NoError(t, err)
	require.NotNil(t, file)

	// Read the data
	data := make([]byte, 100)
	n, err := file.Read(data)
	require.NoError(t, err)
	assert.Equal(t, 10, n)
	assert.Equal(t, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, data[:n])

	// Close the file
	err = file.Close()
	require.NoError(t, err)
}

// TestAdiosBatchTransfer tests multi-variable batch transfer
func TestAdiosBatchTransfer(t *testing.T) {
	// Mock upstream service
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return data for batch query
		batchData := make([]byte, 100)
		for i := 0; i < 100; i++ {
			batchData[i] = byte(i % 256)
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(batchData)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(batchData)
	}))
	defer upstreamServer.Close()

	backend := newAdiosBackend(AdiosBackendOptions{
		ServiceURL:    upstreamServer.URL,
		StoragePrefix: "/data",
		AuthTokenFile: "",
	})

	fileSystem := backend.FileSystem()

	// Test batch variable request with + separator
	file, err := fileSystem.OpenFile(context.Background(), "/data/sim.bp/temp+pressure+humidity/s0n1b0r1", os.O_RDONLY, 0)
	require.NoError(t, err)
	require.NotNil(t, file)

	data := make([]byte, 150)
	n, err := file.Read(data)
	require.NoError(t, err)
	assert.Equal(t, 100, n)

	file.Close()
}

// TestAdiosErrorHandling tests error cases
func TestAdiosErrorHandling(t *testing.T) {
	// Mock upstream that returns error
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	}))
	defer upstreamServer.Close()

	backend := newAdiosBackend(AdiosBackendOptions{
		ServiceURL:    upstreamServer.URL,
		StoragePrefix: "/data",
	})

	fileSystem := backend.FileSystem()

	// Try to open non-existent variable
	_, err := fileSystem.OpenFile(context.Background(), "/data/nonexistent.bp/missing/s0n1b0r0", os.O_RDONLY, 0)
	// The HTTP error should be propagated
	require.Error(t, err)
}

// TestAdiosPathVariations tests various valid ADIOS path formats
func TestAdiosPathVariations(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool // valid path
	}{
		{"simple variable", "/data/file.bp/temp/s0n1b0r0", true},
		{"nested variable", "/data/file.bp/physics%2Ftemp/s0n1b0r1", true},
		{"multiple vars", "/data/file.bp/temp+pressure+humidity/s0n1b0r0", true},
		{"different step", "/data/file.bp/temp/s5n10b2r1", true},
		{"invalid selector low rmorder", "/data/file.bp/temp/s0n1b0r2", false},
		{"missing bp ext", "/data/file/temp/s0n1b0r0", false},
		{"complex path", "/data/deep/path/file.bp/var/s1n2b3r0", true},
	}

	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data"))
	}))
	defer upstreamServer.Close()

	backend := newAdiosBackend(AdiosBackendOptions{
		ServiceURL:    upstreamServer.URL,
		StoragePrefix: "/data",
	})

	fileSystem := backend.FileSystem()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := fileSystem.OpenFile(context.Background(), tt.path, os.O_RDONLY, 0)
			if tt.expected {
				require.NoError(t, err, "expected valid path to succeed")
				require.NotNil(t, file)
				file.Close()
			} else {
				require.Error(t, err, "expected invalid path to fail")
			}
		})
	}
}
