package main

import (
	"github.com/stretchr/testify/assert"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestIsPort calls main.hasPort with a hostname, checking
// for a valid return value.
func TestIsPort(t *testing.T) {

	if HasPort("blah.not.port:") {
		t.Fatal("Failed to parse port when : at end")
	}

	if !HasPort("host:1") {
		t.Fatal("Failed to parse with port = 1")
	}

	if HasPort("https://example.com") {
		t.Fatal("Failed when scheme is specified")
	}
}

// TestNewTransferDetails checks the creation of transfer details
func TestNewTransferDetails(t *testing.T) {
	// Case 1: cache with http
	transfers := NewTransferDetails("cache.edu", false)
	assert.Equal(t, 2, len(transfers))
	assert.Equal(t, "cache.edu:8000", transfers[0].Url.Host)
	assert.Equal(t, "http", transfers[0].Url.Scheme)
	assert.Equal(t, true, transfers[0].Proxy)
	assert.Equal(t, "cache.edu:8000", transfers[1].Url.Host)
	assert.Equal(t, "http", transfers[1].Url.Scheme)
	assert.Equal(t, false, transfers[1].Proxy)

	// Case 2: cache with https
	transfers = NewTransferDetails("cache.edu", true)
	assert.Equal(t, 2, len(transfers))
	assert.Equal(t, "cache.edu:8444", transfers[0].Url.Host)
	assert.Equal(t, "https", transfers[0].Url.Scheme)
	assert.Equal(t, false, transfers[0].Proxy)
	assert.Equal(t, "cache.edu:8443", transfers[1].Url.Host)
	assert.Equal(t, "https", transfers[1].Url.Scheme)
	assert.Equal(t, false, transfers[1].Proxy)

	// Case 3: cache with port with http
	transfers = NewTransferDetails("cache.edu:1234", false)
	assert.Equal(t, 2, len(transfers))
	assert.Equal(t, "cache.edu:1234", transfers[0].Url.Host)
	assert.Equal(t, "http", transfers[0].Url.Scheme)
	assert.Equal(t, true, transfers[0].Proxy)
	assert.Equal(t, "cache.edu:1234", transfers[1].Url.Host)
	assert.Equal(t, "http", transfers[1].Url.Scheme)
	assert.Equal(t, false, transfers[1].Proxy)

	// Case 4. cache with port with https
	transfers = NewTransferDetails("cache.edu:5678", true)
	assert.Equal(t, 1, len(transfers))
	assert.Equal(t, "cache.edu:5678", transfers[0].Url.Host)
	assert.Equal(t, "https", transfers[0].Url.Scheme)
	assert.Equal(t, false, transfers[0].Proxy)
}

func TestNewTransferDetailsEnv(t *testing.T) {
	os.Setenv("OSG_DISABLE_PROXY_FALLBACK", "")
	transfers := NewTransferDetails("cache.edu", false)
	assert.Equal(t, 1, len(transfers))
	assert.Equal(t, true, transfers[0].Proxy)

	transfers = NewTransferDetails("cache.edu", true)
	assert.Equal(t, 2, len(transfers))
	assert.Equal(t, "https", transfers[0].Url.Scheme)
	assert.Equal(t, false, transfers[0].Proxy)
	assert.Equal(t, false, transfers[1].Proxy)
	os.Unsetenv("OSG_DISABLE_PROXY_FALLBACK")
}

func TestSlowTransfers(t *testing.T) {

	channel := make(chan bool)
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Don't send any response
		<-channel
	}))

	defer svr.CloseClientConnections()
	defer svr.Close()

	transfers := NewTransferDetails(svr.URL, false)
	assert.Equal(t, 2, len(transfers))
	assert.Equal(t, svr.URL, transfers[0].Url.String())

	finishedChannel := make(chan bool)
	var err error
	// Do a quick timeout
	go func() {
		_, err = DownloadHTTP(transfers[0], filepath.Join(t.TempDir(), "test.txt"), "")
		finishedChannel <- true
	}()
	select {
	case <-finishedChannel:
		if err == nil {
			t.Fatal("Download should have failed")
		}
	case <-time.After(time.Second * 12):
		t.Fatal("Download should have failed")
	}

	// Close the channel to allow the download to complete
	channel <- true

	// Make sure the errors are correct
	assert.NotNil(t, err)
	assert.IsType(t, &ConnectionSetupError{}, err, err.Error())

}

// Test connection error
func TestConnectionError(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("dialClosedPort: Listen failed: %v", err)
	}
	addr := l.Addr().String()
	l.Close()

	_, err = DownloadHTTP(TransferDetails{Url: url.URL{Host: addr, Scheme: "http"}, Proxy: false}, filepath.Join(t.TempDir(), "test.txt"), "")

	assert.IsType(t, &ConnectionSetupError{}, err)

}
