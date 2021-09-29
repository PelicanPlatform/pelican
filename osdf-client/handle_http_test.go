package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
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
	assert.Equal(t, 4, len(transfers))
	assert.Equal(t, "cache.edu:8444", transfers[0].Url.Host)
	assert.Equal(t, "https", transfers[0].Url.Scheme)
	assert.Equal(t, true, transfers[0].Proxy)
	assert.Equal(t, "cache.edu:8444", transfers[1].Url.Host)
	assert.Equal(t, "https", transfers[1].Url.Scheme)
	assert.Equal(t, false, transfers[1].Proxy)
	assert.Equal(t, "cache.edu:8443", transfers[2].Url.Host)
	assert.Equal(t, "https", transfers[1].Url.Scheme)
	assert.Equal(t, true, transfers[2].Proxy)
	assert.Equal(t, "cache.edu:8443", transfers[3].Url.Host)
	assert.Equal(t, "https", transfers[3].Url.Scheme)
	assert.Equal(t, false, transfers[3].Proxy)

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
	assert.Equal(t, 2, len(transfers))
	assert.Equal(t, "cache.edu:5678", transfers[0].Url.Host)
	assert.Equal(t, "https", transfers[0].Url.Scheme)
	assert.Equal(t, true, transfers[0].Proxy)
	assert.Equal(t, "cache.edu:5678", transfers[1].Url.Host)
	assert.Equal(t, "https", transfers[1].Url.Scheme)
	assert.Equal(t, false, transfers[1].Proxy)
}


