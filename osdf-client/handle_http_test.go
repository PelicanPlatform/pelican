package main

import (
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

