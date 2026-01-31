/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

package byte_rate

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRate(t *testing.T) {
	tests := []struct {
		input    string
		expected float64 // bytes per second
		hasError bool
	}{
		{"5MB/s", 5 * MiB, false},           // Standard
		{"100Mbps", 100 * MiB / 8, false},   // Network style (bits)
		{"100Mbit/s", 100 * MiB / 8, false}, // Explicit bits
		{"1GiB/m", GiB / 60.0, false},       // Large over time (per minute)
		{"500kbps", 500 * KiB / 8, false},   // Small bits
		{"1.5PB/s", 1.5 * PiB, false},       // Decimal with Peta
		{"1024B/s", 1024, false},            // Raw bytes
		{"10MB/s", 10 * MiB, false},         // 10 megabytes per second
		{"", 0, true},                       // Empty string
		{"invalid", 0, true},                // Invalid format
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			rate, err := ParseRate(tt.input)
			if tt.hasError {
				assert.Error(t, err, "Expected error for input: %s", tt.input)
			} else {
				require.NoError(t, err, "Unexpected error for input: %s", tt.input)
				assert.InDelta(t, tt.expected, float64(rate), 0.01, "Rate mismatch for input: %s", tt.input)
			}
		})
	}
}

func TestByteRateString(t *testing.T) {
	tests := []struct {
		rate     ByteRate
		expected string
	}{
		{ByteRate(5 * MiB), "5.00MB/s"},
		{ByteRate(1024), "1.00KB/s"},
		{ByteRate(GiB), "1.00GB/s"},
		{ByteRate(500), "500.00B/s"},
		{ByteRate(1.5 * TiB), "1.50TB/s"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.rate.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestByteRateUnmarshalText(t *testing.T) {
	tests := []struct {
		input    string
		expected ByteRate
		hasError bool
	}{
		{"10MB/s", ByteRate(10 * MiB), false},
		{"100Mbps", ByteRate(100 * MiB / 8), false},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			var rate ByteRate
			err := rate.UnmarshalText([]byte(tt.input))
			if tt.hasError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.InDelta(t, float64(tt.expected), float64(rate), 0.01)
			}
		})
	}
}

func TestByteRateJSON(t *testing.T) {
	// Test JSON marshaling/unmarshaling
	type config struct {
		Rate ByteRate `json:"rate"`
	}

	// Unmarshal
	jsonData := `{"rate": "10MB/s"}`
	var cfg config
	err := json.Unmarshal([]byte(jsonData), &cfg)
	require.NoError(t, err)
	assert.InDelta(t, 10*MiB, float64(cfg.Rate), 0.01)

	// Marshal
	cfg.Rate = ByteRate(5 * MiB)
	data, err := json.Marshal(cfg)
	require.NoError(t, err)
	assert.Contains(t, string(data), "5.00MB/s")
}

func TestBitsVsBytes(t *testing.T) {
	// Test that bits are correctly distinguished from bytes
	bytesRate, err := ParseRate("8MB/s")
	require.NoError(t, err)
	bitsRate, err := ParseRate("8Mbps")
	require.NoError(t, err)
	// 8MB/s should be 8x larger than 8Mbps (since 1 byte = 8 bits)
	assert.InDelta(t, float64(bytesRate)/8.0, float64(bitsRate), 0.01)
}

func TestParseRateEdgeCases(t *testing.T) {
	tests := []struct {
		input       string
		shouldError bool
		description string
	}{
		{"  10MB/s  ", false, "whitespace should be trimmed"},
		{"10", false, "bare number defaults to B/s"},
		{"10.5GB/s", false, "decimal values should work"},
		{"0MB/s", false, "zero is valid"},
		{"-10MB/s", true, "negative values should error"},
		{"MB/s", true, "missing value should error"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			_, err := ParseRate(tt.input)
			if tt.shouldError {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
			}
		})
	}
}
