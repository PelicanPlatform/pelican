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

package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestApplyIPMask(t *testing.T) {
	t.Run("testValidIPv4", func(t *testing.T) {
		expectedMaskedIP := "192.168.1.0"
		validIPv4 := "192.168.1.1"
		maskedIP, ok := ApplyIPMask(validIPv4)
		assert.True(t, ok)
		assert.Equal(t, expectedMaskedIP, maskedIP)
	})

	t.Run("testValidIPv6", func(t *testing.T) {
		expectedMaskedIP := "2001:db8:3333:4444::"
		validIPv6 := "2001:0db8:3333:4444:5555:6666:7777:8888"
		maskedIP, ok := ApplyIPMask(validIPv6)
		assert.True(t, ok)
		assert.Equal(t, expectedMaskedIP, maskedIP)
	})

	t.Run("testInvalidInput", func(t *testing.T) {
		invalid := "abc.123"
		maskedIP, ok := ApplyIPMask(invalid)
		assert.False(t, ok)
		assert.Equal(t, maskedIP, invalid)
	})
}

func TestExtractAndMaskIP(t *testing.T) {
	t.Run("testWrappedIPv4", func(t *testing.T) {
		expectedMaskedIP := "192.168.1.0"
		wrappedValidIPv4 := "[192.168.1.1]"
		maskedIP, ok := ExtractAndMaskIP(wrappedValidIPv4)
		assert.True(t, ok)
		assert.Equal(t, expectedMaskedIP, maskedIP)
	})

	t.Run("testWrappedIPv6", func(t *testing.T) {
		expectedMaskedIP := "2001:db8:3333:4444::"
		wrappedValidIPv6 := "[2001:0db8:3333:4444:5555:6666:7777:8888]"
		maskedIP, ok := ExtractAndMaskIP(wrappedValidIPv6)
		assert.True(t, ok)
		assert.Equal(t, expectedMaskedIP, maskedIP)
	})

	t.Run("testWrappedInvalid", func(t *testing.T) {
		invalid := "[abc.123]"
		expected := "abc.123"
		maskedIP, ok := ExtractAndMaskIP(invalid)
		assert.False(t, ok)
		assert.Equal(t, maskedIP, expected)
	})

	t.Run("testUnwrappedIPv4", func(t *testing.T) {
		expectedMaskedIP := "192.168.1.0"
		validIPv4 := "192.168.1.1"
		maskedIP, ok := ExtractAndMaskIP(validIPv4)
		assert.True(t, ok)
		assert.Equal(t, expectedMaskedIP, maskedIP)
	})

	t.Run("testUnwrappedIPv6", func(t *testing.T) {
		expectedMaskedIP := "2001:db8:3333:4444::"
		validIPv6 := "2001:0db8:3333:4444:5555:6666:7777:8888"
		maskedIP, ok := ExtractAndMaskIP(validIPv6)
		assert.True(t, ok)
		assert.Equal(t, expectedMaskedIP, maskedIP)
	})

	t.Run("testWrappedReal", func(t *testing.T) {
		real := "[::ffff:79.110.62.117]"
		expected := "79.110.62.0"
		maskedIP, ok := ExtractAndMaskIP(real)
		assert.True(t, ok)
		assert.Equal(t, expected, maskedIP)
	})
}

func TestExtractVersionAndServiceFromUserAgent(t *testing.T) {

	type TestExtractCase struct {
		Name            string
		UserAgent       string
		ExpectedVersion string
		ExpectedService string
	}
	var testCases = []TestExtractCase{
		{Name: "testNormalUserAgent", UserAgent: "pelican-origin/7.9.0", ExpectedVersion: "7.9.0", ExpectedService: "origin"},
		{Name: "testMissingSlash", UserAgent: "pelican-origin.7.9.0"},
		{Name: "testNonAlpha", UserAgent: "pelican-origin1/7.9.9"},
		{Name: "testBigVersion", UserAgent: "pelican-origin/7.9.9.9.9"},
		{Name: "testNonNumeric", UserAgent: "pelican-origin/7s.9.0"},
		{Name: "testInvalidUserAgent", UserAgent: "thisisnotvalid"},
		{Name: "testEmptyUserAgent"},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			version, service := ExtractVersionAndServiceFromUserAgent(tc.UserAgent)
			assert.Equal(t, tc.ExpectedService, service)
			assert.Equal(t, tc.ExpectedVersion, version)
		})
	}
}
