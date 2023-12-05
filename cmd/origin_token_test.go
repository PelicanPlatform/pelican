/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseClaims(t *testing.T) {
	// Give it something valid
	claims := []string{"foo=boo", "bar=baz"}
	claimsMap, err := parseClaims(claims)
	assert.NoError(t, err)
	assert.Equal(t, claimsMap["foo"], "boo")
	assert.Equal(t, claimsMap["bar"], "baz")
	assert.Equal(t, len(claimsMap), 2)

	// Give it something with multiple of the same claim key
	claims = []string{"foo=boo", "foo=baz"}
	claimsMap, err = parseClaims(claims)
	assert.NoError(t, err)
	assert.Equal(t, claimsMap["foo"], "boo baz")
	assert.Equal(t, len(claimsMap), 1)

	// Give it something without = delimiter
	claims = []string{"foo=boo", "barbaz"}
	_, err = parseClaims(claims)
	assert.EqualError(t, err, "The claim 'barbaz' is invalid. Did you forget an '='?")
}

func TestParseInputSlice(t *testing.T) {
	// A quick test, just to make sure this gets what it needs to
	rawSlice := []string{"https://my-issuer.com"}
	parsedSlice := parseInputSlice(&rawSlice, "iss")
	assert.Equal(t, parsedSlice, []string{"iss=https://my-issuer.com"})
}
