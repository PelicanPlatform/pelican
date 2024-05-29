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

package web_ui

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateOAuthState(t *testing.T) {
	t.Run("generate-correct-state-string", func(t *testing.T) {
		get := GenerateOAuthState(map[string]string{"key1": "val1"})
		assert.Equal(t, "key1=val1", get)
	})

	t.Run("generate-url-encoded-state-string", func(t *testing.T) {
		val1Raw := "https://example.com"
		val1Encoded := url.QueryEscape(val1Raw)
		get := GenerateOAuthState(map[string]string{"key1": val1Raw})
		assert.Equal(t, "key1="+val1Encoded, get)
	})
}

func TestParseOAuthState(t *testing.T) {
	t.Run("parse-non-url-string", func(t *testing.T) {
		get, err := ParseOAuthState("key1=val1&key2=val2")
		require.NoError(t, err)
		assert.EqualValues(t, map[string]string{"key1": "val1", "key2": "val2"}, get)
	})

	t.Run("parse-url-encoded-string", func(t *testing.T) {
		val2Raw := "https://example.com"
		val2Encoded := url.QueryEscape(val2Raw)
		get, err := ParseOAuthState("key1=val1&key2=" + val2Encoded)
		require.NoError(t, err)
		assert.EqualValues(t, map[string]string{"key1": "val1", "key2": val2Raw}, get)
	})

	t.Run("duplicated-keys-returns-err", func(t *testing.T) {
		get, err := ParseOAuthState("key1=val1&key1=val2")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicated keys")
		assert.Nil(t, get)
	})
}
