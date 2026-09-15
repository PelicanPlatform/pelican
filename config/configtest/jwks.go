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

// Package configtest provides shared test helpers for packages that
// cannot import test_utils without creating an import cycle with config.
package configtest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/require"
)

// WriteJWKSFile serializes keys into a JWKS JSON file at dir/name
// and returns the full path. Fails the test on any error.
func WriteJWKSFile(t testing.TB, dir, name string, keys ...jwk.Key) string {
	t.Helper()
	set := jwk.NewSet()
	for _, k := range keys {
		require.NoError(t, set.AddKey(k))
	}
	data, err := json.Marshal(set)
	require.NoError(t, err)
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, data, 0600))
	return path
}
