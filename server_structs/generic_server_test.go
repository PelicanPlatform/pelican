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

package server_structs

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"unicode"

	"github.com/stretchr/testify/assert"
)

// randFlipCase randomly (50-50) flip the case for each char in
// a unicode-encoded string
func randFlipCase(s string) string {
	var out strings.Builder
	for _, r := range s {
		if rand.Intn(2) == 0 {
			if unicode.IsUpper(r) {
				r = unicode.ToLower(r)
			} else if unicode.IsLower(r) {
				r = unicode.ToUpper(r)
			}
		}
		out.WriteRune(r)
	}
	return out.String()
}

func TestServerTypeFromString(t *testing.T) {
	// Test setup: type and template
	type ServerTypeFromStringTestcase struct {
		Input            string
		ExpectServerType ServerType
		ExpectError      error
	}

	testcases_template := []ServerTypeFromStringTestcase{
		{"origin", OriginType, nil},
		{"cache", CacheType, nil},
		{"registry", RegistryType, nil},
		{"director", DirectorType, nil},
		{"localcache", LocalCacheType, nil},
		{"broker", BrokerType, nil},
		{"transfer", TransferType, nil},
	}

	t.Run("lowercase-test", func(t *testing.T) {
		// Add en error case
		testcases := make([]ServerTypeFromStringTestcase, len(testcases_template))
		copy(testcases, testcases_template)
		testcases = append(testcases, ServerTypeFromStringTestcase{"unknown", 0, fmt.Errorf("unrecognized server type %q", "unknown")})

		// Run tests in batch
		for _, test := range testcases {
			server_type, err := ServerTypeFromString(test.Input)
			assert.Equal(t, test.ExpectServerType, server_type, "server type mismatch")
			assert.Equal(t, test.ExpectError, err, "error mismatch")
		}
	})

	t.Run("case-insensitivity-test-fuzz", func(t *testing.T) {
		// Add an error case
		unknown_type_string := randFlipCase("unknown")
		unknown_type_error := fmt.Errorf("unrecognized server type %q", unknown_type_string)

		testcases := make([]ServerTypeFromStringTestcase, 0, len(testcases_template)+1)
		for _, test := range testcases_template {
			testcases = append(testcases, ServerTypeFromStringTestcase{randFlipCase(test.Input), test.ExpectServerType, test.ExpectError})
		}
		testcases = append(testcases, ServerTypeFromStringTestcase{unknown_type_string, 0, unknown_type_error})

		// Run tests in batch
		for _, test := range testcases {
			server_type, err := ServerTypeFromString(test.Input)
			assert.Equal(t, test.ExpectServerType, server_type, "server type mismatch")
			assert.Equal(t, test.ExpectError, err, "error mismatch")
		}
	})
}
