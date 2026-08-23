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

package oauth2

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAnnounceVerification(t *testing.T) {
	t.Run("complete-uri-is-printed-alone", func(t *testing.T) {
		out := &strings.Builder{}
		announceVerification(out, &DeviceAuth{
			UserCode:                "ABCD-EFGH",
			VerificationURI:         "https://issuer.example.com/device",
			VerificationURIComplete: "https://issuer.example.com/device?user_code=ABCD-EFGH",
		})
		assert.Contains(t, out.String(), "https://issuer.example.com/device?user_code=ABCD-EFGH")
		// The complete URI carries the code, so the user is not asked to type it.
		assert.NotContains(t, out.String(), "enter the following code")
	})

	t.Run("uri-and-code-are-printed-when-no-complete-uri", func(t *testing.T) {
		out := &strings.Builder{}
		announceVerification(out, &DeviceAuth{
			UserCode:        "ABCD-EFGH",
			VerificationURI: "https://issuer.example.com/device",
		})
		// Regression: this branch used to print VerificationURIComplete, which
		// is by definition empty here, so the user was told to navigate to a
		// blank line and then handed a code with nowhere to type it.
		assert.Contains(t, out.String(), "https://issuer.example.com/device")
		assert.Contains(t, out.String(), "enter the following code")
		assert.Contains(t, out.String(), "ABCD-EFGH")
	})
}
