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

func TestHeaderParser(t *testing.T) {
	header1 := "namespace=/foo/bar, issuer = https://get-your-tokens.org, readhttps=False"
	newMap1 := HeaderParser(header1)

	assert.Equal(t, "/foo/bar", newMap1["namespace"])
	assert.Equal(t, "https://get-your-tokens.org", newMap1["issuer"])
	assert.Equal(t, "False", newMap1["readhttps"])

	header2 := ""
	newMap2 := HeaderParser(header2)
	assert.Equal(t, map[string]string{}, newMap2)
}
