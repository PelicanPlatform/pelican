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
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestOriginStorageType_IsPosixLike pins down which backends count as
// "POSIX-like" so a future contributor can't silently flip an entry and have
// every downstream call site (self-test, director-test, etc.) start treating
// a remote-protocol backend as local.
func TestOriginStorageType_IsPosixLike(t *testing.T) {
	cases := []struct {
		in       OriginStorageType
		expected bool
	}{
		{OriginStoragePosix, true},
		{OriginStoragePosixv2, true},

		{OriginStorageSSH, false},
		{OriginStorageS3, false},
		{OriginStorageHTTPS, false},
		{OriginStorageGlobus, false},
		{OriginStorageXRoot, false},

		// Unknown / unset values must not be treated as POSIX-like.
		{OriginStorageType(""), false},
		{OriginStorageType("does-not-exist"), false},
	}
	for _, tc := range cases {
		t.Run(string(tc.in), func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.in.IsPosixLike())
		})
	}
}
