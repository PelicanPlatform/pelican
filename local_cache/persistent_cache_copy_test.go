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

package local_cache

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestForwardTPCHeaders verifies the cache forwards exactly the third-party-copy
// headers a broker-origin COPY needs — including the TransferHeader* credentials
// in their canonicalized form — and nothing else.
func TestForwardTPCHeaders(t *testing.T) {
	src := http.Header{}
	// Set via canonical keys as Go's HTTP server would present them.
	src.Set("Source", "https://origin-b.example/data/obj")
	src.Set("Overwrite", "T")
	// "TransferHeaderAuthorization" canonicalizes to "Transferheaderauthorization".
	src.Set("TransferHeaderAuthorization", "Bearer source-token")
	src.Set("TransferHeaderX-Custom", "v")
	// Headers that must NOT be swept in by the TPC forwarder.
	src.Set("Authorization", "Bearer dest-token")
	src.Set("Content-Type", "application/octet-stream")
	src.Set("Host", "cache.example")

	dst := http.Header{}
	forwardTPCHeaders(dst, src)

	assert.Equal(t, "https://origin-b.example/data/obj", dst.Get("Source"))
	assert.Equal(t, "T", dst.Get("Overwrite"))
	assert.Equal(t, "Bearer source-token", dst.Get("Transferheaderauthorization"))
	assert.Equal(t, "v", dst.Get("Transferheaderx-Custom"))

	// The destination write token and framing headers are handled elsewhere and
	// must not be duplicated by the TPC forwarder.
	assert.Empty(t, dst.Get("Authorization"))
	assert.Empty(t, dst.Get("Content-Type"))
	assert.Empty(t, dst.Get("Host"))
}
