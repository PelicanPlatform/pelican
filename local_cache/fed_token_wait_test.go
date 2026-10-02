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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetFedTokenWaitsOnlyOnce pins the startup grace period to a single
// wait per cache: a cache that never receives a federation token (site-local
// mode, or one built directly in a test) must not block on every miss.
func TestGetFedTokenWaitsOnlyOnce(t *testing.T) {
	oldWait := fedTokenStartupWait
	fedTokenStartupWait = 100 * time.Millisecond
	t.Cleanup(func() { fedTokenStartupWait = oldWait })

	pc := &PersistentCache{fedTokenReady: make(chan struct{})}

	start := time.Now()
	assert.Empty(t, pc.getFedToken())
	assert.GreaterOrEqual(t, time.Since(start), fedTokenStartupWait, "the first call waits for a token")

	start = time.Now()
	assert.Empty(t, pc.getFedToken())
	assert.Less(t, time.Since(start), fedTokenStartupWait, "later calls return without waiting")

	// A token that arrives after the grace period is still picked up.
	pc.SetFedToken("tok")
	assert.Equal(t, "tok", pc.getFedToken())
}

// TestGetFedTokenUnblocksOnSetFedToken verifies that a caller waiting in the
// grace period returns as soon as the first token is delivered.
func TestGetFedTokenUnblocksOnSetFedToken(t *testing.T) {
	oldWait := fedTokenStartupWait
	fedTokenStartupWait = 10 * time.Second
	t.Cleanup(func() { fedTokenStartupWait = oldWait })

	pc := &PersistentCache{fedTokenReady: make(chan struct{})}
	got := make(chan string, 1)
	go func() { got <- pc.getFedToken() }()

	pc.SetFedToken("tok")
	select {
	case tok := <-got:
		require.Equal(t, "tok", tok)
	case <-time.After(5 * time.Second):
		t.Fatal("getFedToken did not return after SetFedToken")
	}
}
