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

// TestGetFedTokenNoManagerNeverWaits pins the behaviour for a cache with no
// federation token manager (site-local mode, or an instance built directly
// in a test): a cache miss must not block waiting for a token that will
// never come.
func TestGetFedTokenNoManagerNeverWaits(t *testing.T) {
	pc := &PersistentCache{fedTokenReady: make(chan struct{})}

	start := time.Now()
	assert.Empty(t, pc.getFedToken())
	assert.Less(t, time.Since(start), fedTokenStartupWait, "no manager: return without waiting")

	// A token handed over anyway is still used.
	pc.SetFedToken("tok")
	assert.Equal(t, "tok", pc.getFedToken())
}

// TestGetFedTokenWaitsForExpectedManager verifies that a cache whose launcher
// declared a token manager waits for the first token, bounded by
// fedTokenStartupWait, and uses the token once it arrives.
func TestGetFedTokenWaitsForExpectedManager(t *testing.T) {
	oldWait := fedTokenStartupWait
	fedTokenStartupWait = 100 * time.Millisecond
	t.Cleanup(func() { fedTokenStartupWait = oldWait })

	pc := &PersistentCache{fedTokenReady: make(chan struct{}), expectFedToken: true}

	start := time.Now()
	assert.Empty(t, pc.getFedToken())
	assert.GreaterOrEqual(t, time.Since(start), fedTokenStartupWait, "waits for the manager's first token")

	pc.SetFedToken("tok")
	start = time.Now()
	assert.Equal(t, "tok", pc.getFedToken())
	assert.Less(t, time.Since(start), fedTokenStartupWait, "no wait once a token is set")
}

// TestGetFedTokenUnblocksOnSetFedToken verifies that a caller waiting for the
// first token returns as soon as it is delivered.
func TestGetFedTokenUnblocksOnSetFedToken(t *testing.T) {
	oldWait := fedTokenStartupWait
	fedTokenStartupWait = 10 * time.Second
	t.Cleanup(func() { fedTokenStartupWait = oldWait })

	pc := &PersistentCache{fedTokenReady: make(chan struct{}), expectFedToken: true}
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
