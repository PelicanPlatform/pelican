//go:build server || client

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

package database

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestGetOrCreateUserConcurrent verifies that concurrent first-time
// authentications for the same (sub, issuer) all succeed. Without a race-safe
// get-or-create, the goroutine that loses the INSERT trips a UNIQUE constraint
// and returns an error, which the transfer auth middleware surfaces as a
// spurious 500 (observed as a flaky TestTransferJobSubmission failure). A
// file-backed DB is used so the pooled connections share one database (an
// in-memory sqlite gives each connection its own).
func TestGetOrCreateUserConcurrent(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "u.sqlite")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&User{}, &Group{}, &GroupMember{}, &UserIdentity{}, &UserScope{}, &GroupScope{}))
	require.NoError(t, db.AutoMigrate(&userCredential{}))

	const n = 16
	var wg sync.WaitGroup
	results := make([]*User, n)
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = GetOrCreateUser(db, "raceuser", "raceuser", "https://issuer.example", CreatorSelf())
		}(i)
	}
	close(start)
	wg.Wait()

	for i, e := range errs {
		require.NoErrorf(t, e, "concurrent GetOrCreateUser call %d failed", i)
	}
	// Every caller must observe the same single user row.
	require.NotNil(t, results[0])
	id := results[0].ID
	for i, u := range results {
		require.NotNilf(t, u, "call %d returned nil user", i)
		require.Equalf(t, id, u.ID, "call %d resolved a different user id", i)
	}
}
