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

package main

import (
	"net/url"
	"sort"
	"strings"
	"testing"

	dbutils "github.com/pelicanplatform/pelican/database/utils"
)

// dsnSettings decomposes a DSN into its pragma set plus any bare query
// parameters, so two DSNs can be compared on meaning rather than on the order
// their parameters happen to be written in.
func dsnSettings(t *testing.T, dsn string) (pragmas []string, params map[string]string) {
	t.Helper()
	_, query, _ := strings.Cut(dsn, "?")
	values, err := url.ParseQuery(query)
	if err != nil {
		t.Fatalf("parsing DSN %q: %v", dsn, err)
	}
	params = map[string]string{}
	for k, vs := range values {
		if k == "_pragma" {
			pragmas = append(pragmas, vs...)
			continue
		}
		params[k] = vs[0]
	}
	sort.Strings(pragmas)
	return pragmas, params
}

// TestDSNMatchesPelican pins this library's connection settings against
// database/utils.SQLiteDSN, the canonical definition.
//
// The two processes open the *same* lots.sqlite: pelican-server through
// SQLiteDSN, the purge plugin through this library. A setting present on one
// side and not the other is not a style difference — _txlock=immediate is what
// stops a read-then-write transaction from failing with SQLITE_BUSY_SNAPSHOT
// the moment the other process commits, and busy_timeout cannot retry that
// error. This library restates the DSN rather than importing it so the shared
// object does not pull in Pelican's config package, which is exactly the kind
// of duplication that drifts; this test is the thing that stops it.
func TestDSNMatchesPelican(t *testing.T) {
	const dbPath = "/var/lib/lotman/lots.sqlite"

	ourPragmas, ourParams := dsnSettings(t, lotDBDSN(dbPath, defaultBusyTimeoutMs))
	theirPragmas, theirParams := dsnSettings(t, dbutils.SQLiteDSN(dbPath))

	if strings.Join(ourPragmas, ",") != strings.Join(theirPragmas, ",") {
		t.Errorf("pragma set differs from database/utils.SQLiteDSN:\n  cshared: %v\n  pelican: %v",
			ourPragmas, theirPragmas)
	}
	for k, want := range theirParams {
		if got := ourParams[k]; got != want {
			t.Errorf("parameter %s = %q, want %q (as database/utils.SQLiteDSN sets it)", k, got, want)
		}
	}
	for k := range ourParams {
		if _, expected := theirParams[k]; !expected {
			t.Errorf("parameter %s is set here but not by database/utils.SQLiteDSN", k)
		}
	}
}

// TestDSNHonoursBusyTimeout covers the one setting this library is allowed to
// differ on: the purge plugin can override it through the "db_timeout" context
// key.
func TestDSNHonoursBusyTimeout(t *testing.T) {
	pragmas, _ := dsnSettings(t, lotDBDSN("/tmp/lots.sqlite", 12345))
	found := false
	for _, p := range pragmas {
		if p == "busy_timeout(12345)" {
			found = true
		}
	}
	if !found {
		t.Errorf("configured busy timeout missing from DSN; got pragmas %v", pragmas)
	}
}
