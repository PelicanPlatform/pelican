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

// Package core is a native-Go implementation of the "lotman" storage-lot
// (reservation) accounting model, replacing the external C library
// (libLotMan.so). It owns a small SQLite schema (managed by GORM + Goose) and
// implements lot CRUD, a DAG hierarchy, longest-prefix path resolution, usage
// accounting with parent/child rollup, strict-hierarchy policy axioms, and the
// eviction-priority queries used to decide what to purge under storage pressure.
//
// Dependency hygiene: this package depends ONLY on the Go standard library,
// gorm.io/gorm, and github.com/pressly/goose/v3. It must NOT import any
// github.com/pelicanplatform/pelican/... package, so that it can be promoted to
// a standalone repository. All Pelican-specific concerns (config, federation
// discovery, token-scope auth, HTTP routing, cache integration) live in the
// adapter layer outside this package.
package core

// Sentinel values, ported verbatim from the C++ library's semantics.
const (
	// Unbounded marks a management-policy axis (dedicated_GB, opportunistic_GB,
	// max_num_objects) as having no limit.
	Unbounded = -1

	// UnboundedGB is the float form of Unbounded for the GB axes.
	UnboundedGB float64 = -1
)

// IsUnboundedGB reports whether a GB axis value means "no limit".
func IsUnboundedGB(v float64) bool { return v == UnboundedGB }

// IsUnboundedObjects reports whether an object-count axis value means "no limit".
func IsUnboundedObjects(v int64) bool { return v == Unbounded }

// IsNonExpiring reports whether a (creation, expiration, deletion) timestamp
// triple denotes a non-expiring lot. By the ported convention this is true iff
// all three are zero; any partial-zero combination is invalid.
func IsNonExpiring(creationMs, expirationMs, deletionMs int64) bool {
	return creationMs == 0 && expirationMs == 0 && deletionMs == 0
}

// Logger is the minimal logging surface the manager uses. The adapter injects a
// logrus-backed implementation; standalone callers may pass nil (see New).
type Logger interface {
	Debugf(format string, args ...any)
	Warnf(format string, args ...any)
}

// nopLogger discards all output; used when no Logger is injected.
type nopLogger struct{}

func (nopLogger) Debugf(string, ...any) {}
func (nopLogger) Warnf(string, ...any)  {}
