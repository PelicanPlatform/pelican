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

package lotman

import (
	"errors"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/lotman/core"
)

// errNotInitialized is returned by the wrappers when InitLotman has not yet
// built the manager.
var errNotInitialized = errors.New("lotman: manager is not initialized")

// requireManager returns the initialized manager or errNotInitialized.
func requireManager() (*core.Manager, error) {
	m := getManager()
	if m == nil {
		return nil, errNotInitialized
	}
	return m, nil
}

// This file holds the native lotman engine: a process-wide core.Manager plus
// the mapping layer that converts the adapter's GB-based public types into the
// core's byte-based specs (and back). The wrapper functions delegate to the
// manager held here instead of the libLotMan.so binding.

var (
	mgr   *core.Manager
	mgrMu sync.RWMutex

	// fedPrefix, when non-empty, is prepended to every namespace ad path during
	// lot auto-creation so V2 (persistent cache) lots are federation-qualified
	// (e.g. "/osg-htc.org/atlas"), matching the cache's federation-qualified
	// resolution keys. It MUST stay empty for the V1 (XRootD) cache: the purge
	// plugin and xrootd have no concept of federation prefixes and bare paths
	// are required there.
	fedPrefix   string
	fedPrefixMu sync.RWMutex
)

// getManager returns the initialized core manager, or nil if InitLotman has not
// run. Wrappers should treat nil as "lotman not initialized".
func getManager() *core.Manager {
	mgrMu.RLock()
	defer mgrMu.RUnlock()
	return mgr
}

// GetManager returns the initialized lot core manager (or nil before
// InitLotman). The persistent (V2) cache uses it to resolve objects to lots and
// to track/evict per-lot usage.
func GetManager() *core.Manager {
	return getManager()
}

// setManager installs the process-wide manager (called by InitLotman, and by
// tests that exercise the wrappers against an in-memory database).
func setManager(m *core.Manager) {
	mgrMu.Lock()
	defer mgrMu.Unlock()
	mgr = m
}

// SetFederationPrefix sets the path prefix prepended to namespace ad paths
// during lot auto-creation. The V2 cache launcher calls it with "/<discovery
// host>" BEFORE InitLotman so lots are federation-qualified; V1 must never call
// it. Pass "" to disable.
func SetFederationPrefix(prefix string) {
	fedPrefixMu.Lock()
	defer fedPrefixMu.Unlock()
	fedPrefix = prefix
}

// getFederationPrefix returns the configured federation path prefix ("" if none).
func getFederationPrefix() string {
	fedPrefixMu.RLock()
	defer fedPrefixMu.RUnlock()
	return fedPrefix
}

// coreLogger adapts logrus to the core.Logger interface so the standalone core
// emits through Pelican's logging without importing logrus itself.
type coreLogger struct{}

func (coreLogger) Debugf(format string, args ...any) { log.Debugf(format, args...) }
func (coreLogger) Warnf(format string, args ...any)  { log.Warnf(format, args...) }
