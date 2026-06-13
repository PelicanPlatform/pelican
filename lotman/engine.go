//go:build linux && !ppc64le

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
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/lotman/core"
)

// This file holds the native lotman engine: a process-wide core.Manager plus
// the mapping layer that converts the adapter's GB-based public types into the
// core's byte-based specs (and back). The wrapper functions delegate to the
// manager held here instead of the libLotMan.so binding.

var (
	mgr   *core.Manager
	mgrMu sync.RWMutex
)

// getManager returns the initialized core manager, or nil if InitLotman has not
// run. Wrappers should treat nil as "lotman not initialized".
func getManager() *core.Manager {
	mgrMu.RLock()
	defer mgrMu.RUnlock()
	return mgr
}

// setManager installs the process-wide manager (called by InitLotman, and by
// tests that exercise the wrappers against an in-memory database).
func setManager(m *core.Manager) {
	mgrMu.Lock()
	defer mgrMu.Unlock()
	mgr = m
}

// coreLogger adapts logrus to the core.Logger interface so the standalone core
// emits through Pelican's logging without importing logrus itself.
type coreLogger struct{}

func (coreLogger) Debugf(format string, args ...any) { log.Debugf(format, args...) }
func (coreLogger) Warnf(format string, args ...any)  { log.Warnf(format, args...) }

// --- input mappers: adapter (GB) -> core (bytes) ---

// gbPtrToBytesPtr converts an optional GB value to an optional int64 bytes
// value (nil stays nil), preserving the unbounded sentinel.
func gbPtrToBytesPtr(gb *float64) *int64 {
	if gb == nil {
		return nil
	}
	v := gbToBytes(*gb)
	return &v
}

// mpaToCore converts an adapter MPA (GB, pointers) to a core MPA (bytes). A nil
// MPA yields a zero-storage, unbounded-objects, non-expiring MPA; unset object
// counts default to unbounded and unset timestamps to the non-expiring sentinel.
func mpaToCore(m *MPA) core.MPA {
	if m == nil {
		return core.MPA{MaxNumObjects: core.Unbounded}
	}
	return core.MPA{
		DedicatedBytes:     gbPtrToBytes(m.DedicatedGB),
		OpportunisticBytes: gbPtrToBytes(m.OpportunisticGB),
		MaxNumObjects:      int64PtrValue(m.MaxNumObjects, core.Unbounded),
		CreationTime:       int64PtrValue(m.CreationTime, 0),
		ExpirationTime:     int64PtrValue(m.ExpirationTime, 0),
		DeletionTime:       int64PtrValue(m.DeletionTime, 0),
	}
}

// parentAttrToCore converts adapter parent attributions (GB) to core
// attributions (bytes), preserving which axes were explicitly specified.
func parentAttrToCore(in map[string]ParentAttribution) map[string]core.ParentAttribution {
	if in == nil {
		return nil
	}
	out := make(map[string]core.ParentAttribution, len(in))
	for parent, pa := range in {
		ca := core.ParentAttribution{
			DedicatedBytes:     gbPtrToBytesPtr(pa.DedicatedGB),
			OpportunisticBytes: gbPtrToBytesPtr(pa.OpportunisticGB),
		}
		if pa.MaxNumObjects != nil {
			v := pa.MaxNumObjects.Value
			ca.MaxNumObjects = &v
		}
		out[parent] = ca
	}
	return out
}

// lotToSpec converts an adapter Lot (the create shape) to a core LotSpec. The
// adapter LotPath has no exclude flag, so exclusions are never set via this
// path (they are not part of the create surface).
func lotToSpec(l *Lot) core.LotSpec {
	paths := make([]core.PathSpec, 0, len(l.Paths))
	for _, p := range l.Paths {
		paths = append(paths, core.PathSpec{Path: p.Path, Recursive: p.Recursive})
	}
	return core.LotSpec{
		LotName:            l.LotName,
		Owner:              l.Owner,
		Parents:            l.Parents,
		Paths:              paths,
		MPA:                mpaToCore(l.MPA),
		ParentAttributions: parentAttrToCore(l.ParentAttributions),
	}
}
