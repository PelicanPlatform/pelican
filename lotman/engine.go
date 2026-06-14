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

// pathSpecsFromLotPaths converts adapter LotPath values to core PathSpecs. The
// adapter LotPath carries no exclude flag.
func pathSpecsFromLotPaths(in []LotPath) []core.PathSpec {
	out := make([]core.PathSpec, 0, len(in))
	for _, p := range in {
		out = append(out, core.PathSpec{Path: p.Path, Recursive: p.Recursive})
	}
	return out
}

// mergeMPAToCore builds the full replacement MPA for an update: it starts from
// the lot's existing MPA and overlays only the fields the caller specified
// (non-nil). This preserves unspecified fields — notably creation_time, which
// getLotUpdateJSONs deliberately nils out because it must not change.
func mergeMPAToCore(u *MPA, existing core.Lot) core.MPA {
	out := core.MPA{
		DedicatedBytes:     existing.DedicatedBytes,
		OpportunisticBytes: existing.OpportunisticBytes,
		MaxNumObjects:      existing.MaxNumObjects,
		CreationTime:       existing.CreationTime,
		ExpirationTime:     existing.ExpirationTime,
		DeletionTime:       existing.DeletionTime,
	}
	if u == nil {
		return out
	}
	if u.DedicatedGB != nil {
		out.DedicatedBytes = gbToBytes(*u.DedicatedGB)
	}
	if u.OpportunisticGB != nil {
		out.OpportunisticBytes = gbToBytes(*u.OpportunisticGB)
	}
	if u.MaxNumObjects != nil {
		out.MaxNumObjects = u.MaxNumObjects.Value
	}
	if u.CreationTime != nil {
		out.CreationTime = u.CreationTime.Value
	}
	if u.ExpirationTime != nil {
		out.ExpirationTime = u.ExpirationTime.Value
	}
	if u.DeletionTime != nil {
		out.DeletionTime = u.DeletionTime.Value
	}
	return out
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

// mpaToCore converts an adapter MPA (GB, pointers) to a core MPA (bytes). Every
// unset axis defaults to 0 (no quota / non-expiring); the unbounded sentinel
// (-1) is always set explicitly by callers, never implied by omission. A nil
// MPA therefore yields an all-zero MPA.
func mpaToCore(m *MPA) core.MPA {
	if m == nil {
		return core.MPA{}
	}
	return core.MPA{
		DedicatedBytes:     gbPtrToBytes(m.DedicatedGB),
		OpportunisticBytes: gbPtrToBytes(m.OpportunisticGB),
		MaxNumObjects:      int64PtrValue(m.MaxNumObjects, 0),
		CreationTime:       int64PtrValue(m.CreationTime, 0),
		ExpirationTime:     int64PtrValue(m.ExpirationTime, 0),
		DeletionTime:       int64PtrValue(m.DeletionTime, 0),
	}
}

// attrValuesToAdapter converts core attribution values (bytes, keyed by parent
// then MPA key) back to the adapter's GB-based ParentAttribution map.
func attrValuesToAdapter(in map[string]map[string]int64) map[string]ParentAttribution {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]ParentAttribution, len(in))
	for parent, axes := range in {
		var pa ParentAttribution
		if v, ok := axes[core.MpaKeyDedicatedBytes]; ok {
			pa.DedicatedGB = bytesToGBPtr(v)
		}
		if v, ok := axes[core.MpaKeyOpportunisticBytes]; ok {
			pa.OpportunisticGB = bytesToGBPtr(v)
		}
		if v, ok := axes[core.MpaKeyMaxNumObjects]; ok {
			vv := v
			pa.MaxNumObjects = &Int64FromFloat{Value: vv}
		}
		out[parent] = pa
	}
	return out
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

// --- output mappers: core (bytes) -> adapter (GB) ---

// coreMPAToAdapter converts a core Lot's MPA fields to the adapter MPA (GB).
func coreMPAToAdapter(l core.Lot) *MPA {
	return &MPA{
		DedicatedGB:     bytesToGBPtr(l.DedicatedBytes),
		OpportunisticGB: bytesToGBPtr(l.OpportunisticBytes),
		MaxNumObjects:   &Int64FromFloat{Value: l.MaxNumObjects},
		CreationTime:    &Int64FromFloat{Value: l.CreationTime},
		ExpirationTime:  &Int64FromFloat{Value: l.ExpirationTime},
		DeletionTime:    &Int64FromFloat{Value: l.DeletionTime},
	}
}

// lotViewToAdapter converts a core LotView (lot + parents + paths + usage row)
// to the adapter Lot shape. RestrictiveMPA is attached separately by the caller
// when a recursive GetLot was requested.
func lotViewToAdapter(v *core.LotView) *Lot {
	paths := make([]LotPath, 0, len(v.Paths))
	for _, p := range v.Paths {
		paths = append(paths, LotPath{Path: p.Path, Recursive: p.Recursive, LotName: v.LotName})
	}
	return &Lot{
		LotName: v.LotName,
		Owner:   v.Owner,
		Parents: v.Parents,
		Paths:   paths,
		MPA:     coreMPAToAdapter(v.Lot),
		Usage:   usageRowToLotUsage(v.Usage, v.Lot),
	}
}

// splitStorage divides a used-byte total into the portion that falls within the
// dedicated allotment and the portion that spills into opportunistic burst,
// honoring the unbounded sentinel on either axis.
func splitStorage(used, dedicated, opportunistic int64) (ded, opp int64) {
	if dedicated == core.Unbounded {
		return used, 0
	}
	if used <= dedicated {
		return used, 0
	}
	overage := used - dedicated
	if opportunistic == core.Unbounded {
		return dedicated, overage
	}
	if overage > opportunistic {
		overage = opportunistic
	}
	return dedicated, overage
}

// usageRowToLotUsage maps a core usage row to the adapter's per-axis LotUsage
// view. The total/objects/being-written axes map directly; the dedicated and
// opportunistic axes are derived by splitting total usage against the lot's MPA
// (a total-level split; the reference's finer self/children CASE breakdown can
// be layered in later if a consumer needs it).
func usageRowToLotUsage(u core.LotUsage, l core.Lot) *LotUsage {
	total := u.SelfBytes + u.ChildrenBytes
	dedUsed, oppUsed := splitStorage(total, l.DedicatedBytes, l.OpportunisticBytes)
	return &LotUsage{
		TotalGB: UsageMapFloat{
			SelfContrib:     bytesToGB(u.SelfBytes),
			ChildrenContrib: bytesToGB(u.ChildrenBytes),
			Total:           bytesToGB(total),
		},
		DedicatedGB:     UsageMapFloat{Total: bytesToGB(dedUsed)},
		OpportunisticGB: UsageMapFloat{Total: bytesToGB(oppUsed)},
		NumObjects: UsageMapInt{
			SelfContrib:     Int64FromFloat{Value: u.SelfObjects},
			ChildrenContrib: Int64FromFloat{Value: u.ChildrenObjects},
			Total:           Int64FromFloat{Value: u.SelfObjects + u.ChildrenObjects},
		},
		GBBeingWritten: UsageMapFloat{
			SelfContrib:     bytesToGB(u.SelfBytesBeingWritten),
			ChildrenContrib: bytesToGB(u.ChildrenBytesBeingWritten),
			Total:           bytesToGB(u.SelfBytesBeingWritten + u.ChildrenBytesBeingWritten),
		},
		ObjectsBeingWritten: UsageMapInt{
			SelfContrib:     Int64FromFloat{Value: u.SelfObjectsBeingWritten},
			ChildrenContrib: Int64FromFloat{Value: u.ChildrenObjectsBeingWritten},
			Total:           Int64FromFloat{Value: u.SelfObjectsBeingWritten + u.ChildrenObjectsBeingWritten},
		},
	}
}

// restrictiveToAdapter converts core's restrictive-value map (keyed by core MPA
// key) into the adapter's RestrictiveMPA. Byte axes are converted to GB.
func restrictiveToAdapter(rv map[string]core.RestrictiveValue) *RestrictiveMPA {
	floatAxis := func(key string) LotValueMapFloat {
		v := rv[key]
		return LotValueMapFloat{LotName: v.LotName, Value: bytesToGB(v.Value)}
	}
	intAxis := func(key string) LotValueMapInt {
		v := rv[key]
		return LotValueMapInt{LotName: v.LotName, Value: Int64FromFloat{Value: v.Value}}
	}
	return &RestrictiveMPA{
		DedicatedGB:     floatAxis(core.MpaKeyDedicatedBytes),
		OpportunisticGB: floatAxis(core.MpaKeyOpportunisticBytes),
		MaxNumObjects:   intAxis(core.MpaKeyMaxNumObjects),
		CreationTime:    intAxis("creation_time"),
		ExpirationTime:  intAxis("expiration_time"),
		DeletionTime:    intAxis("deletion_time"),
	}
}

// capacityToAdapter converts core available-capacity (bytes, nil for unbounded
// axes) to the adapter AvailableCapacity (GB; an unbounded axis reports 0,
// matching the prior null-decodes-to-zero behavior).
func capacityToAdapter(c *core.AvailableCapacity) *AvailableCapacity {
	gbOrZero := func(p *int64) float64 {
		if p == nil {
			return 0
		}
		return bytesToGB(*p)
	}
	return &AvailableCapacity{
		AvailableDedicatedGB:     gbOrZero(c.AvailableDedicatedBytes),
		AvailableOpportunisticGB: gbOrZero(c.AvailableOpportunisticBytes),
		AvailableTotalGB:         gbOrZero(c.AvailableTotalBytes),
		AvailableMaxNumObjects:   derefOrZero(c.AvailableMaxNumObjects),
		PeakDedicatedGB:          bytesToGB(c.PeakDedicatedBytes),
		PeakOpportunisticGB:      bytesToGB(c.PeakOpportunisticBytes),
		PeakMaxNumObjects:        c.PeakMaxNumObjects,
		PeakTotalGB:              bytesToGB(c.PeakTotalBytes),
	}
}

func derefOrZero(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}
