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

package lotjson

import (
	"math"

	"github.com/pelicanplatform/pelican/lotman/core"
)

// The lotman core stores storage quantities as int64 bytes. The JSON schema
// (and the REST API and PolicyDefinitions config) speak GB as float64. These
// helpers convert at that boundary, using the same decimal-GB factor the
// codebase has always used (BytesInGigabyte = 1e9).
//
// The unbounded sentinel is preserved across the unit change: -1 GB maps to -1
// bytes (core.Unbounded), NOT to -1e9 bytes. A nil GB pointer means "unset" and
// maps to 0 (callers apply field defaults before conversion).

// GbToBytes converts a GB value to int64 bytes, preserving the unbounded
// sentinel (-1 GB -> -1 bytes).
func GbToBytes(gb float64) int64 {
	if gb == -1 {
		return core.Unbounded
	}
	return int64(math.Round(gb * BytesInGigabyte))
}

// BytesToGB converts int64 bytes to a GB value, preserving the unbounded
// sentinel (-1 bytes -> -1 GB).
func BytesToGB(b int64) float64 {
	if b == core.Unbounded {
		return -1
	}
	return float64(b) / BytesInGigabyte
}

// GbPtrToBytes converts an optional GB value to int64 bytes. A nil pointer maps
// to 0 (the field was not set; defaults are applied upstream).
func GbPtrToBytes(gb *float64) int64 {
	if gb == nil {
		return 0
	}
	return GbToBytes(*gb)
}

// BytesToGBPtr converts int64 bytes to a non-nil *float64 GB value.
func BytesToGBPtr(b int64) *float64 {
	v := BytesToGB(b)
	return &v
}

// GbPtrToBytesPtr converts an optional GB value to an optional int64 bytes
// value (nil stays nil), preserving the unbounded sentinel.
func GbPtrToBytesPtr(gb *float64) *int64 {
	if gb == nil {
		return nil
	}
	v := GbToBytes(*gb)
	return &v
}

// Int64PtrValue returns the value of an optional Int64FromFloat (object counts
// and millisecond timestamps), with nil mapping to def.
func Int64PtrValue(v *Int64FromFloat, def int64) int64 {
	if v == nil {
		return def
	}
	return v.Value
}

// DerefOrZero returns the pointed-to value, or 0 for a nil pointer.
func DerefOrZero(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// PathSpecsFromLotPaths converts JSON LotPath values to core PathSpecs. The
// LotPath carries no exclude flag.
func PathSpecsFromLotPaths(in []LotPath) []core.PathSpec {
	out := make([]core.PathSpec, 0, len(in))
	for _, p := range in {
		out = append(out, core.PathSpec{Path: p.Path, Recursive: p.Recursive})
	}
	return out
}

// --- input mappers: JSON (GB) -> core (bytes) ---

// MpaToCore converts a JSON MPA (GB, pointers) to a core MPA (bytes). Every
// unset axis defaults to 0 (no quota / non-expiring); the unbounded sentinel
// (-1) is always set explicitly by callers, never implied by omission. A nil
// MPA therefore yields an all-zero MPA.
func MpaToCore(m *MPA) core.MPA {
	if m == nil {
		return core.MPA{}
	}
	return core.MPA{
		DedicatedBytes:     GbPtrToBytes(m.DedicatedGB),
		OpportunisticBytes: GbPtrToBytes(m.OpportunisticGB),
		MaxNumObjects:      Int64PtrValue(m.MaxNumObjects, 0),
		CreationTime:       Int64PtrValue(m.CreationTime, 0),
		ExpirationTime:     Int64PtrValue(m.ExpirationTime, 0),
		DeletionTime:       Int64PtrValue(m.DeletionTime, 0),
	}
}

// MergeMPAToCore builds the full replacement MPA for an update: it starts from
// the lot's existing MPA and overlays only the fields the caller specified
// (non-nil). This preserves unspecified fields — notably creation_time, which
// the update path deliberately nils out because it must not change.
func MergeMPAToCore(u *MPA, existing core.Lot) core.MPA {
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
		out.DedicatedBytes = GbToBytes(*u.DedicatedGB)
	}
	if u.OpportunisticGB != nil {
		out.OpportunisticBytes = GbToBytes(*u.OpportunisticGB)
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

// AttrValuesToAdapter converts core attribution values (bytes, keyed by parent
// then MPA key) back to the JSON GB-based ParentAttribution map.
func AttrValuesToAdapter(in map[string]map[string]int64) map[string]ParentAttribution {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]ParentAttribution, len(in))
	for parent, axes := range in {
		var pa ParentAttribution
		if v, ok := axes[core.MpaKeyDedicatedBytes]; ok {
			pa.DedicatedGB = BytesToGBPtr(v)
		}
		if v, ok := axes[core.MpaKeyOpportunisticBytes]; ok {
			pa.OpportunisticGB = BytesToGBPtr(v)
		}
		if v, ok := axes[core.MpaKeyMaxNumObjects]; ok {
			vv := v
			pa.MaxNumObjects = &Int64FromFloat{Value: vv}
		}
		out[parent] = pa
	}
	return out
}

// ParentAttrToCore converts JSON parent attributions (GB) to core attributions
// (bytes), preserving which axes were explicitly specified.
func ParentAttrToCore(in map[string]ParentAttribution) map[string]core.ParentAttribution {
	if in == nil {
		return nil
	}
	out := make(map[string]core.ParentAttribution, len(in))
	for parent, pa := range in {
		ca := core.ParentAttribution{
			DedicatedBytes:     GbPtrToBytesPtr(pa.DedicatedGB),
			OpportunisticBytes: GbPtrToBytesPtr(pa.OpportunisticGB),
		}
		if pa.MaxNumObjects != nil {
			v := pa.MaxNumObjects.Value
			ca.MaxNumObjects = &v
		}
		out[parent] = ca
	}
	return out
}

// LotToSpec converts a JSON Lot (the create shape) to a core LotSpec. The
// LotPath has no exclude flag, so exclusions are never set via this path (they
// are not part of the create surface).
func LotToSpec(l *Lot) core.LotSpec {
	paths := make([]core.PathSpec, 0, len(l.Paths))
	for _, p := range l.Paths {
		paths = append(paths, core.PathSpec{Path: p.Path, Recursive: p.Recursive})
	}
	return core.LotSpec{
		LotName:            l.LotName,
		Owner:              l.Owner,
		Parents:            l.Parents,
		Paths:              paths,
		MPA:                MpaToCore(l.MPA),
		ParentAttributions: ParentAttrToCore(l.ParentAttributions),
	}
}

// --- output mappers: core (bytes) -> JSON (GB) ---

// CoreMPAToAdapter converts a core Lot's MPA fields to the JSON MPA (GB).
func CoreMPAToAdapter(l core.Lot) *MPA {
	return &MPA{
		DedicatedGB:     BytesToGBPtr(l.DedicatedBytes),
		OpportunisticGB: BytesToGBPtr(l.OpportunisticBytes),
		MaxNumObjects:   &Int64FromFloat{Value: l.MaxNumObjects},
		CreationTime:    &Int64FromFloat{Value: l.CreationTime},
		ExpirationTime:  &Int64FromFloat{Value: l.ExpirationTime},
		DeletionTime:    &Int64FromFloat{Value: l.DeletionTime},
	}
}

// LotViewToAdapter converts a core LotView (lot + parents + paths + usage row)
// to the JSON Lot shape. RestrictiveMPA is attached separately by the caller
// when a recursive GetLot was requested.
func LotViewToAdapter(v *core.LotView) *Lot {
	paths := make([]LotPath, 0, len(v.Paths))
	for _, p := range v.Paths {
		paths = append(paths, LotPath{Path: p.Path, Recursive: p.Recursive, LotName: v.LotName})
	}
	return &Lot{
		LotName: v.LotName,
		Owner:   v.Owner,
		Parents: v.Parents,
		Paths:   paths,
		MPA:     CoreMPAToAdapter(v.Lot),
		Usage:   UsageRowToLotUsage(v.Usage, v.Lot),
	}
}

// SplitStorage divides a used-byte total into the portion that falls within the
// dedicated allotment and the portion that spills into opportunistic burst,
// honoring the unbounded sentinel on either axis.
func SplitStorage(used, dedicated, opportunistic int64) (ded, opp int64) {
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

// UsageRowToLotUsage maps a core usage row to the JSON per-axis LotUsage view.
// The total/objects/being-written axes map directly; the dedicated and
// opportunistic axes are derived by splitting total usage against the lot's MPA
// (a total-level split; the reference's finer self/children CASE breakdown can
// be layered in later if a consumer needs it).
func UsageRowToLotUsage(u core.LotUsage, l core.Lot) *LotUsage {
	total := u.SelfBytes + u.ChildrenBytes
	dedUsed, oppUsed := SplitStorage(total, l.DedicatedBytes, l.OpportunisticBytes)
	return &LotUsage{
		TotalGB: UsageMapFloat{
			SelfContrib:     BytesToGB(u.SelfBytes),
			ChildrenContrib: BytesToGB(u.ChildrenBytes),
			Total:           BytesToGB(total),
		},
		DedicatedGB:     UsageMapFloat{Total: BytesToGB(dedUsed)},
		OpportunisticGB: UsageMapFloat{Total: BytesToGB(oppUsed)},
		NumObjects: UsageMapInt{
			SelfContrib:     Int64FromFloat{Value: u.SelfObjects},
			ChildrenContrib: Int64FromFloat{Value: u.ChildrenObjects},
			Total:           Int64FromFloat{Value: u.SelfObjects + u.ChildrenObjects},
		},
		GBBeingWritten: UsageMapFloat{
			SelfContrib:     BytesToGB(u.SelfBytesBeingWritten),
			ChildrenContrib: BytesToGB(u.ChildrenBytesBeingWritten),
			Total:           BytesToGB(u.SelfBytesBeingWritten + u.ChildrenBytesBeingWritten),
		},
		ObjectsBeingWritten: UsageMapInt{
			SelfContrib:     Int64FromFloat{Value: u.SelfObjectsBeingWritten},
			ChildrenContrib: Int64FromFloat{Value: u.ChildrenObjectsBeingWritten},
			Total:           Int64FromFloat{Value: u.SelfObjectsBeingWritten + u.ChildrenObjectsBeingWritten},
		},
	}
}

// RestrictiveToAdapter converts core's restrictive-value map (keyed by core MPA
// key) into the JSON RestrictiveMPA. Byte axes are converted to GB.
func RestrictiveToAdapter(rv map[string]core.RestrictiveValue) *RestrictiveMPA {
	floatAxis := func(key string) LotValueMapFloat {
		v := rv[key]
		return LotValueMapFloat{LotName: v.LotName, Value: BytesToGB(v.Value)}
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

// CapacityToAdapter converts core available-capacity (bytes, nil for unbounded
// axes) to the JSON AvailableCapacity (GB; an unbounded axis reports 0,
// matching the prior null-decodes-to-zero behavior).
func CapacityToAdapter(c *core.AvailableCapacity) *AvailableCapacity {
	gbOrZero := func(p *int64) float64 {
		if p == nil {
			return 0
		}
		return BytesToGB(*p)
	}
	return &AvailableCapacity{
		AvailableDedicatedGB:     gbOrZero(c.AvailableDedicatedBytes),
		AvailableOpportunisticGB: gbOrZero(c.AvailableOpportunisticBytes),
		AvailableTotalGB:         gbOrZero(c.AvailableTotalBytes),
		AvailableMaxNumObjects:   DerefOrZero(c.AvailableMaxNumObjects),
		PeakDedicatedGB:          BytesToGB(c.PeakDedicatedBytes),
		PeakOpportunisticGB:      BytesToGB(c.PeakOpportunisticBytes),
		PeakMaxNumObjects:        c.PeakMaxNumObjects,
		PeakTotalGB:              BytesToGB(c.PeakTotalBytes),
	}
}
