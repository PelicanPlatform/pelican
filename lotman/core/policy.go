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

package core

import (
	"math"
	"sort"

	"gorm.io/gorm"
)

// mpaKeys are the three axes that carry parent attributions.
var mpaKeys = []string{MpaKeyDedicatedBytes, MpaKeyOpportunisticBytes, MpaKeyMaxNumObjects}

// isPartialStorageSentinel reports the transient mid-update state where
// dedicated is unbounded but opportunistic is not (an invalid persisting state,
// but tolerated during a multi-field update so axiom checks defer to the final
// invariant check).
func isPartialStorageSentinel(dedicated, opportunistic int64) bool {
	return IsUnboundedBytes(dedicated) && !IsUnboundedBytes(opportunistic)
}

// mpaAxisValue returns the MPA value for an attribution axis.
func mpaAxisValue(mpa MPA, key string) int64 {
	switch key {
	case MpaKeyDedicatedBytes:
		return mpa.DedicatedBytes
	case MpaKeyOpportunisticBytes:
		return mpa.OpportunisticBytes
	case MpaKeyMaxNumObjects:
		return mpa.MaxNumObjects
	}
	return 0
}

// explicitAttr returns the explicit attributed value for an axis, if specified.
func explicitAttr(pa ParentAttribution, key string) (int64, bool) {
	switch key {
	case MpaKeyDedicatedBytes:
		if pa.DedicatedBytes != nil {
			return *pa.DedicatedBytes, true
		}
	case MpaKeyOpportunisticBytes:
		if pa.OpportunisticBytes != nil {
			return *pa.OpportunisticBytes, true
		}
	case MpaKeyMaxNumObjects:
		if pa.MaxNumObjects != nil {
			return *pa.MaxNumObjects, true
		}
	}
	return 0, false
}

// computeAndStoreAttributions distributes the lot's MPA across its non-self
// parents as absolute amounts and persists them, replacing any existing rows.
// Root/self-only lots have nothing to attribute. An unbounded axis (-1) is
// propagated as -1 to every parent; a zero axis attributes 0; otherwise
// explicit per-parent amounts are honored and the remainder is split as evenly
// as integer division allows.
func computeAndStoreAttributions(tx *gorm.DB, lotName string, mpa MPA, parents []string, attrs map[string]ParentAttribution) error {
	nonSelf := make([]string, 0, len(parents))
	for _, p := range parents {
		if p != lotName {
			nonSelf = append(nonSelf, p)
		}
	}
	// Always clear stale rows for this child.
	if err := tx.Where("child_lot_name = ?", lotName).Delete(&LotParentAttribution{}).Error; err != nil {
		return wrap(err, "clearing attributions")
	}
	if len(nonSelf) == 0 {
		return nil
	}
	// Reject attributions naming a non-parent.
	nonSelfSet := map[string]bool{}
	for _, p := range nonSelf {
		nonSelfSet[p] = true
	}
	for k := range attrs {
		if !nonSelfSet[k] {
			return wrapf(ErrInvalidLot, "attribution names %q which is not a non-self parent of %q", k, lotName)
		}
	}

	for _, key := range mpaKeys {
		total := mpaAxisValue(mpa, key)

		switch {
		case total == -1: // unbounded: propagate to every parent
			for _, p := range nonSelf {
				if err := storeAttribution(tx, lotName, p, key, -1); err != nil {
					return err
				}
			}
			continue
		case total == 0: // nothing to attribute on this axis
			for _, p := range nonSelf {
				if err := storeAttribution(tx, lotName, p, key, 0); err != nil {
					return err
				}
			}
			continue
		}

		var explicitlyAttributed int64
		var unspecified []string
		for _, p := range nonSelf {
			if pa, present := attrs[p]; present {
				if ev, ok := explicitAttr(pa, key); ok {
					if err := storeAttribution(tx, lotName, p, key, ev); err != nil {
						return err
					}
					explicitlyAttributed += ev
					continue
				}
			}
			unspecified = append(unspecified, p)
		}

		if len(unspecified) == 0 {
			if explicitlyAttributed < total {
				return wrapf(ErrInvalidLot, "explicit attributions for %q sum to %d but total is %d (shortfall, no parent to absorb)", key, explicitlyAttributed, total)
			}
			if explicitlyAttributed > total {
				return wrapf(ErrInvalidLot, "explicit attributions for %q sum to %d which exceeds total %d (double-count)", key, explicitlyAttributed, total)
			}
			continue
		}

		remainder := total - explicitlyAttributed
		if remainder < 0 {
			return wrapf(ErrInvalidLot, "explicit attributions for %q exceed the total allocation", key)
		}
		n := int64(len(unspecified))
		per := remainder / n
		extra := remainder % n
		for i, p := range unspecified {
			value := per
			if int64(i) < extra {
				value++
			}
			if err := storeAttribution(tx, lotName, p, key, value); err != nil {
				return err
			}
		}
	}
	return nil
}

func storeAttribution(tx *gorm.DB, child, parent, key string, value int64) error {
	row := LotParentAttribution{ChildLotName: child, ParentLotName: parent, MpaKey: key, AttributedValue: value}
	if err := tx.Create(&row).Error; err != nil {
		return wrap(err, "storing attribution")
	}
	return nil
}

// Attributions returns the stored parent attributions for a child lot, keyed by
// parent name then MPA key (absolute values in bytes/counts; -1 = unbounded).
func (m *Manager) Attributions(childName string) (map[string]map[string]int64, error) {
	return attributionValues(m.db, childName)
}

// attributionValues returns parent -> {mpaKey -> attributed value} for a child.
func attributionValues(tx *gorm.DB, childName string) (map[string]map[string]int64, error) {
	var rows []LotParentAttribution
	if err := tx.Where("child_lot_name = ?", childName).Find(&rows).Error; err != nil {
		return nil, wrap(err, "loading attributions")
	}
	out := map[string]map[string]int64{}
	for _, r := range rows {
		if out[r.ParentLotName] == nil {
			out[r.ParentLotName] = map[string]int64{}
		}
		out[r.ParentLotName][r.MpaKey] = r.AttributedValue
	}
	return out, nil
}

// nonSelfParentNames returns the lot's parents excluding itself.
func nonSelfParentNames(tx *gorm.DB, lotName string) ([]string, error) {
	var edges []LotParent
	if err := tx.Where("lot_name = ? AND parent != ?", lotName, lotName).Find(&edges).Error; err != nil {
		return nil, wrap(err, "loading parents")
	}
	out := make([]string, 0, len(edges))
	for _, e := range edges {
		out = append(out, e.Parent)
	}
	return out, nil
}

// directChildNames returns the lot's direct children excluding itself.
func directChildNames(tx *gorm.DB, lotName string) ([]string, error) {
	var edges []LotParent
	if err := tx.Where("parent = ? AND lot_name != ?", lotName, lotName).Find(&edges).Error; err != nil {
		return nil, wrap(err, "loading children")
	}
	out := make([]string, 0, len(edges))
	for _, e := range edges {
		out = append(out, e.LotName)
	}
	return out, nil
}

// validateAxioms runs the strict-hierarchy axioms for a lot, and (when
// checkChildren is set, e.g. after an MPA change) for each of its direct
// children too. A no-op when strict hierarchy is disabled.
func (m *Manager) validateAxioms(tx *gorm.DB, lotName string, checkChildren bool) error {
	if !m.opts.StrictHierarchy {
		return nil
	}
	now := m.nowMs()
	if err := m.validateAxiom1(tx, lotName); err != nil {
		return err
	}
	if err := m.validateAxiom2(tx, lotName, now); err != nil {
		return err
	}
	if err := m.validateAxiom3(tx, lotName); err != nil {
		return err
	}
	if checkChildren {
		children, err := directChildNames(tx, lotName)
		if err != nil {
			return err
		}
		for _, c := range children {
			if err := m.validateAxiom1(tx, c); err != nil {
				return err
			}
			if err := m.validateAxiom2(tx, c, now); err != nil {
				return err
			}
			if err := m.validateAxiom3(tx, c); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateAxiom1: each parent's attributed share of the child must not exceed
// the parent's own MPA, per axis.
func (m *Manager) validateAxiom1(tx *gorm.DB, childName string) error {
	child, err := m.loadLot(tx, childName)
	if err != nil {
		return err
	}
	if isPartialStorageSentinel(child.DedicatedBytes, child.OpportunisticBytes) {
		return nil // defer transient state
	}
	childUnbDed := IsUnboundedBytes(child.DedicatedBytes)
	childUnbOpp := IsUnboundedBytes(child.OpportunisticBytes)
	childUnbObj := IsUnboundedObjects(child.MaxNumObjects)

	parents, err := nonSelfParentNames(tx, childName)
	if err != nil {
		return err
	}
	vals, err := attributionValues(tx, childName)
	if err != nil {
		return err
	}
	for _, pn := range parents {
		pv, ok := vals[pn]
		if !ok {
			return wrapf(ErrInvalidLot, "missing attribution rows for child %q under parent %q", childName, pn)
		}
		parent, err := m.loadLot(tx, pn)
		if err != nil {
			return err
		}
		if isPartialStorageSentinel(parent.DedicatedBytes, parent.OpportunisticBytes) {
			continue
		}
		pUnbDed := IsUnboundedBytes(parent.DedicatedBytes)
		pUnbOpp := IsUnboundedBytes(parent.OpportunisticBytes)
		pUnbObj := IsUnboundedObjects(parent.MaxNumObjects)

		if childUnbDed && !pUnbDed {
			return wrapf(ErrInvalidLot, "child %q has unbounded dedicated_bytes but parent %q is bounded", childName, pn)
		}
		if childUnbOpp && !pUnbOpp {
			return wrapf(ErrInvalidLot, "child %q has unbounded opportunistic_bytes but parent %q is bounded", childName, pn)
		}
		if childUnbObj && !pUnbObj {
			return wrapf(ErrInvalidLot, "child %q has unbounded max_num_objects but parent %q is bounded", childName, pn)
		}

		if !pUnbDed && pv[MpaKeyDedicatedBytes] > parent.DedicatedBytes {
			return wrapf(ErrInvalidLot, "child %q attributes %d dedicated_bytes to parent %q exceeding its %d", childName, pv[MpaKeyDedicatedBytes], pn, parent.DedicatedBytes)
		}
		if !pUnbOpp && pv[MpaKeyOpportunisticBytes] > parent.OpportunisticBytes {
			return wrapf(ErrInvalidLot, "child %q attributes %d opportunistic_bytes to parent %q exceeding its %d", childName, pv[MpaKeyOpportunisticBytes], pn, parent.OpportunisticBytes)
		}
		if !pUnbObj && pv[MpaKeyMaxNumObjects] > parent.MaxNumObjects {
			return wrapf(ErrInvalidLot, "child %q attributes %d max_num_objects to parent %q exceeding its %d", childName, pv[MpaKeyMaxNumObjects], pn, parent.MaxNumObjects)
		}
	}
	return nil
}

// validateAxiom2: for each parent, the peak concurrent attributed usage across
// its children (sweep-line over their active windows) must not exceed the
// parent's MPA, per axis.
func (m *Manager) validateAxiom2(tx *gorm.DB, childName string, nowMs int64) error {
	parents, err := nonSelfParentNames(tx, childName)
	if err != nil {
		return err
	}
	for _, pn := range parents {
		parent, err := m.loadLot(tx, pn)
		if err != nil {
			return err
		}
		if isPartialStorageSentinel(parent.DedicatedBytes, parent.OpportunisticBytes) {
			continue
		}
		pUnbDed := IsUnboundedBytes(parent.DedicatedBytes)
		pUnbOpp := IsUnboundedBytes(parent.OpportunisticBytes)
		pUnbObj := IsUnboundedObjects(parent.MaxNumObjects)
		if pUnbDed && pUnbOpp && pUnbObj {
			continue
		}
		events, err := m.buildAttributionEvents(tx, pn, 0, 0, nowMs)
		if err != nil {
			return err
		}
		peak := runSweepLine(events)
		if !pUnbDed && peak.ded > parent.DedicatedBytes {
			return wrapf(ErrInvalidLot, "peak concurrent dedicated_bytes across children of %q is %d exceeding its %d", pn, peak.ded, parent.DedicatedBytes)
		}
		if !pUnbOpp && peak.opp > parent.OpportunisticBytes {
			return wrapf(ErrInvalidLot, "peak concurrent opportunistic_bytes across children of %q is %d exceeding its %d", pn, peak.opp, parent.OpportunisticBytes)
		}
		if !pUnbObj && peak.obj > parent.MaxNumObjects {
			return wrapf(ErrInvalidLot, "peak concurrent max_num_objects across children of %q is %d exceeding its %d", pn, peak.obj, parent.MaxNumObjects)
		}
	}
	return nil
}

// validateAxiom3: a child's lifecycle window must fit within every parent's.
func (m *Manager) validateAxiom3(tx *gorm.DB, childName string) error {
	child, err := m.loadLot(tx, childName)
	if err != nil {
		return err
	}
	childNonExpiring := IsNonExpiring(child.CreationTime, child.ExpirationTime, child.DeletionTime)
	childPartialZero := !childNonExpiring && (child.CreationTime == 0 || child.ExpirationTime == 0 || child.DeletionTime == 0)
	if childPartialZero {
		return nil // defer
	}
	parents, err := nonSelfParentNames(tx, childName)
	if err != nil {
		return err
	}
	for _, pn := range parents {
		parent, err := m.loadLot(tx, pn)
		if err != nil {
			return err
		}
		parentNonExpiring := IsNonExpiring(parent.CreationTime, parent.ExpirationTime, parent.DeletionTime)
		parentPartialZero := !parentNonExpiring && (parent.CreationTime == 0 || parent.ExpirationTime == 0 || parent.DeletionTime == 0)
		if parentPartialZero {
			continue
		}
		if parentNonExpiring {
			continue
		}
		if childNonExpiring {
			return wrapf(ErrInvalidLot, "non-expiring child %q cannot fit inside finite parent %q", childName, pn)
		}
		if child.CreationTime < parent.CreationTime {
			return wrapf(ErrInvalidLot, "child %q creation_time %d precedes parent %q creation_time %d", childName, child.CreationTime, pn, parent.CreationTime)
		}
		if child.ExpirationTime > parent.ExpirationTime {
			return wrapf(ErrInvalidLot, "child %q expiration_time %d exceeds parent %q expiration_time %d", childName, child.ExpirationTime, pn, parent.ExpirationTime)
		}
		if child.DeletionTime > parent.DeletionTime {
			return wrapf(ErrInvalidLot, "child %q deletion_time %d exceeds parent %q deletion_time %d", childName, child.DeletionTime, pn, parent.DeletionTime)
		}
	}
	return nil
}

// sweepEvent is a start (+delta) or end (-delta) of a child's attributed
// contribution to a parent.
type sweepEvent struct {
	time    int64
	dDed    int64
	dOpp    int64
	dObj    int64
	isStart bool
}

type sweepPeak struct {
	ded, opp, obj, total int64
}

// buildAttributionEvents constructs sweep-line events from a parent's children's
// attributions, optionally clipped to [startMs, endMs). Reclaimed and
// non-overlapping children are skipped; unbounded axes contribute zero.
func (m *Manager) buildAttributionEvents(tx *gorm.DB, parentName string, startMs, endMs, nowMs int64) ([]sweepEvent, error) {
	hasWindow := startMs < endMs
	children, err := directChildNames(tx, parentName)
	if err != nil {
		return nil, err
	}
	var events []sweepEvent
	for _, cn := range children {
		child, err := m.loadLot(tx, cn)
		if err != nil {
			return nil, err
		}
		reclaimed, err := m.isReclaimedAtTx(tx, cn, nowMs)
		if err != nil {
			return nil, err
		}
		if reclaimed {
			continue
		}
		nonExpiring := IsNonExpiring(child.CreationTime, child.ExpirationTime, child.DeletionTime)
		if !nonExpiring && hasWindow && (child.CreationTime >= endMs || child.ExpirationTime <= startMs) {
			continue
		}
		vals, err := attributionValues(tx, cn)
		if err != nil {
			return nil, err
		}
		pv := vals[parentName]
		if pv == nil {
			if m.opts.StrictHierarchy {
				return nil, wrapf(ErrInvalidLot, "missing attribution rows for child %q under parent %q", cn, parentName)
			}
			pv = map[string]int64{}
		}
		var dDed, dOpp, dObj int64
		if !IsUnboundedBytes(child.DedicatedBytes) {
			dDed = pv[MpaKeyDedicatedBytes]
		}
		if !IsUnboundedBytes(child.OpportunisticBytes) {
			dOpp = pv[MpaKeyOpportunisticBytes]
		}
		if !IsUnboundedObjects(child.MaxNumObjects) {
			dObj = pv[MpaKeyMaxNumObjects]
		}

		evStart := child.CreationTime
		evEnd := child.ExpirationTime
		if nonExpiring {
			evStart = math.MinInt64
			evEnd = math.MaxInt64
		}
		if hasWindow {
			if evStart < startMs {
				evStart = startMs
			}
			if evEnd > endMs {
				evEnd = endMs
			}
		}
		events = append(events,
			sweepEvent{time: evStart, dDed: dDed, dOpp: dOpp, dObj: dObj, isStart: true},
			sweepEvent{time: evEnd, dDed: -dDed, dOpp: -dOpp, dObj: -dObj, isStart: false},
		)
	}
	return events, nil
}

// runSweepLine accumulates events in time order (removals before additions at
// the same instant, preserving half-open intervals) and returns the peak
// concurrent values.
func runSweepLine(events []sweepEvent) sweepPeak {
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].time != events[j].time {
			return events[i].time < events[j].time
		}
		// removal (false) sorts before addition (true)
		return !events[i].isStart && events[j].isStart
	})
	var curDed, curOpp, curObj int64
	var peak sweepPeak
	for _, ev := range events {
		curDed += ev.dDed
		curOpp += ev.dOpp
		curObj += ev.dObj
		if curDed > peak.ded {
			peak.ded = curDed
		}
		if curOpp > peak.opp {
			peak.opp = curOpp
		}
		if curObj > peak.obj {
			peak.obj = curObj
		}
		if curDed+curOpp > peak.total {
			peak.total = curDed + curOpp
		}
	}
	return peak
}

// isReclaimedAtTx is isReclaimedAt scoped to a transaction.
func (m *Manager) isReclaimedAtTx(tx *gorm.DB, name string, t int64) (bool, error) {
	var recs []LotReclamation
	if err := tx.Where("lot_name = ?", name).Limit(1).Find(&recs).Error; err != nil {
		return false, wrap(err, "checking reclamation")
	}
	if len(recs) == 0 {
		return false, nil
	}
	return recs[0].ReclaimedAt <= t, nil
}

// AvailableCapacity reports the advisory remaining capacity under a parent over
// the window [startMs, endMs), accounting for children's attributed allocations
// via a sweep-line. Unbounded axes report nil.
type AvailableCapacity struct {
	AvailableDedicatedBytes     *int64
	AvailableOpportunisticBytes *int64
	AvailableTotalBytes         *int64
	AvailableMaxNumObjects      *int64
	PeakDedicatedBytes          int64
	PeakOpportunisticBytes      int64
	PeakMaxNumObjects           int64
	PeakTotalBytes              int64
}

// AvailableCapacity computes advisory capacity under parentName for the window.
func (m *Manager) AvailableCapacity(parentName string, startMs, endMs int64) (*AvailableCapacity, error) {
	parent, err := m.loadLot(m.db, parentName)
	if err != nil {
		return nil, err
	}
	events, err := m.buildAttributionEvents(m.db, parentName, startMs, endMs, m.nowMs())
	if err != nil {
		return nil, err
	}
	peak := runSweepLine(events)

	pUnbDed := IsUnboundedBytes(parent.DedicatedBytes)
	pUnbOpp := IsUnboundedBytes(parent.OpportunisticBytes)
	pUnbObj := IsUnboundedObjects(parent.MaxNumObjects)

	out := &AvailableCapacity{
		PeakDedicatedBytes:     peak.ded,
		PeakOpportunisticBytes: peak.opp,
		PeakMaxNumObjects:      peak.obj,
		PeakTotalBytes:         peak.total,
	}
	if !pUnbDed {
		v := parent.DedicatedBytes - peak.ded
		out.AvailableDedicatedBytes = &v
	}
	if !pUnbOpp {
		v := parent.OpportunisticBytes - peak.opp
		out.AvailableOpportunisticBytes = &v
	}
	if !pUnbDed && !pUnbOpp {
		v := (parent.DedicatedBytes + parent.OpportunisticBytes) - peak.total
		out.AvailableTotalBytes = &v
	}
	if !pUnbObj {
		v := parent.MaxNumObjects - peak.obj
		out.AvailableMaxNumObjects = &v
	}
	return out, nil
}

// PolicyAttrsRequest selects which restrictive policy attributes to return.
type PolicyAttrsRequest struct {
	LotName   string
	Recursive bool
	Keys      []string // MPA keys; empty means all six
}

// RestrictiveValue is the most-restrictive (numerically smallest) value for an
// axis and the lot that imposes it.
type RestrictiveValue struct {
	LotName string
	Value   int64
}

// allPolicyKeys are the six attributes PolicyAttributes can report.
var allPolicyKeys = []string{
	MpaKeyDedicatedBytes, MpaKeyOpportunisticBytes, MpaKeyMaxNumObjects,
	"creation_time", "expiration_time", "deletion_time",
}

// PolicyAttributes returns, per requested key, the most restrictive value among
// the lot and (when recursive) its ancestors, and which lot imposes it. Note:
// values are compared numerically (matching the reference), so the unbounded
// sentinel (-1) compares as smallest; callers should interpret -1 as unbounded.
func (m *Manager) PolicyAttributes(req PolicyAttrsRequest) (map[string]RestrictiveValue, error) {
	lot, err := m.loadLot(m.db, req.LotName)
	if err != nil {
		return nil, err
	}
	keys := req.Keys
	if len(keys) == 0 {
		keys = allPolicyKeys
	}

	lots := []*Lot{lot}
	if req.Recursive {
		ancestors, err := m.GetParents(req.LotName, true, false)
		if err != nil {
			return nil, err
		}
		for _, a := range ancestors {
			al, err := m.loadLot(m.db, a)
			if err != nil {
				return nil, err
			}
			lots = append(lots, al)
		}
	}

	out := map[string]RestrictiveValue{}
	for _, key := range keys {
		best := RestrictiveValue{LotName: lot.LotName, Value: policyKeyValue(*lot, key)}
		for _, l := range lots[1:] {
			v := policyKeyValue(*l, key)
			if v < best.Value {
				best = RestrictiveValue{LotName: l.LotName, Value: v}
			}
		}
		out[key] = best
	}
	return out, nil
}

func policyKeyValue(l Lot, key string) int64 {
	switch key {
	case MpaKeyDedicatedBytes:
		return l.DedicatedBytes
	case MpaKeyOpportunisticBytes:
		return l.OpportunisticBytes
	case MpaKeyMaxNumObjects:
		return l.MaxNumObjects
	case "creation_time":
		return l.CreationTime
	case "expiration_time":
		return l.ExpirationTime
	case "deletion_time":
		return l.DeletionTime
	}
	return 0
}
