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

const fpTol = 1e-9

// mpaKeys are the three axes that carry parent attributions.
var mpaKeys = []string{MpaKeyDedicatedGB, MpaKeyOpportunisticGB, MpaKeyMaxNumObjects}

// isPartialStorageSentinel reports the transient mid-update state where
// dedicated is unbounded but opportunistic is not (an invalid persisting state,
// but tolerated during a multi-field update so axiom checks defer to the final
// invariant check).
func isPartialStorageSentinel(dedicated, opportunistic float64) bool {
	return IsUnboundedGB(dedicated) && !IsUnboundedGB(opportunistic)
}

// mpaAxisValue returns the MPA value for an attribution axis as a float.
func mpaAxisValue(mpa MPA, key string) float64 {
	switch key {
	case MpaKeyDedicatedGB:
		return mpa.DedicatedGB
	case MpaKeyOpportunisticGB:
		return mpa.OpportunisticGB
	case MpaKeyMaxNumObjects:
		return float64(mpa.MaxNumObjects)
	}
	return 0
}

// explicitAttr returns the explicit attributed value for an axis, if specified.
func explicitAttr(pa ParentAttribution, key string) (float64, bool) {
	switch key {
	case MpaKeyDedicatedGB:
		if pa.DedicatedGB != nil {
			return *pa.DedicatedGB, true
		}
	case MpaKeyOpportunisticGB:
		if pa.OpportunisticGB != nil {
			return *pa.OpportunisticGB, true
		}
	case MpaKeyMaxNumObjects:
		if pa.MaxNumObjects != nil {
			return float64(*pa.MaxNumObjects), true
		}
	}
	return 0, false
}

// computeAndStoreAttributions distributes the lot's MPA across its non-self
// parents as fractions and persists them, replacing any existing attribution
// rows. Root/self-only lots have nothing to attribute. Ported from the
// reference compute_and_store_attributions.
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

		// Unbounded child: propagate the unbounded designation to every parent
		// with fraction 1.0 (downstream reconstructs child.mpa * 1.0 == -1).
		if total == -1 {
			for _, p := range nonSelf {
				if err := storeAttribution(tx, lotName, p, key, 1.0); err != nil {
					return err
				}
			}
			continue
		}

		explicitlyAttributed := 0.0
		var unspecified []string
		for _, p := range nonSelf {
			val, ok := false, false
			var ev float64
			if pa, present := attrs[p]; present {
				ev, ok = explicitAttr(pa, key)
				val = ok
			}
			if val {
				frac := 0.0
				if total > 0 {
					frac = ev / total
				}
				if err := storeAttribution(tx, lotName, p, key, frac); err != nil {
					return err
				}
				explicitlyAttributed += ev
			} else {
				unspecified = append(unspecified, p)
			}
		}

		if len(unspecified) == 0 && total > 0 {
			if total-explicitlyAttributed > fpTol {
				return wrapf(ErrInvalidLot, "explicit attributions for %q sum to %v but total is %v (shortfall, no parent to absorb)", key, explicitlyAttributed, total)
			}
			if explicitlyAttributed-total > fpTol {
				return wrapf(ErrInvalidLot, "explicit attributions for %q sum to %v which exceeds total %v (double-count)", key, explicitlyAttributed, total)
			}
		}

		if len(unspecified) > 0 {
			remainder := total - explicitlyAttributed
			if remainder < -fpTol {
				return wrapf(ErrInvalidLot, "explicit attributions for %q exceed the total allocation", key)
			}
			if remainder < 0 {
				remainder = 0
			}
			n := int64(len(unspecified))
			perParent := remainder / float64(len(unspecified))
			var intPer, intExtra int64
			if key == MpaKeyMaxNumObjects {
				ir := int64(remainder)
				intPer = ir / n
				intExtra = ir % n
			}
			for i, p := range unspecified {
				value := perParent
				if key == MpaKeyMaxNumObjects {
					value = float64(intPer)
					if int64(i) < intExtra {
						value++
					}
				}
				frac := 0.0
				if total > 0 {
					frac = value / total
				}
				if err := storeAttribution(tx, lotName, p, key, frac); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func storeAttribution(tx *gorm.DB, child, parent, key string, fraction float64) error {
	row := LotParentAttribution{ChildLotName: child, ParentLotName: parent, MpaKey: key, Fraction: fraction}
	if err := tx.Create(&row).Error; err != nil {
		return wrap(err, "storing attribution")
	}
	return nil
}

// attributionFractions returns parent -> {mpaKey -> fraction} for a child.
func attributionFractions(tx *gorm.DB, childName string) (map[string]map[string]float64, error) {
	var rows []LotParentAttribution
	if err := tx.Where("child_lot_name = ?", childName).Find(&rows).Error; err != nil {
		return nil, wrap(err, "loading attributions")
	}
	out := map[string]map[string]float64{}
	for _, r := range rows {
		if out[r.ParentLotName] == nil {
			out[r.ParentLotName] = map[string]float64{}
		}
		out[r.ParentLotName][r.MpaKey] = r.Fraction
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
	if isPartialStorageSentinel(child.DedicatedGB, child.OpportunisticGB) {
		return nil // defer transient state
	}
	childUnbDed := IsUnboundedGB(child.DedicatedGB)
	childUnbOpp := IsUnboundedGB(child.OpportunisticGB)
	childUnbObj := IsUnboundedObjects(child.MaxNumObjects)

	parents, err := nonSelfParentNames(tx, childName)
	if err != nil {
		return err
	}
	fracs, err := attributionFractions(tx, childName)
	if err != nil {
		return err
	}
	for _, pn := range parents {
		pf, ok := fracs[pn]
		if !ok {
			return wrapf(ErrInvalidLot, "missing attribution rows for child %q under parent %q", childName, pn)
		}
		parent, err := m.loadLot(tx, pn)
		if err != nil {
			return err
		}
		if isPartialStorageSentinel(parent.DedicatedGB, parent.OpportunisticGB) {
			continue
		}
		pUnbDed := IsUnboundedGB(parent.DedicatedGB)
		pUnbOpp := IsUnboundedGB(parent.OpportunisticGB)
		pUnbObj := IsUnboundedObjects(parent.MaxNumObjects)

		if childUnbDed && !pUnbDed {
			return wrapf(ErrInvalidLot, "child %q has unbounded dedicated_GB but parent %q is bounded", childName, pn)
		}
		if childUnbOpp && !pUnbOpp {
			return wrapf(ErrInvalidLot, "child %q has unbounded opportunistic_GB but parent %q is bounded", childName, pn)
		}
		if childUnbObj && !pUnbObj {
			return wrapf(ErrInvalidLot, "child %q has unbounded max_num_objects but parent %q is bounded", childName, pn)
		}

		attrDed := pf[MpaKeyDedicatedGB] * child.DedicatedGB
		attrOpp := pf[MpaKeyOpportunisticGB] * child.OpportunisticGB
		attrObj := math.Round(pf[MpaKeyMaxNumObjects] * float64(child.MaxNumObjects))

		if !pUnbDed && attrDed > parent.DedicatedGB+fpTol {
			return wrapf(ErrInvalidLot, "child %q attributes %v dedicated_GB to parent %q exceeding its %v", childName, attrDed, pn, parent.DedicatedGB)
		}
		if !pUnbOpp && attrOpp > parent.OpportunisticGB+fpTol {
			return wrapf(ErrInvalidLot, "child %q attributes %v opportunistic_GB to parent %q exceeding its %v", childName, attrOpp, pn, parent.OpportunisticGB)
		}
		if !pUnbObj && int64(attrObj) > parent.MaxNumObjects {
			return wrapf(ErrInvalidLot, "child %q attributes %d max_num_objects to parent %q exceeding its %d", childName, int64(attrObj), pn, parent.MaxNumObjects)
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
		if isPartialStorageSentinel(parent.DedicatedGB, parent.OpportunisticGB) {
			continue
		}
		pUnbDed := IsUnboundedGB(parent.DedicatedGB)
		pUnbOpp := IsUnboundedGB(parent.OpportunisticGB)
		pUnbObj := IsUnboundedObjects(parent.MaxNumObjects)
		if pUnbDed && pUnbOpp && pUnbObj {
			continue
		}
		events, err := m.buildAttributionEvents(tx, pn, 0, 0, nowMs)
		if err != nil {
			return err
		}
		peak := runSweepLine(events)
		if !pUnbDed && peak.ded > parent.DedicatedGB+fpTol {
			return wrapf(ErrInvalidLot, "peak concurrent dedicated_GB across children of %q is %v exceeding its %v", pn, peak.ded, parent.DedicatedGB)
		}
		if !pUnbOpp && peak.opp > parent.OpportunisticGB+fpTol {
			return wrapf(ErrInvalidLot, "peak concurrent opportunistic_GB across children of %q is %v exceeding its %v", pn, peak.opp, parent.OpportunisticGB)
		}
		if !pUnbObj && int64(math.Round(peak.obj)) > parent.MaxNumObjects {
			return wrapf(ErrInvalidLot, "peak concurrent max_num_objects across children of %q is %d exceeding its %d", pn, int64(math.Round(peak.obj)), parent.MaxNumObjects)
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
	dDed    float64
	dOpp    float64
	dObj    float64
	isStart bool
}

type sweepPeak struct {
	ded, opp, obj, total float64
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
		fracs, err := attributionFractions(tx, cn)
		if err != nil {
			return nil, err
		}
		pf := fracs[parentName]
		if pf == nil {
			if m.opts.StrictHierarchy {
				return nil, wrapf(ErrInvalidLot, "missing attribution rows for child %q under parent %q", cn, parentName)
			}
			pf = map[string]float64{}
		}
		var dDed, dOpp, dObj float64
		if !IsUnboundedGB(child.DedicatedGB) {
			dDed = pf[MpaKeyDedicatedGB] * child.DedicatedGB
		}
		if !IsUnboundedGB(child.OpportunisticGB) {
			dOpp = pf[MpaKeyOpportunisticGB] * child.OpportunisticGB
		}
		if !IsUnboundedObjects(child.MaxNumObjects) {
			dObj = math.Round(pf[MpaKeyMaxNumObjects] * float64(child.MaxNumObjects))
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
	var curDed, curOpp, curObj float64
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
	AvailableDedicatedGB     *float64
	AvailableOpportunisticGB *float64
	AvailableTotalGB         *float64
	AvailableMaxNumObjects   *int64
	PeakDedicatedGB          float64
	PeakOpportunisticGB      float64
	PeakMaxNumObjects        int64
	PeakTotalGB              float64
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

	pUnbDed := IsUnboundedGB(parent.DedicatedGB)
	pUnbOpp := IsUnboundedGB(parent.OpportunisticGB)
	pUnbObj := IsUnboundedObjects(parent.MaxNumObjects)

	out := &AvailableCapacity{
		PeakDedicatedGB:     peak.ded,
		PeakOpportunisticGB: peak.opp,
		PeakMaxNumObjects:   int64(peak.obj),
		PeakTotalGB:         peak.total,
	}
	if !pUnbDed {
		v := parent.DedicatedGB - peak.ded
		out.AvailableDedicatedGB = &v
	}
	if !pUnbOpp {
		v := parent.OpportunisticGB - peak.opp
		out.AvailableOpportunisticGB = &v
	}
	if !pUnbDed && !pUnbOpp {
		v := (parent.DedicatedGB + parent.OpportunisticGB) - peak.total
		out.AvailableTotalGB = &v
	}
	if !pUnbObj {
		v := parent.MaxNumObjects - int64(peak.obj)
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
	Value   float64
}

// allPolicyKeys are the six attributes get_policy_attributes can report.
var allPolicyKeys = []string{
	MpaKeyDedicatedGB, MpaKeyOpportunisticGB, MpaKeyMaxNumObjects,
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

func policyKeyValue(l Lot, key string) float64 {
	switch key {
	case MpaKeyDedicatedGB:
		return l.DedicatedGB
	case MpaKeyOpportunisticGB:
		return l.OpportunisticGB
	case MpaKeyMaxNumObjects:
		return float64(l.MaxNumObjects)
	case "creation_time":
		return float64(l.CreationTime)
	case "expiration_time":
		return float64(l.ExpirationTime)
	case "deletion_time":
		return float64(l.DeletionTime)
	}
	return 0
}
