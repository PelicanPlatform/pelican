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
	"gorm.io/gorm"
)

// UsageUpdate reports a lot's own ("self") usage. Nil fields are left
// unchanged. In delta mode each value is added to the current value (and may be
// negative, as long as the result is non-negative); in absolute mode each value
// replaces the current value (and must be non-negative).
type UsageUpdate struct {
	LotName                 string
	SelfGB                  *float64
	SelfObjects             *int64
	SelfGBBeingWritten      *float64
	SelfObjectsBeingWritten *int64
}

// DirUsage reports usage for a path. UpdateLotUsageByDir resolves the path to
// its owning lot (attribution semantics) before applying.
type DirUsage struct {
	Path       string
	SizeGB     float64
	NumObjects int64
}

// UsageReport is the result of GetLotUsage: per-axis self/children/total usage.
type UsageReport struct {
	LotName string

	SelfGB     float64
	ChildrenGB float64
	TotalGB    float64

	SelfObjects     int64
	ChildrenObjects int64
	TotalObjects    int64

	SelfGBBeingWritten     float64
	ChildrenGBBeingWritten float64
	TotalGBBeingWritten    float64

	SelfObjectsBeingWritten     int64
	ChildrenObjectsBeingWritten int64
	TotalObjectsBeingWritten    int64
}

// UpdateLotUsage applies a self-usage update to a lot and recomputes the
// children rollup for the lot's ancestors so the result is consistent. The
// caller must own the lot or a parent (empty caller = trusted/system, used by
// the cache usage reconciler).
func (m *Manager) UpdateLotUsage(u UsageUpdate, delta bool, caller string) error {
	return m.db.Transaction(func(tx *gorm.DB) error {
		lot, err := m.loadLot(tx, u.LotName)
		if err != nil {
			return err
		}
		if err := m.authorizeModify(tx, *lot, caller); err != nil {
			return err
		}
		if err := applySelfUsage(tx, u, delta); err != nil {
			return err
		}
		// Only the lot's ancestors can have a changed children rollup.
		ancestors, err := ancestorsVia(tx, u.LotName)
		if err != nil {
			return err
		}
		for _, a := range ancestors {
			if err := recalcChildren(tx, a); err != nil {
				return err
			}
		}
		return nil
	})
}

// UpdateLotUsageByDir resolves each path entry to its owning lot (attribution
// semantics at atMs), aggregates usage per lot, applies it, and recomputes
// rollups. In absolute mode each resolved lot's self usage is set to the
// aggregated total for that lot; lots not referenced are left untouched.
func (m *Manager) UpdateLotUsageByDir(entries []DirUsage, delta bool, atMs int64, caller string) error {
	type agg struct {
		gb  float64
		obj int64
	}
	perLot := map[string]*agg{}
	for _, e := range entries {
		lots, err := m.lotsFromDir(e.Path, false, atMs, true)
		if err != nil {
			return err
		}
		lot := lots[0]
		a := perLot[lot]
		if a == nil {
			a = &agg{}
			perLot[lot] = a
		}
		a.gb += e.SizeGB
		a.obj += e.NumObjects
	}
	for lot, a := range perLot {
		if lot == "default" {
			// The default lot has no usage row unless it was created; skip if
			// absent rather than failing the whole batch.
			if ok, err := m.LotExists(lot); err != nil {
				return err
			} else if !ok {
				continue
			}
		}
		gb, obj := a.gb, a.obj
		if err := m.UpdateLotUsage(UsageUpdate{LotName: lot, SelfGB: &gb, SelfObjects: &obj}, delta, caller); err != nil {
			return err
		}
	}
	return nil
}

// GetLotUsage returns the self/children/total usage for a lot. The children
// values reflect the last rollup recomputation.
func (m *Manager) GetLotUsage(lotName string) (*UsageReport, error) {
	if ok, err := m.LotExists(lotName); err != nil {
		return nil, err
	} else if !ok {
		return nil, ErrLotNotFound
	}
	var u LotUsage
	var usages []LotUsage
	if err := m.db.Where("lot_name = ?", lotName).Limit(1).Find(&usages).Error; err != nil {
		return nil, wrap(err, "loading usage")
	}
	if len(usages) > 0 {
		u = usages[0]
	}
	return &UsageReport{
		LotName:                     lotName,
		SelfGB:                      u.SelfGB,
		ChildrenGB:                  u.ChildrenGB,
		TotalGB:                     u.SelfGB + u.ChildrenGB,
		SelfObjects:                 u.SelfObjects,
		ChildrenObjects:             u.ChildrenObjects,
		TotalObjects:                u.SelfObjects + u.ChildrenObjects,
		SelfGBBeingWritten:          u.SelfGBBeingWritten,
		ChildrenGBBeingWritten:      u.ChildrenGBBeingWritten,
		TotalGBBeingWritten:         u.SelfGBBeingWritten + u.ChildrenGBBeingWritten,
		SelfObjectsBeingWritten:     u.SelfObjectsBeingWritten,
		ChildrenObjectsBeingWritten: u.ChildrenObjectsBeingWritten,
		TotalObjectsBeingWritten:    u.SelfObjectsBeingWritten + u.ChildrenObjectsBeingWritten,
	}, nil
}

// RecalculateChildrenUsage recomputes the children rollup for every lot. Use
// after a batch of self-usage updates or to repair drift.
func (m *Manager) RecalculateChildrenUsage() error {
	return m.db.Transaction(func(tx *gorm.DB) error {
		var names []string
		if err := tx.Model(&Lot{}).Pluck("lot_name", &names).Error; err != nil {
			return wrap(err, "listing lots")
		}
		for _, name := range names {
			if err := recalcChildren(tx, name); err != nil {
				return err
			}
		}
		return nil
	})
}

// applySelfUsage writes the self-usage columns named in u, validating that no
// value goes negative.
func applySelfUsage(tx *gorm.DB, u UsageUpdate, delta bool) error {
	var usages []LotUsage
	if err := tx.Where("lot_name = ?", u.LotName).Limit(1).Find(&usages).Error; err != nil {
		return wrap(err, "loading current usage")
	}
	cur := LotUsage{LotName: u.LotName}
	if len(usages) > 0 {
		cur = usages[0]
	}

	fields := map[string]any{}
	if u.SelfGB != nil {
		nv, err := newFloat(cur.SelfGB, *u.SelfGB, delta)
		if err != nil {
			return wrapf(err, "self_gb")
		}
		fields["self_gb"] = nv
	}
	if u.SelfObjects != nil {
		nv, err := newInt(cur.SelfObjects, *u.SelfObjects, delta)
		if err != nil {
			return wrapf(err, "self_objects")
		}
		fields["self_objects"] = nv
	}
	if u.SelfGBBeingWritten != nil {
		nv, err := newFloat(cur.SelfGBBeingWritten, *u.SelfGBBeingWritten, delta)
		if err != nil {
			return wrapf(err, "self_gb_being_written")
		}
		fields["self_gb_being_written"] = nv
	}
	if u.SelfObjectsBeingWritten != nil {
		nv, err := newInt(cur.SelfObjectsBeingWritten, *u.SelfObjectsBeingWritten, delta)
		if err != nil {
			return wrapf(err, "self_objects_being_written")
		}
		fields["self_objects_being_written"] = nv
	}
	if len(fields) == 0 {
		return nil
	}
	// Ensure the row exists (lots created via AddLot always have one, but be
	// defensive for usage updates against externally-inserted lots).
	if len(usages) == 0 {
		if err := tx.Create(&LotUsage{LotName: u.LotName}).Error; err != nil {
			return wrap(err, "creating usage row")
		}
	}
	if err := tx.Model(&LotUsage{}).Where("lot_name = ?", u.LotName).Updates(fields).Error; err != nil {
		return wrap(err, "updating self usage")
	}
	return nil
}

func newFloat(current, val float64, delta bool) (float64, error) {
	if delta {
		nv := current + val
		if nv < 0 {
			return 0, wrapf(ErrInvalidLot, "delta update would store a negative value (%v)", nv)
		}
		return nv, nil
	}
	if val < 0 {
		return 0, wrapf(ErrInvalidLot, "absolute usage value must be non-negative (%v)", val)
	}
	return val, nil
}

func newInt(current, val int64, delta bool) (int64, error) {
	if delta {
		nv := current + val
		if nv < 0 {
			return 0, wrapf(ErrInvalidLot, "delta update would store a negative value (%d)", nv)
		}
		return nv, nil
	}
	if val < 0 {
		return 0, wrapf(ErrInvalidLot, "absolute usage value must be non-negative (%d)", val)
	}
	return val, nil
}

// recalcChildren sets a lot's children_* columns to the sum of its recursive
// descendants' self_* values, excluding any descendant with a reclamation row
// (matching the reference's "as of now" rollup semantics).
func recalcChildren(tx *gorm.DB, name string) error {
	descendants, err := descendantsVia(tx, name)
	if err != nil {
		return err
	}
	var sums struct {
		GB   float64 `gorm:"column:gb"`
		GBW  float64 `gorm:"column:gbw"`
		Obj  int64   `gorm:"column:obj"`
		ObjW int64   `gorm:"column:objw"`
	}
	if len(descendants) > 0 {
		err := tx.Table("lot_usage AS lu").
			Select("COALESCE(SUM(lu.self_gb),0) AS gb, COALESCE(SUM(lu.self_gb_being_written),0) AS gbw, "+
				"COALESCE(SUM(lu.self_objects),0) AS obj, COALESCE(SUM(lu.self_objects_being_written),0) AS objw").
			Joins("LEFT JOIN lot_reclamations r ON r.lot_name = lu.lot_name").
			Where("r.lot_name IS NULL AND lu.lot_name IN ?", descendants).
			Scan(&sums).Error
		if err != nil {
			return wrap(err, "summing child usage")
		}
	}
	fields := map[string]any{
		"children_gb":                    sums.GB,
		"children_gb_being_written":      sums.GBW,
		"children_objects":               sums.Obj,
		"children_objects_being_written": sums.ObjW,
	}
	if err := tx.Model(&LotUsage{}).Where("lot_name = ?", name).Updates(fields).Error; err != nil {
		return wrap(err, "updating children usage")
	}
	return nil
}

// ancestorsVia returns all recursive ancestors of name (excluding self),
// cycle-safe, using the supplied transaction/handle.
func ancestorsVia(tx *gorm.DB, name string) ([]string, error) {
	seen := map[string]bool{name: true}
	var out []string
	queue := []string{name}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		var edges []LotParent
		if err := tx.Where("lot_name = ? AND parent != ?", cur, cur).Find(&edges).Error; err != nil {
			return nil, wrap(err, "walking ancestors")
		}
		for _, e := range edges {
			if !seen[e.Parent] {
				seen[e.Parent] = true
				out = append(out, e.Parent)
				queue = append(queue, e.Parent)
			}
		}
	}
	return out, nil
}

// descendantsVia returns all recursive descendants of name (excluding self),
// cycle-safe, using the supplied transaction/handle.
func descendantsVia(tx *gorm.DB, name string) ([]string, error) {
	seen := map[string]bool{name: true}
	var out []string
	queue := []string{name}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		var edges []LotParent
		if err := tx.Where("parent = ? AND lot_name != ?", cur, cur).Find(&edges).Error; err != nil {
			return nil, wrap(err, "walking descendants")
		}
		for _, e := range edges {
			if !seen[e.LotName] {
				seen[e.LotName] = true
				out = append(out, e.LotName)
				queue = append(queue, e.LotName)
			}
		}
	}
	return out, nil
}
