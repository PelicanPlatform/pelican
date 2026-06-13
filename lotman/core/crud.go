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
	"gorm.io/gorm/clause"
)

// AddLot creates a new lot, its parent edges, its paths, and a zeroed usage row,
// all in one transaction. The caller must own at least one parent, unless the
// lot is self-parented (a new root) or the call is a trusted/system call
// (empty caller) or AdminOverride is set. Owner authentication is the adapter's
// responsibility; this method enforces only the ownership relationships the
// model requires.
func (m *Manager) AddLot(spec LotSpec, caller string) error {
	spec.Paths = normalizedPaths(spec.Paths)
	if err := validateLotSpec(spec); err != nil {
		return err
	}
	now := m.nowMs()
	return m.db.Transaction(func(tx *gorm.DB) error {
		var exists int64
		if err := tx.Model(&Lot{}).Where("lot_name = ?", spec.LotName).Count(&exists).Error; err != nil {
			return wrap(err, "checking for existing lot")
		}
		if exists > 0 {
			return ErrLotExists
		}
		for _, p := range spec.Parents {
			if p == spec.LotName {
				continue // self-parent: the lot is its own root
			}
			var pc int64
			if err := tx.Model(&Lot{}).Where("lot_name = ?", p).Count(&pc).Error; err != nil {
				return wrap(err, "checking parent existence")
			}
			if pc == 0 {
				return wrapf(ErrInvalidLot, "parent %q of lot %q does not exist", p, spec.LotName)
			}
		}
		if err := m.authorizeCreate(tx, spec, caller); err != nil {
			return err
		}

		lot := Lot{
			LotName:         spec.LotName,
			Owner:           spec.Owner,
			DedicatedGB:     spec.MPA.DedicatedGB,
			OpportunisticGB: spec.MPA.OpportunisticGB,
			MaxNumObjects:   spec.MPA.MaxNumObjects,
			CreationTime:    spec.MPA.CreationTime,
			ExpirationTime:  spec.MPA.ExpirationTime,
			DeletionTime:    spec.MPA.DeletionTime,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		if err := tx.Create(&lot).Error; err != nil {
			return wrap(err, "creating lot row")
		}
		for _, p := range spec.Parents {
			if err := tx.Create(&LotParent{LotName: spec.LotName, Parent: p}).Error; err != nil {
				return wrap(err, "creating parent edge")
			}
		}
		for _, ps := range spec.Paths {
			if err := tx.Create(&LotPath{LotName: spec.LotName, Path: ps.Path, Recursive: ps.Recursive, Exclude: ps.Exclude}).Error; err != nil {
				return wrap(err, "creating path")
			}
		}
		if err := tx.Create(&LotUsage{LotName: spec.LotName}).Error; err != nil {
			return wrap(err, "creating usage row")
		}
		return nil
	})
}

// GetLot returns a lot with its immediate parents, paths, and usage.
func (m *Manager) GetLot(name string) (*LotView, error) {
	lot, err := m.loadLot(m.db, name)
	if err != nil {
		return nil, err
	}
	parents, err := m.GetParents(name, false, true)
	if err != nil {
		return nil, err
	}
	var paths []LotPath
	if err := m.db.Where("lot_name = ?", name).Order("path").Find(&paths).Error; err != nil {
		return nil, wrap(err, "loading paths")
	}
	usage := LotUsage{LotName: name}
	if err := m.db.Where("lot_name = ?", name).First(&usage).Error; err != nil && err != gorm.ErrRecordNotFound {
		return nil, wrap(err, "loading usage")
	}
	return &LotView{Lot: *lot, Parents: parents, Paths: toPathSpecs(paths), Usage: usage}, nil
}

// UpdateLot updates a lot's owner and/or management-policy attributes. The
// caller must own the lot or one of its parents (or AdminOverride / system).
func (m *Manager) UpdateLot(update LotUpdate, caller string) error {
	if update.MPA != nil {
		if err := validateMPA(*update.MPA); err != nil {
			return err
		}
	}
	return m.db.Transaction(func(tx *gorm.DB) error {
		lot, err := m.loadLot(tx, update.LotName)
		if err != nil {
			return err
		}
		if err := m.authorizeModify(tx, *lot, caller); err != nil {
			return err
		}
		fields := map[string]any{"updated_at": m.nowMs()}
		if update.Owner != nil {
			if *update.Owner == "" {
				return wrapf(ErrInvalidLot, "owner cannot be set to empty")
			}
			fields["owner"] = *update.Owner
		}
		if update.MPA != nil {
			fields["dedicated_gb"] = update.MPA.DedicatedGB
			fields["opportunistic_gb"] = update.MPA.OpportunisticGB
			fields["max_num_objects"] = update.MPA.MaxNumObjects
			fields["creation_time"] = update.MPA.CreationTime
			fields["expiration_time"] = update.MPA.ExpirationTime
			fields["deletion_time"] = update.MPA.DeletionTime
		}
		if err := tx.Model(&Lot{}).Where("lot_name = ?", update.LotName).Updates(fields).Error; err != nil {
			return wrap(err, "updating lot")
		}
		return nil
	})
}

// AddToLot adds parents and/or paths to an existing lot. Duplicate edges/paths
// are ignored. The caller must own the lot or one of its parents.
func (m *Manager) AddToLot(add LotAddition, caller string) error {
	add.Paths = normalizedPaths(add.Paths)
	return m.db.Transaction(func(tx *gorm.DB) error {
		lot, err := m.loadLot(tx, add.LotName)
		if err != nil {
			return err
		}
		if err := m.authorizeModify(tx, *lot, caller); err != nil {
			return err
		}
		for _, p := range add.Parents {
			if p == "" {
				return wrapf(ErrInvalidLot, "cannot add empty parent")
			}
			if p != add.LotName {
				var pc int64
				if err := tx.Model(&Lot{}).Where("lot_name = ?", p).Count(&pc).Error; err != nil {
					return wrap(err, "checking parent existence")
				}
				if pc == 0 {
					return wrapf(ErrInvalidLot, "parent %q does not exist", p)
				}
			}
			edge := LotParent{LotName: add.LotName, Parent: p}
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&edge).Error; err != nil {
				return wrap(err, "adding parent edge")
			}
		}
		for _, ps := range add.Paths {
			if ps.Path == "" {
				return wrapf(ErrInvalidLot, "cannot add empty path")
			}
			row := LotPath{LotName: add.LotName, Path: ps.Path, Recursive: ps.Recursive, Exclude: ps.Exclude}
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error; err != nil {
				return wrap(err, "adding path")
			}
		}
		return nil
	})
}

// RemoveParents removes parent edges from a lot. The lot must retain at least
// one parent.
func (m *Manager) RemoveParents(rm LotParentRemoval, caller string) error {
	if len(rm.Parents) == 0 {
		return nil
	}
	return m.db.Transaction(func(tx *gorm.DB) error {
		lot, err := m.loadLot(tx, rm.LotName)
		if err != nil {
			return err
		}
		if err := m.authorizeModify(tx, *lot, caller); err != nil {
			return err
		}
		if err := tx.Where("lot_name = ? AND parent IN ?", rm.LotName, rm.Parents).Delete(&LotParent{}).Error; err != nil {
			return wrap(err, "removing parent edges")
		}
		var remaining int64
		if err := tx.Model(&LotParent{}).Where("lot_name = ?", rm.LotName).Count(&remaining).Error; err != nil {
			return wrap(err, "counting remaining parents")
		}
		if remaining == 0 {
			return wrapf(ErrInvalidLot, "lot %q must retain at least one parent", rm.LotName)
		}
		return nil
	})
}

// RemovePaths removes paths from a lot.
func (m *Manager) RemovePaths(rm LotPathRemoval, caller string) error {
	if len(rm.Paths) == 0 {
		return nil
	}
	normPaths := make([]string, len(rm.Paths))
	for i, p := range rm.Paths {
		normPaths[i] = normalizePath(p)
	}
	rm.Paths = normPaths
	return m.db.Transaction(func(tx *gorm.DB) error {
		lot, err := m.loadLot(tx, rm.LotName)
		if err != nil {
			return err
		}
		if err := m.authorizeModify(tx, *lot, caller); err != nil {
			return err
		}
		if err := tx.Where("lot_name = ? AND path IN ?", rm.LotName, rm.Paths).Delete(&LotPath{}).Error; err != nil {
			return wrap(err, "removing paths")
		}
		return nil
	})
}

// RemoveLot deletes a lot. With opts.Recursive, the lot and all descendants are
// removed. Otherwise the lot's direct children are reparented to the lot's
// parents before deletion; removing a childless lot always succeeds, but
// non-recursively removing a root that still has children is rejected (the
// children would be orphaned).
func (m *Manager) RemoveLot(name string, opts RemoveOptions, caller string) error {
	return m.db.Transaction(func(tx *gorm.DB) error {
		lot, err := m.loadLot(tx, name)
		if err != nil {
			return err
		}
		if err := m.authorizeModify(tx, *lot, caller); err != nil {
			return err
		}

		if opts.Recursive {
			victims, err := m.descendantsAndSelf(tx, name)
			if err != nil {
				return err
			}
			// Deleting each lot row cascades its paths, usage, reclamation, and
			// own parent edges via ON DELETE CASCADE.
			if err := tx.Where("lot_name IN ?", victims).Delete(&Lot{}).Error; err != nil {
				return wrap(err, "deleting lot subtree")
			}
			return nil
		}

		// Non-recursive: reparent direct children to this lot's parents.
		var parentEdges []LotParent
		if err := tx.Where("lot_name = ?", name).Find(&parentEdges).Error; err != nil {
			return wrap(err, "loading lot parents")
		}
		newParents := make([]string, 0, len(parentEdges))
		for _, e := range parentEdges {
			if e.Parent != name { // skip self-parent
				newParents = append(newParents, e.Parent)
			}
		}

		var childEdges []LotParent
		if err := tx.Where("parent = ? AND lot_name != ?", name, name).Find(&childEdges).Error; err != nil {
			return wrap(err, "loading child edges")
		}
		if len(childEdges) > 0 && len(newParents) == 0 {
			return wrapf(ErrInvalidLot, "cannot remove root lot %q non-recursively while it has children", name)
		}
		for _, ce := range childEdges {
			// Drop the edge to the removed lot, attach to each surviving parent.
			if err := tx.Where("lot_name = ? AND parent = ?", ce.LotName, name).Delete(&LotParent{}).Error; err != nil {
				return wrap(err, "detaching child edge")
			}
			for _, np := range newParents {
				edge := LotParent{LotName: ce.LotName, Parent: np}
				if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&edge).Error; err != nil {
					return wrap(err, "reparenting child")
				}
			}
		}

		if err := tx.Where("lot_name = ?", name).Delete(&Lot{}).Error; err != nil {
			return wrap(err, "deleting lot")
		}
		return nil
	})
}

// RemoveLotRecursive deletes a lot and all of its descendants.
func (m *Manager) RemoveLotRecursive(name, caller string) error {
	return m.RemoveLot(name, RemoveOptions{Recursive: true}, caller)
}

// descendantsAndSelf returns name plus all of its descendants, cycle-safe.
func (m *Manager) descendantsAndSelf(tx *gorm.DB, name string) ([]string, error) {
	seen := map[string]bool{name: true}
	out := []string{name}
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

// authorizeCreate enforces the create-time ownership rule. Empty caller is a
// trusted/system call (e.g. bootstrap of root/default lots).
func (m *Manager) authorizeCreate(tx *gorm.DB, spec LotSpec, caller string) error {
	if caller == "" || m.opts.AdminOverride {
		return nil
	}
	for _, p := range spec.Parents {
		if p == spec.LotName {
			return nil // self-parented: creating one's own root
		}
	}
	var owned int64
	if err := tx.Model(&Lot{}).Where("lot_name IN ? AND owner = ?", spec.Parents, caller).Count(&owned).Error; err != nil {
		return wrap(err, "checking parent ownership")
	}
	if owned == 0 {
		return wrapf(ErrNotAuthorized, "caller %q owns no parent of lot %q", caller, spec.LotName)
	}
	return nil
}

// authorizeModify enforces the modify-time ownership rule: the caller must own
// the lot or one of its parents (or be a trusted/system/admin caller).
func (m *Manager) authorizeModify(tx *gorm.DB, lot Lot, caller string) error {
	if caller == "" || m.opts.AdminOverride {
		return nil
	}
	if lot.Owner == caller {
		return nil
	}
	var owned int64
	err := tx.Table("lot_parents AS lp").
		Joins("JOIN lots l ON l.lot_name = lp.parent").
		Where("lp.lot_name = ? AND lp.parent != lp.lot_name AND l.owner = ?", lot.LotName, caller).
		Count(&owned).Error
	if err != nil {
		return wrap(err, "checking lot ownership")
	}
	if owned == 0 {
		return wrapf(ErrNotAuthorized, "caller %q does not own lot %q or a parent", caller, lot.LotName)
	}
	return nil
}
