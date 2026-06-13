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
	"errors"

	"gorm.io/gorm"
)

// LotExists reports whether a lot with the given name exists.
func (m *Manager) LotExists(name string) (bool, error) {
	var count int64
	if err := m.db.Model(&Lot{}).Where("lot_name = ?", name).Count(&count).Error; err != nil {
		return false, wrap(err, "checking lot existence")
	}
	return count > 0, nil
}

// ListAllLots returns every lot name, ordered.
func (m *Manager) ListAllLots() ([]string, error) {
	var names []string
	if err := m.db.Model(&Lot{}).Order("lot_name").Pluck("lot_name", &names).Error; err != nil {
		return nil, wrap(err, "listing lots")
	}
	return names, nil
}

// IsRoot reports whether the lot is a root — i.e. its only parent is itself.
func (m *Manager) IsRoot(name string) (bool, error) {
	if ok, err := m.LotExists(name); err != nil {
		return false, err
	} else if !ok {
		return false, ErrLotNotFound
	}
	var edges []LotParent
	if err := m.db.Where("lot_name = ?", name).Find(&edges).Error; err != nil {
		return false, wrap(err, "loading parents")
	}
	if len(edges) == 0 {
		return false, nil
	}
	for _, e := range edges {
		if e.Parent != name {
			return false, nil
		}
	}
	return true, nil
}

// GetParents returns the lot's parents. When recursive, all ancestors are
// returned. When getSelf is true and the lot is self-parented, the lot itself
// is included. Cycles (self-parent edges on roots) are handled.
func (m *Manager) GetParents(name string, recursive, getSelf bool) ([]string, error) {
	if ok, err := m.LotExists(name); err != nil {
		return nil, err
	} else if !ok {
		return nil, ErrLotNotFound
	}

	result := []string{}
	seen := map[string]bool{}
	queue := []string{}

	add := func(parent, child string, enqueue bool) {
		if parent == child { // self-parent edge
			if getSelf && parent == name && !seen[parent] {
				seen[parent] = true
				result = append(result, parent)
			}
			return
		}
		if !seen[parent] {
			seen[parent] = true
			result = append(result, parent)
			if enqueue {
				queue = append(queue, parent)
			}
		}
	}

	var edges []LotParent
	if err := m.db.Where("lot_name = ?", name).Find(&edges).Error; err != nil {
		return nil, wrap(err, "loading parents")
	}
	for _, e := range edges {
		add(e.Parent, name, recursive)
	}

	for recursive && len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		var pe []LotParent
		if err := m.db.Where("lot_name = ?", cur).Find(&pe).Error; err != nil {
			return nil, wrap(err, "loading ancestor parents")
		}
		for _, e := range pe {
			add(e.Parent, cur, true)
		}
	}
	return result, nil
}

// GetChildren returns the lot's children. When recursive, all descendants are
// returned. When getSelf is true and the lot is self-parented, the lot itself
// is included.
func (m *Manager) GetChildren(name string, recursive, getSelf bool) ([]string, error) {
	if ok, err := m.LotExists(name); err != nil {
		return nil, err
	} else if !ok {
		return nil, ErrLotNotFound
	}

	result := []string{}
	seen := map[string]bool{}
	queue := []string{}

	add := func(child, parent string, enqueue bool) {
		if child == parent { // self-parent edge
			if getSelf && child == name && !seen[child] {
				seen[child] = true
				result = append(result, child)
			}
			return
		}
		if !seen[child] {
			seen[child] = true
			result = append(result, child)
			if enqueue {
				queue = append(queue, child)
			}
		}
	}

	var edges []LotParent
	if err := m.db.Where("parent = ?", name).Find(&edges).Error; err != nil {
		return nil, wrap(err, "loading children")
	}
	for _, e := range edges {
		add(e.LotName, name, recursive)
	}

	for recursive && len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		var ce []LotParent
		if err := m.db.Where("parent = ?", cur).Find(&ce).Error; err != nil {
			return nil, wrap(err, "loading descendant children")
		}
		for _, e := range ce {
			add(e.LotName, cur, true)
		}
	}
	return result, nil
}

// GetOwners returns the lot's owner. When recursive, the owners of all
// ancestors are also included (de-duplicated, lot's own owner first).
func (m *Manager) GetOwners(name string, recursive bool) ([]string, error) {
	lot, err := m.loadLot(m.db, name)
	if err != nil {
		return nil, err
	}
	result := []string{lot.Owner}
	seen := map[string]bool{lot.Owner: true}
	if recursive {
		ancestors, err := m.GetParents(name, true, false)
		if err != nil {
			return nil, err
		}
		for _, a := range ancestors {
			al, err := m.loadLot(m.db, a)
			if err != nil {
				return nil, err
			}
			if !seen[al.Owner] {
				seen[al.Owner] = true
				result = append(result, al.Owner)
			}
		}
	}
	return result, nil
}

// loadLot fetches a single lot, returning ErrLotNotFound when absent.
func (m *Manager) loadLot(tx *gorm.DB, name string) (*Lot, error) {
	var lot Lot
	if err := tx.Where("lot_name = ?", name).First(&lot).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrLotNotFound
		}
		return nil, wrap(err, "loading lot")
	}
	return &lot, nil
}
