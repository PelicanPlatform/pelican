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
	"sort"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ReclaimResult is the outcome of ReclaimLot.
type ReclaimResult int

const (
	// ReclaimError indicates the reclaim failed (returned alongside an error).
	ReclaimError ReclaimResult = -1
	// ReclaimOK indicates at least one new reclamation row was written.
	ReclaimOK ReclaimResult = 0
	// ReclaimAlreadyReclaimed indicates every target lot was already reclaimed.
	ReclaimAlreadyReclaimed ReclaimResult = 1
)

// LotsPastExp returns lots whose expiration_time has passed at atMs. Non-expiring
// lots (expiration_time 0) are never included. With recursive, descendants of
// expired lots are added. Reclaimed lots (as of atMs) are dropped unless
// includeReclaimed.
func (m *Manager) LotsPastExp(atMs int64, recursive, includeReclaimed bool) ([]string, error) {
	var names []string
	if err := m.db.Model(&Lot{}).
		Where("expiration_time != 0 AND expiration_time <= ?", atMs).
		Pluck("lot_name", &names).Error; err != nil {
		return nil, wrap(err, "querying past-expiration lots")
	}
	return m.finishPastQuery(names, recursive, includeReclaimed, atMs)
}

// LotsPastDel returns lots whose deletion_time has passed at atMs (the GC
// trigger). Semantics mirror LotsPastExp.
func (m *Manager) LotsPastDel(atMs int64, recursive, includeReclaimed bool) ([]string, error) {
	var names []string
	if err := m.db.Model(&Lot{}).
		Where("deletion_time != 0 AND deletion_time <= ?", atMs).
		Pluck("lot_name", &names).Error; err != nil {
		return nil, wrap(err, "querying past-deletion lots")
	}
	return m.finishPastQuery(names, recursive, includeReclaimed, atMs)
}

// LotsPastDed returns lots over their dedicated_GB quota. With hierarchical, an
// adjusted-usage query attributes children's overage to their parents and
// results are returned deepest-first; recQuota/recChildren are ignored in that
// mode. Otherwise recQuota counts children toward the quota (self+children) and
// recChildren appends descendants of over-quota lots.
func (m *Manager) LotsPastDed(recQuota, recChildren, includeReclaimed, hierarchical bool) ([]string, error) {
	if hierarchical {
		return m.lotsPastThresholdHierarchical(
			"self_gb", "c_usage.self_gb + c_usage.children_gb", "c_mpa.dedicated_gb", "p_mpa.dedicated_gb",
			"p_mpa.dedicated_gb = -1", "c_mpa.dedicated_gb = -1", includeReclaimed)
	}
	usageExpr := "u.self_gb"
	if recQuota {
		usageExpr = "u.self_gb + u.children_gb"
	}
	names, err := m.pastQuotaQuery("l.dedicated_gb != -1", usageExpr+" >= l.dedicated_gb")
	if err != nil {
		return nil, err
	}
	return m.finishQuotaQuery(names, recChildren, includeReclaimed)
}

// LotsPastOpp returns lots over their dedicated+opportunistic quota.
func (m *Manager) LotsPastOpp(recQuota, recChildren, includeReclaimed, hierarchical bool) ([]string, error) {
	if hierarchical {
		return m.lotsPastThresholdHierarchical(
			"self_gb", "c_usage.self_gb + c_usage.children_gb",
			"c_mpa.dedicated_gb + c_mpa.opportunistic_gb", "p_mpa.dedicated_gb + p_mpa.opportunistic_gb",
			"p_mpa.dedicated_gb = -1 OR p_mpa.opportunistic_gb = -1",
			"c_mpa.dedicated_gb = -1 OR c_mpa.opportunistic_gb = -1", includeReclaimed)
	}
	usageExpr := "u.self_gb"
	if recQuota {
		usageExpr = "u.self_gb + u.children_gb"
	}
	names, err := m.pastQuotaQuery(
		"l.dedicated_gb != -1 AND l.opportunistic_gb != -1",
		usageExpr+" >= l.dedicated_gb + l.opportunistic_gb")
	if err != nil {
		return nil, err
	}
	return m.finishQuotaQuery(names, recChildren, includeReclaimed)
}

// LotsPastObj returns lots over their max_num_objects quota.
func (m *Manager) LotsPastObj(recQuota, recChildren, includeReclaimed, hierarchical bool) ([]string, error) {
	if hierarchical {
		return m.lotsPastThresholdHierarchical(
			"self_objects", "c_usage.self_objects + c_usage.children_objects", "c_mpa.max_num_objects",
			"p_mpa.max_num_objects", "p_mpa.max_num_objects = -1", "c_mpa.max_num_objects = -1", includeReclaimed)
	}
	usageExpr := "u.self_objects"
	if recQuota {
		usageExpr = "u.self_objects + u.children_objects"
	}
	names, err := m.pastQuotaQuery("l.max_num_objects != -1", usageExpr+" >= l.max_num_objects")
	if err != nil {
		return nil, err
	}
	return m.finishQuotaQuery(names, recChildren, includeReclaimed)
}

// pastQuotaQuery runs a non-hierarchical over-quota query joining usage to MPAs.
func (m *Manager) pastQuotaQuery(boundedPredicate, overPredicate string) ([]string, error) {
	var names []string
	err := m.db.Table("lot_usage AS u").
		Joins("JOIN lots l ON l.lot_name = u.lot_name").
		Where(boundedPredicate).
		Where(overPredicate).
		Pluck("u.lot_name", &names).Error
	if err != nil {
		return nil, wrap(err, "querying past-quota lots")
	}
	return names, nil
}

// finishQuotaQuery applies the recursive-children expansion and reclamation
// filter (evaluated at "now") shared by the quota past-* queries.
func (m *Manager) finishQuotaQuery(names []string, recChildren, includeReclaimed bool) ([]string, error) {
	if recChildren {
		var err error
		if names, err = m.expandRecursiveChildren(names); err != nil {
			return nil, err
		}
	}
	return m.filterReclaimed(names, includeReclaimed, m.nowMs())
}

// finishPastQuery applies recursive-children expansion and reclamation filter
// (evaluated at the query time) shared by the time-based past-* queries.
func (m *Manager) finishPastQuery(names []string, recursive, includeReclaimed bool, atMs int64) ([]string, error) {
	if recursive {
		var err error
		if names, err = m.expandRecursiveChildren(names); err != nil {
			return nil, err
		}
	}
	return m.filterReclaimed(names, includeReclaimed, atMs)
}

// lotsPastThresholdHierarchical builds the adjusted-usage query: a parent is
// "past" when its own usage plus the sum of its children's overage (capped at 0,
// excluding unbounded and reclaimed children) meets the parent's threshold.
// Unbounded and reclaimed parents are excluded. Results are deepest-first.
func (m *Manager) lotsPastThresholdHierarchical(selfCol, childUsageExpr, childThreshExpr, parentThreshExpr, parentUnb, childUnb string, includeReclaimed bool) ([]string, error) {
	now := m.nowMs()
	query := "SELECT p_usage.lot_name FROM lot_usage p_usage " +
		"JOIN lots p_mpa ON p_usage.lot_name = p_mpa.lot_name " +
		"LEFT JOIN lot_reclamations p_rec ON p_rec.lot_name = p_usage.lot_name " +
		"WHERE NOT (" + parentUnb + ") " +
		"AND (p_rec.lot_name IS NULL OR p_rec.reclaimed_at > ?) " +
		"AND p_usage." + selfCol + " + COALESCE(" +
		"  (SELECT SUM(CASE WHEN (" + childUnb + ") THEN 0 " +
		"                   WHEN (c_rec.lot_name IS NOT NULL AND c_rec.reclaimed_at <= ?) THEN 0 " +
		"                   ELSE MAX(0, (" + childUsageExpr + ") - (" + childThreshExpr + ")) END) " +
		"   FROM lot_parents c_par " +
		"   JOIN lot_usage c_usage ON c_par.lot_name = c_usage.lot_name " +
		"   JOIN lots c_mpa ON c_par.lot_name = c_mpa.lot_name " +
		"   LEFT JOIN lot_reclamations c_rec ON c_rec.lot_name = c_par.lot_name " +
		"   WHERE c_par.parent = p_usage.lot_name AND c_par.lot_name != c_par.parent), 0" +
		") >= " + parentThreshExpr + ";"

	var names []string
	if err := m.db.Raw(query, now, now).Scan(&names).Error; err != nil {
		return nil, wrap(err, "querying hierarchical past-threshold lots")
	}
	names = m.sortByDepthDescending(names)
	return m.filterReclaimed(names, includeReclaimed, now)
}

// expandRecursiveChildren returns the input names plus all of their recursive
// descendants, de-duplicated and sorted.
func (m *Manager) expandRecursiveChildren(names []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, n := range names {
		add(n)
	}
	for _, n := range names {
		desc, err := descendantsVia(m.db, n)
		if err != nil {
			return nil, err
		}
		for _, d := range desc {
			add(d)
		}
	}
	sort.Strings(out)
	return out, nil
}

// filterReclaimed removes lots reclaimed as of atMs, unless includeReclaimed.
func (m *Manager) filterReclaimed(names []string, includeReclaimed bool, atMs int64) ([]string, error) {
	if includeReclaimed || len(names) == 0 {
		return names, nil
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		reclaimed, err := m.isReclaimedAt(n, atMs)
		if err != nil {
			return nil, err
		}
		if !reclaimed {
			out = append(out, n)
		}
	}
	return out, nil
}

// sortByDepthDescending orders lots by their maximum depth from a root,
// deepest-first, so the most specific lots are evicted before their ancestors.
func (m *Manager) sortByDepthDescending(names []string) []string {
	if len(names) <= 1 {
		return names
	}
	type depthRow struct {
		LotName string `gorm:"column:lot_name"`
		Depth   int    `gorm:"column:depth"`
	}
	const cte = "WITH RECURSIVE depth_cte(lot_name, depth) AS (" +
		"  SELECT lot_name, 0 FROM lot_parents WHERE lot_name = parent " +
		"  UNION ALL " +
		"  SELECT p.lot_name, d.depth + 1 FROM lot_parents p JOIN depth_cte d ON p.parent = d.lot_name " +
		"  WHERE p.lot_name != p.parent" +
		") SELECT lot_name, MAX(depth) AS depth FROM depth_cte GROUP BY lot_name;"
	var rows []depthRow
	if err := m.db.Raw(cte).Scan(&rows).Error; err != nil {
		return names // on error, leave unsorted
	}
	depth := make(map[string]int, len(rows))
	for _, r := range rows {
		depth[r.LotName] = r.Depth
	}
	sort.SliceStable(names, func(i, j int) bool { return depth[names[i]] > depth[names[j]] })
	return names
}

// ReclaimLot records that a lot and all of its descendants have been reclaimed
// by the storage provider. The reclamations table is an immutable ledger:
// existing rows are never overwritten. Returns ReclaimAlreadyReclaimed if every
// target already had a row. The "default" lot cannot be reclaimed. Ancestors'
// children rollups are recomputed so reclaimed usage stops counting immediately.
func (m *Manager) ReclaimLot(name string, atMs int64, reason, caller string) (ReclaimResult, error) {
	if name == "default" {
		return ReclaimError, wrapf(ErrInvalidLot, "the default lot cannot be reclaimed")
	}
	result := ReclaimOK
	err := m.db.Transaction(func(tx *gorm.DB) error {
		lot, err := m.loadLot(tx, name)
		if err != nil {
			return err
		}
		if err := m.authorizeModify(tx, *lot, caller); err != nil {
			return err
		}
		descendants, err := descendantsVia(tx, name)
		if err != nil {
			return err
		}
		targets := append([]string{name}, descendants...)

		insertedAny, skippedExisting := false, false
		for _, t := range targets {
			row := LotReclamation{LotName: t, ReclaimedAt: atMs, ReclaimedReason: reason}
			res := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
			if res.Error != nil {
				return wrap(res.Error, "inserting reclamation")
			}
			if res.RowsAffected > 0 {
				insertedAny = true
			} else {
				skippedExisting = true
			}
		}
		if !insertedAny && skippedExisting {
			result = ReclaimAlreadyReclaimed
		}

		// Reclaimed usage must stop counting toward ancestors' rollups.
		ancestors, err := ancestorsVia(tx, name)
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
	if err != nil {
		return ReclaimError, err
	}
	return result, nil
}
