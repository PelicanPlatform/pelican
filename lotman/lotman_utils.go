//go:build lotman && linux && !ppc64le

/***************************************************************
*
* Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

// The LotMan library is used for managing storage in Pelican caches. For more information, see:
// https://github.com/pelicanplatform/lotman
package lotman

import (
	"reflect"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type UpdateInfo[T comparable] struct {
	Remove bool
	Update T
	Add    bool
}

// Helper function that converts a slice of type T to a set (map) of type T.
func sliceToSet[T comparable](s []T) map[T]struct{} {
	set := make(map[T]struct{}, len(s))
	for _, item := range s {
		set[item] = struct{}{}
	}
	return set
}

// Given two slices (lotman paths or parents), this function determines how to construct
// an update map for the Lotman API. The nuance and special handling in this function comes
// from a few Lotman peculiarities -- in particular, an update over a simple path list:
//
//	[path1, path2] -> [path1, path3, path4]
//
// could be constructed with lotman operations as:
//  1. "update path2 to path3" and "add path4" OR
//  2. "update path2 to path4" and "add path3" OR
//  3. "remove path2" and "add path3" and "add path4"
//
// Because Lotman prevents you from deleting _all_ parents associated with a lot, we avoid
// removals where we can and prefer options 1/2, which don't require a remove operation at all.
// This function determines how to construct these update primitives based on the logic that
// (remove + add) = update
func getModMap[T comparable](existing, new []T) map[T]UpdateInfo[T] {
	if len(existing) == 0 && len(new) == 0 {
		return nil
	}

	updateMap := map[T]UpdateInfo[T]{}

	eSet := sliceToSet(existing)
	nSet := sliceToSet(new)

	visited := make(map[T]bool)
	removedItems := map[T]struct{}{}
	addedItems := map[T]struct{}{}

	// Check for removals
	for eItem := range eSet {
		if _, inNSet := nSet[eItem]; !inNSet {
			updateMap[eItem] = UpdateInfo[T]{Remove: true}
			visited[eItem] = true
			removedItems[eItem] = struct{}{}
		} else {
			visited[eItem] = true
		}
	}

	// Check for additions
	for nItem := range nSet {
		if _, exists := visited[nItem]; exists {
			continue
		}
		if _, inESet := eSet[nItem]; !inESet {
			updateMap[nItem] = UpdateInfo[T]{Add: true}
			visited[nItem] = true
			addedItems[nItem] = struct{}{}
		}
	}

	// Convert removals + additions into updates where possible
	numRemoved := len(removedItems)
	numAdded := len(addedItems)
	if numRemoved > 0 && numAdded > 0 {
		if numRemoved <= numAdded {
			for removedItem := range removedItems {
				for addedItem := range addedItems {
					updateMap[removedItem] = UpdateInfo[T]{Update: addedItem}
					delete(updateMap, addedItem)
					delete(addedItems, addedItem)
					break
				}
			}
		} else {
			for addedItem := range addedItems {
				for removedItem := range removedItems {
					updateMap[removedItem] = UpdateInfo[T]{Update: addedItem}
					delete(updateMap, addedItem)
					delete(removedItems, removedItem)
					break
				}
			}
		}
	}

	return updateMap
}

// CompareMPAs checks whether two MPA structs have the same values, including dereferencing pointers.
func compareMPAs(mpa1, mpa2 *MPA) bool {
	if mpa1 == nil && mpa2 == nil {
		return true
	}
	if mpa1 == nil || mpa2 == nil {
		return false
	}
	if !reflect.DeepEqual(mpa1.DedicatedGB, mpa2.DedicatedGB) {
		return false
	}
	if !reflect.DeepEqual(mpa1.OpportunisticGB, mpa2.OpportunisticGB) {
		return false
	}
	if !reflect.DeepEqual(mpa1.MaxNumObjects, mpa2.MaxNumObjects) {
		return false
	}
	if !reflect.DeepEqual(mpa1.CreationTime, mpa2.CreationTime) {
		return false
	}
	if !reflect.DeepEqual(mpa1.ExpirationTime, mpa2.ExpirationTime) {
		return false
	}
	if !reflect.DeepEqual(mpa1.DeletionTime, mpa2.DeletionTime) {
		return false
	}
	return true
}

// Check various lot fields for the purpose of determining whether a lot needs an update.
// Note that we can't use reflect.DeepEqual here because we need to ignore some fields from the
// lot we grabbed via the `GetLot()` invocation (e.g. children, usage, etc.)
func lotRequiresUpdate(existingLot, newLot *Lot) (bool, error) {
	if existingLot == nil && newLot == nil {
		return false, nil
	}

	if existingLot == nil || newLot == nil {
		return false, errors.New("internal error -- lotRequiresUpdate was passed one nil lot")
	}

	// Compare fields explicitly, excluding the ones you want to ignore
	if existingLot.LotName != newLot.LotName {
		return false, errors.New("lot names do not match")
	}

	if existingLot.Owner != newLot.Owner {
		return true, nil
	}
	if !reflect.DeepEqual(existingLot.Parents, newLot.Parents) {
		return true, nil
	}
	if !reflect.DeepEqual(existingLot.Paths, newLot.Paths) {
		return true, nil
	}

	if !compareMPAs(existingLot.MPA, newLot.MPA) {
		return true, nil
	}

	return false, nil
}

// Given two lots, construct the relevant JSON objects for passing to Lotman's CRUD functions (if needed)
func getLotUpdateJSONs(existingLot *Lot, newLot *Lot) (*LotUpdate, *LotAddition, *LotPathRemoval, *LotParentRemoval, error) {

	lotRequiresUpdate, err := lotRequiresUpdate(existingLot, newLot)
	if err != nil {
		if existingLot == nil {
			return nil, nil, nil, nil, errors.New("internal error -- unable to check whether lot requires update: existing lot is nil")
		} else {
			return nil, nil, nil, nil, errors.Errorf("unable to check whether lot %s requires update: %v", existingLot.LotName, err)
		}
	}

	if !lotRequiresUpdate {
		log.Debugf("Lot '%s' already exists and doesn't need to be updated", newLot.LotName)
		return nil, nil, nil, nil, nil
	}

	// Otherwise, there's something to do. Start constructing relevant JSON objects
	// for passing to Lotman's CRUD functions.
	log.Debugf("Updating/adding to lot '%s'", newLot.LotName)

	var lotUpdate *LotUpdate
	var lotAddition *LotAddition
	var lotPathRemoval *LotPathRemoval
	var lotParentRemoval *LotParentRemoval

	// Check for owner update
	if existingLot.Owner != newLot.Owner {
		if lotUpdate == nil {
			lotUpdate = &LotUpdate{}
		}
		lotUpdate.Owner = &newLot.Owner
	}

	// Check for MPA update
	// If the MPAs are different, we update the entire MPA
	if !compareMPAs(existingLot.MPA, newLot.MPA) {
		if lotUpdate == nil {
			lotUpdate = &LotUpdate{}
		}
		lotUpdate.MPA = newLot.MPA

		// Lotman doesn't let us update the creation time
		lotUpdate.MPA.CreationTime = nil
	}

	// Check for parent updates
	if !reflect.DeepEqual(existingLot.Parents, newLot.Parents) {
		updateMap := getModMap(existingLot.Parents, newLot.Parents)
		for parent, update := range updateMap {
			switch {
			case update.Remove:
				if lotParentRemoval == nil {
					lotParentRemoval = &LotParentRemoval{}
				}
				lotParentRemoval.Parents = append(lotParentRemoval.Parents, parent)
			case update.Add:
				if lotAddition == nil {
					lotAddition = &LotAddition{}
				}
				lotAddition.Parents = append(lotAddition.Parents, parent)
			default: // update
				if lotUpdate == nil {
					lotUpdate = &LotUpdate{}
				}
				lotParentUpdate := ParentUpdate{
					Current: parent,
					New:     update.Update,
				}
				if lotUpdate.Parents == nil {
					lotUpdate.Parents = &[]ParentUpdate{}
				}
				*lotUpdate.Parents = append(*lotUpdate.Parents, lotParentUpdate)
			}
		}
	}

	// Check for path updates
	if !reflect.DeepEqual(existingLot.Paths, newLot.Paths) {
		updateMap := getModMap(existingLot.Paths, newLot.Paths)
		for path, update := range updateMap {
			switch {
			case update.Remove:
				if lotPathRemoval == nil {
					lotPathRemoval = &LotPathRemoval{}
				}
				lotPathRemoval.Paths = append(lotPathRemoval.Paths, path.Path)
			case update.Add:
				if lotAddition == nil {
					lotAddition = &LotAddition{}
				}
				lotAddition.Paths = append(lotAddition.Paths, path)
			default: // update
				if lotUpdate == nil {
					lotUpdate = &LotUpdate{}
				}
				lotPathUpdate := PathUpdate{
					Current:   path.Path,
					New:       update.Update.Path,
					Recursive: update.Update.Recursive,
				}
				if lotUpdate.Paths == nil {
					lotUpdate.Paths = &[]PathUpdate{}
				}
				*lotUpdate.Paths = append(*lotUpdate.Paths, lotPathUpdate)
			}
		}
	}

	// Add LotName to the structs if they are not nil. Note that paths can
	// belong to at most one lot, so the path removal struct doesn't have a lot name field
	if lotUpdate != nil {
		lotUpdate.LotName = newLot.LotName
	}
	if lotAddition != nil {
		lotAddition.LotName = newLot.LotName
	}
	if lotParentRemoval != nil {
		lotParentRemoval.LotName = newLot.LotName
	}

	return lotUpdate, lotAddition, lotPathRemoval, lotParentRemoval, nil
}
