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

package lotman

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create an MPA with given parameters
func createMPA(dedicatedGB, opportunisticGB float64, maxNumObjects int64) *MPA {
	return &MPA{
		DedicatedGB:     &dedicatedGB,
		OpportunisticGB: &opportunisticGB,
		MaxNumObjects:   &Int64FromFloat{Value: maxNumObjects},
	}
}

func TestCompareMPAs(t *testing.T) {
	// This test only checks a subset of MAP fields, as the rest are\
	// all handled similarly.
	testCases := []struct {
		name     string
		mpa1     *MPA
		mpa2     *MPA
		expected bool
	}{
		{
			name:     "Equal MPAs",
			mpa1:     createMPA(10.0, 5.0, 100),
			mpa2:     createMPA(10.0, 5.0, 100),
			expected: true,
		},
		{
			name:     "Different DedicatedGB",
			mpa1:     createMPA(10.0, 5.0, 100),
			mpa2:     createMPA(20.0, 5.0, 100),
			expected: false,
		},
		{
			name:     "Different OpportunisticGB",
			mpa1:     createMPA(10.0, 5.0, 100),
			mpa2:     createMPA(10.0, 10.0, 100),
			expected: false,
		},
		{
			name:     "Different MaxNumObjects",
			mpa1:     createMPA(10.0, 5.0, 100),
			mpa2:     createMPA(10.0, 5.0, 200),
			expected: false,
		},
		{
			name:     "One nil MPA",
			mpa1:     createMPA(10.0, 5.0, 100),
			mpa2:     nil,
			expected: false,
		},
		{
			name:     "Both nil MPAs",
			mpa1:     nil,
			mpa2:     nil,
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := compareMPAs(tc.mpa1, tc.mpa2)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// A test helper function for testing getModMap. This function takes the existing slice
// and applies the mod map to it to generate the new slice, which is what we use for test
// verification. This is much easier than verifying the mod map directly, because go maps
// are unordered and there are multiple ways to represent the same mod map.
func applyModMap[T comparable](existing []T, modMap map[T]UpdateInfo[T]) []T {
	result := make([]T, 0, len(existing))
	visited := make(map[T]bool)

	for _, item := range existing {
		if mod, exists := modMap[item]; exists {
			if mod.Remove {
				continue
			}
			var zeroValue T // Default zero value for type T
			if mod.Update != zeroValue {
				result = append(result, mod.Update)
				visited[mod.Update] = true
				continue
			}
		}
		result = append(result, item)
		visited[item] = true
	}

	for item, mod := range modMap {
		if mod.Add && !visited[item] {
			result = append(result, item)
		}
	}

	return result
}

type ModMapTestCase[T comparable] struct {
	name     string
	existing []T
	new      []T
}

func runGetModMapTests[T comparable](t *testing.T, testCases []ModMapTestCase[T]) {
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			modMap := getModMap(tc.existing, tc.new)
			result := applyModMap(tc.existing, modMap)
			assert.ElementsMatch(t, tc.new, result)
		})
	}
}
func TestGetModMap(t *testing.T) {
	stringTestCases := []ModMapTestCase[string]{
		{"Single update", []string{"foo", "bar"}, []string{"foo", "baz"}},
		{"Add item", []string{"foo", "bar"}, []string{"foo", "bar", "baz"}},
		{"Remove item", []string{"foo", "bar"}, []string{"foo"}},
		{"Update and add", []string{"foo", "bar"}, []string{"foo", "baz", "goo"}},
		{"Update and remove", []string{"foo", "bar", "goo"}, []string{"foo", "baz"}},
		{"Complex case", []string{"foo", "bar", "baz"}, []string{"foo", "goo", "boo"}},
	}

	lotPathTestCases := []ModMapTestCase[LotPath]{
		{
			name:     "Single update",
			existing: []LotPath{{Path: "/foo", Recursive: true}, {Path: "/bar", Recursive: false}},
			new:      []LotPath{{Path: "/foo", Recursive: true}, {Path: "/baz", Recursive: false}},
		},
		{
			name:     "Add item",
			existing: []LotPath{{Path: "/foo", Recursive: true}, {Path: "/bar", Recursive: false}},
			new:      []LotPath{{Path: "/foo", Recursive: true}, {Path: "/bar", Recursive: false}, {Path: "/baz", Recursive: true}},
		},
		{
			name:     "Remove item",
			existing: []LotPath{{Path: "/foo", Recursive: true}, {Path: "/bar", Recursive: false}},
			new:      []LotPath{{Path: "/foo", Recursive: true}},
		},
		{
			name:     "Update two and add", // Note that the /foo is an update because of new recursive value
			existing: []LotPath{{Path: "/foo", Recursive: true}, {Path: "/bar", Recursive: false}},
			new:      []LotPath{{Path: "/foo", Recursive: false}, {Path: "/baz", Recursive: false}, {Path: "/goo", Recursive: true}},
		},
		{
			name:     "Update and remove",
			existing: []LotPath{{Path: "/foo", Recursive: true}, {Path: "/bar", Recursive: false}, {Path: "/goo", Recursive: true}},
			new:      []LotPath{{Path: "/foo", Recursive: false}, {Path: "/baz", Recursive: false}},
		},
		{
			name:     "Complex case",
			existing: []LotPath{{Path: "/foo", Recursive: true}, {Path: "/bar", Recursive: false}, {Path: "/baz", Recursive: true}},
			new:      []LotPath{{Path: "/foo", Recursive: true}, {Path: "/goo", Recursive: false}, {Path: "/boo", Recursive: true}},
		},
	}

	runGetModMapTests(t, stringTestCases)
	runGetModMapTests(t, lotPathTestCases)
}

// Some updates may have multiple correct solutions. In these cases, there is a dependency
// between the LotUpdate and relevant removal/addition pieces for paths and parents. To handle
// this, we define two types of solutions -- those where there's exactly one correct solution
// (concreteSolution) and those where there are multiple correct solutions (dynamicSolution).
// The dynamicSolution type contains maps that allow us to verify that the correct removals/additions
// are present in the context of the other parts of the update.

type concreteSolution struct {
	Update   *LotUpdate
	Add      *LotAddition
	PathRm   *LotPathRemoval
	ParentRm *LotParentRemoval
}

type dynamicSolution struct {
	Owner                           *string
	MPA                             *MPA
	PathUpdateToRmMap               map[PathUpdate]*LotPathRemoval
	PathUpdateToPathAdditionMap     map[PathUpdate][]LotPath
	ParentUpdateToRmMap             map[ParentUpdate]*LotParentRemoval
	ParentUpdateToParentAdditionMap map[ParentUpdate][]string
}

type updateSolution struct {
	Concrete *concreteSolution
	Dynamic  *dynamicSolution
}

func TestGetLotUpdateJSONs(t *testing.T) {
	createLot := func(name, owner string, parents []string, paths []LotPath, mpa *MPA) *Lot {
		return &Lot{
			LotName: name,
			Owner:   owner,
			Parents: parents,
			Paths:   paths,
			MPA:     mpa,
		}
	}
	stringPtr := func(s string) *string {
		return &s
	}

	testCases := []struct {
		name                string
		existingLot         *Lot
		newLot              *Lot
		acceptableSolutions updateSolution
		expectError         bool
	}{
		{
			name: "No changes needed",
			existingLot: createLot(
				"lot1",
				"owner1",
				[]string{"parent1"},
				[]LotPath{{Path: "/path1", Recursive: true}},
				createMPA(10.0, 5.0, 100),
			),
			newLot: createLot(
				"lot1",
				"owner1",
				[]string{"parent1"},
				[]LotPath{{Path: "/path1", Recursive: true}},
				createMPA(10.0, 5.0, 100),
			),
			acceptableSolutions: updateSolution{},
			expectError:         false,
		},
		{
			name: "Different lots produces error",
			existingLot: createLot(
				"lot1",
				"owner1",
				[]string{"parent1"},
				[]LotPath{{Path: "/path1", Recursive: true}},
				createMPA(10.0, 5.0, 100),
			),
			newLot: createLot(
				"lot2",
				"owner1",
				[]string{"parent1"},
				[]LotPath{{Path: "/path1", Recursive: true}},
				createMPA(10.0, 5.0, 100),
			),
			acceptableSolutions: updateSolution{},
			expectError:         true,
		},
		{
			name: "Owner update needed",
			existingLot: createLot(
				"lot1",
				"owner1",
				[]string{"parent1"},
				[]LotPath{{Path: "/path1", Recursive: true}},
				createMPA(10.0, 5.0, 100),
			),
			newLot: createLot(
				"lot1",
				"owner2",
				[]string{"parent1"},
				[]LotPath{{Path: "/path1", Recursive: true}},
				createMPA(10.0, 5.0, 100),
			),
			acceptableSolutions: updateSolution{
				Concrete: &concreteSolution{
					Update:   &LotUpdate{LotName: "lot1", Owner: stringPtr("owner2")},
					Add:      nil,
					PathRm:   nil,
					ParentRm: nil,
				},
			},
			expectError: false,
		},
		{
			name: "MPA update needed",
			existingLot: createLot(
				"lot1",
				"owner1",
				[]string{"parent1"},
				[]LotPath{{Path: "/path1", Recursive: true}},
				createMPA(10.0, 5.0, 100),
			),
			newLot: createLot(
				"lot1",
				"owner1",
				[]string{"parent1"},
				[]LotPath{{Path: "/path1", Recursive: true}},
				createMPA(20.0, 10.0, 200),
			),
			acceptableSolutions: updateSolution{
				Concrete: &concreteSolution{
					Update:   &LotUpdate{LotName: "lot1", MPA: createMPA(20.0, 10.0, 200)},
					Add:      nil,
					PathRm:   nil,
					ParentRm: nil,
				},
			},
			expectError: false,
		},
		{
			name: "Parent addition needed",
			existingLot: createLot(
				"lot1",
				"owner1",
				[]string{"parent1"},
				[]LotPath{{Path: "/path1", Recursive: true}},
				createMPA(10.0, 5.0, 100),
			),
			newLot: createLot(
				"lot1",
				"owner1",
				[]string{"parent1", "parent2"},
				[]LotPath{{Path: "/path1", Recursive: true}},
				createMPA(10.0, 5.0, 100),
			),
			acceptableSolutions: updateSolution{
				Concrete: &concreteSolution{
					Update:   nil,
					Add:      &LotAddition{LotName: "lot1", Parents: []string{"parent2"}},
					PathRm:   nil,
					ParentRm: nil,
				},
			},
			expectError: false,
		},
		{
			name: "Path removal needed",
			existingLot: createLot(
				"lot1",
				"owner1",
				[]string{"parent1"},
				[]LotPath{{Path: "/path1", Recursive: true}, {Path: "/path2", Recursive: false}},
				createMPA(10.0, 5.0, 100),
			),
			newLot: createLot(
				"lot1",
				"owner1",
				[]string{"parent1"},
				[]LotPath{{Path: "/path1", Recursive: true}},
				createMPA(10.0, 5.0, 100),
			),
			acceptableSolutions: updateSolution{
				Concrete: &concreteSolution{
					Update:   nil,
					Add:      nil,
					PathRm:   &LotPathRemoval{Paths: []string{"/path2"}},
					ParentRm: nil,
				},
			},
			expectError: false,
		},
		{
			name: "Multiple updates needed (dynamic solution)",
			existingLot: createLot(
				"lot1",
				"owner1",
				[]string{"parent1", "parent2"},
				[]LotPath{{Path: "/path1", Recursive: true}, {Path: "/path2", Recursive: false}},
				createMPA(10.0, 5.0, 100),
			),
			newLot: createLot(
				"lot1",
				"owner2",
				[]string{"parent1", "parent3", "parent4"},
				[]LotPath{{Path: "/path1", Recursive: true}, {Path: "/path3", Recursive: true}, {Path: "/path4", Recursive: false}},
				createMPA(20.0, 10.0, 200),
			),
			acceptableSolutions: updateSolution{
				Dynamic: &dynamicSolution{
					Owner: stringPtr("owner2"),
					MPA:   createMPA(20.0, 10.0, 200),
					PathUpdateToPathAdditionMap: map[PathUpdate][]LotPath{
						{Current: "/path2", New: "/path3", Recursive: true}:  {{Path: "/path4", Recursive: false}},
						{Current: "/path2", New: "/path4", Recursive: false}: {{Path: "/path3", Recursive: true}},
					},
					ParentUpdateToParentAdditionMap: map[ParentUpdate][]string{
						{Current: "parent2", New: "parent3"}: {"parent4"},
						{Current: "parent2", New: "parent4"}: {"parent3"},
					},
				},
			},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			update, add, pathRm, parentRm, err := getLotUpdateJSONs(tc.existingLot, tc.newLot)
			if tc.expectError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			if tc.acceptableSolutions.Concrete != nil {
				assert.Equal(t, tc.acceptableSolutions.Concrete.Update, update)
				assert.Equal(t, tc.acceptableSolutions.Concrete.Add, add)
				assert.Equal(t, tc.acceptableSolutions.Concrete.PathRm, pathRm)
				assert.Equal(t, tc.acceptableSolutions.Concrete.ParentRm, parentRm)

				return
			}

			// If we have a dynamic solution because there's more than one correct answer,
			// use our solutions maps to verify that each part of the update is correct in
			// the context of the other parts of the update.
			if tc.acceptableSolutions.Dynamic != nil {
				assert.Equal(t, tc.acceptableSolutions.Dynamic.Owner, update.Owner)
				assert.Equal(t, tc.acceptableSolutions.Dynamic.MPA, update.MPA)

				// Validate dynamic path "updates", which may be a removal or an addition
				pathUpdates := update.Paths
				for _, pathUpdate := range *pathUpdates {
					if tc.acceptableSolutions.Dynamic.PathUpdateToRmMap != nil {
						if removal, ok := tc.acceptableSolutions.Dynamic.PathUpdateToRmMap[pathUpdate]; ok {
							assert.Equal(t, removal.Paths, pathRm.Paths)
							continue
						}
					}

					if tc.acceptableSolutions.Dynamic.PathUpdateToPathAdditionMap != nil {
						if additions, ok := tc.acceptableSolutions.Dynamic.PathUpdateToPathAdditionMap[pathUpdate]; ok {
							assert.Equal(t, additions, add.Paths)
							continue
						}
					}
				}

				// Same goes for parent updates
				parentUpdates := update.Parents
				for _, parentUpdate := range *parentUpdates {
					if tc.acceptableSolutions.Dynamic.ParentUpdateToRmMap != nil {
						if removal, ok := tc.acceptableSolutions.Dynamic.ParentUpdateToRmMap[parentUpdate]; ok {
							assert.Contains(t, removal.Parents, parentRm.Parents)
							continue
						}
					}

					if tc.acceptableSolutions.Dynamic.ParentUpdateToParentAdditionMap != nil {
						if additions, ok := tc.acceptableSolutions.Dynamic.ParentUpdateToParentAdditionMap[parentUpdate]; ok {
							assert.Equal(t, additions, add.Parents)
							continue
						}
					}
				}

				return
			}
		})
	}
}
