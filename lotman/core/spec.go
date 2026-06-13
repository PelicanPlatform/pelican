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

// PathSpec is a path association for a lot. Recursive controls whether
// subdirectories belong to the lot; Exclude marks a path ignored by resolution.
type PathSpec struct {
	Path      string
	Recursive bool
	Exclude   bool
}

// MPA bundles a lot's management-policy attributes. GB axes use -1 for
// "unbounded"; MaxNumObjects uses -1 for "unbounded". A (creation, expiration,
// deletion) triple of all zeros denotes a non-expiring lot.
type MPA struct {
	DedicatedGB     float64
	OpportunisticGB float64
	MaxNumObjects   int64
	CreationTime    int64 // Unix ms
	ExpirationTime  int64 // Unix ms
	DeletionTime    int64 // Unix ms
}

// LotSpec is the input to AddLot.
type LotSpec struct {
	LotName string
	Owner   string
	Parents []string
	Paths   []PathSpec
	MPA     MPA
}

// LotUpdate is the input to UpdateLot. Nil fields are left unchanged. A non-nil
// MPA replaces the lot's management-policy attributes wholesale.
type LotUpdate struct {
	LotName string
	Owner   *string
	MPA     *MPA
}

// LotAddition is the input to AddToLot: parents and/or paths to add.
type LotAddition struct {
	LotName string
	Parents []string
	Paths   []PathSpec
}

// LotParentRemoval is the input to RemoveParents.
type LotParentRemoval struct {
	LotName string
	Parents []string
}

// LotPathRemoval is the input to RemovePaths.
type LotPathRemoval struct {
	LotName string
	Paths   []string
}

// RemoveOptions controls RemoveLot. When Recursive is true the lot and all its
// descendants are deleted; otherwise direct children are reparented to the
// removed lot's parents.
type RemoveOptions struct {
	Recursive bool
}

// LotView is the aggregate returned by GetLot.
type LotView struct {
	Lot
	Parents []string
	Paths   []PathSpec
	Usage   LotUsage
}

// mpaOf extracts the MPA from a Lot row.
func mpaOf(l Lot) MPA {
	return MPA{
		DedicatedGB:     l.DedicatedGB,
		OpportunisticGB: l.OpportunisticGB,
		MaxNumObjects:   l.MaxNumObjects,
		CreationTime:    l.CreationTime,
		ExpirationTime:  l.ExpirationTime,
		DeletionTime:    l.DeletionTime,
	}
}

// toPathSpecs converts persisted LotPath rows to PathSpec values.
func toPathSpecs(rows []LotPath) []PathSpec {
	out := make([]PathSpec, 0, len(rows))
	for _, r := range rows {
		out = append(out, PathSpec{Path: r.Path, Recursive: r.Recursive, Exclude: r.Exclude})
	}
	return out
}
