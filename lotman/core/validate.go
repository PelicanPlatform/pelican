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

// validateMPA enforces the sentinel rules for management-policy attributes:
//   - each axis is either >= 0 or exactly -1 (unbounded); values < -1 are invalid
//   - an unbounded dedicated_GB requires an unbounded opportunistic_GB
func validateMPA(mpa MPA) error {
	if mpa.DedicatedGB < -1 {
		return wrapf(ErrInvalidLot, "dedicated_GB %v is below the unbounded sentinel (-1)", mpa.DedicatedGB)
	}
	if mpa.OpportunisticGB < -1 {
		return wrapf(ErrInvalidLot, "opportunistic_GB %v is below the unbounded sentinel (-1)", mpa.OpportunisticGB)
	}
	if mpa.MaxNumObjects < -1 {
		return wrapf(ErrInvalidLot, "max_num_objects %d is below the unbounded sentinel (-1)", mpa.MaxNumObjects)
	}
	if IsUnboundedGB(mpa.DedicatedGB) && !IsUnboundedGB(mpa.OpportunisticGB) {
		return wrapf(ErrInvalidLot, "unbounded dedicated_GB requires unbounded opportunistic_GB (got %v)", mpa.OpportunisticGB)
	}
	return validateTimestamps(mpa.CreationTime, mpa.ExpirationTime, mpa.DeletionTime)
}

// validateTimestamps enforces the lifecycle-window rules: either all three are
// zero (non-expiring) or all three are positive and ordered
// creation <= expiration <= deletion. Any partial-zero combination is invalid.
func validateTimestamps(creationMs, expirationMs, deletionMs int64) error {
	if IsNonExpiring(creationMs, expirationMs, deletionMs) {
		return nil
	}
	if creationMs <= 0 || expirationMs <= 0 || deletionMs <= 0 {
		return wrapf(ErrInvalidLot,
			"lifecycle timestamps must be all-zero (non-expiring) or all-positive (got creation=%d expiration=%d deletion=%d)",
			creationMs, expirationMs, deletionMs)
	}
	if creationMs > expirationMs {
		return wrapf(ErrInvalidLot, "creation_time %d must not exceed expiration_time %d", creationMs, expirationMs)
	}
	if expirationMs > deletionMs {
		return wrapf(ErrInvalidLot, "expiration_time %d must not exceed deletion_time %d", expirationMs, deletionMs)
	}
	return nil
}

// validateLotSpec checks an AddLot input for structural validity.
func validateLotSpec(spec LotSpec) error {
	if spec.LotName == "" {
		return wrapf(ErrInvalidLot, "lot name is required")
	}
	if spec.Owner == "" {
		return wrapf(ErrInvalidLot, "owner is required for lot %q", spec.LotName)
	}
	if len(spec.Parents) == 0 {
		return wrapf(ErrInvalidLot, "lot %q must have at least one parent", spec.LotName)
	}
	seenParent := map[string]bool{}
	for _, p := range spec.Parents {
		if p == "" {
			return wrapf(ErrInvalidLot, "lot %q has an empty parent name", spec.LotName)
		}
		if seenParent[p] {
			return wrapf(ErrInvalidLot, "lot %q lists parent %q more than once", spec.LotName, p)
		}
		seenParent[p] = true
	}
	seenPath := map[string]bool{}
	for _, ps := range spec.Paths {
		if ps.Path == "" {
			return wrapf(ErrInvalidLot, "lot %q has an empty path", spec.LotName)
		}
		if seenPath[ps.Path] {
			return wrapf(ErrInvalidLot, "lot %q lists path %q more than once", spec.LotName, ps.Path)
		}
		seenPath[ps.Path] = true
	}
	return validateMPA(spec.MPA)
}
