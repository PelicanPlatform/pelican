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

package database

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"
)

// orphanedMembershipSweepInterval is how often to look for mirrored
// memberships no provider will ever refresh. The sweep is a single
// DELETE, so this is about how long an orphan may linger rather than
// about cost; an hour bounds it without the operator waiting for a
// restart.
const orphanedMembershipSweepInterval = time.Hour

// RetractOrphanedMirroredMemberships deletes mirrored memberships that
// came from a provider which is no longer the configured group source,
// and which that provider has not asserted within the TTL. It returns
// how many rows it removed.
//
// A mirrored row is normally retracted when the account is observed
// again and the provider no longer asserts it. Change
// Issuer.GroupSource and that never happens: the old provider is not
// consulted any more, and the account has to sign in through the NEW
// source before anything reconciles it — which for a password-only
// account under `oidc` or `github` is never. The row then lives
// forever, and if it is in a group that confers administrator
// privilege the account becomes unmanageable: the restricting guard
// keeps seeing the row and refuses a user-administrator, the latch
// cannot be cleared, the membership cannot be removed (it reads as
// provider-owned) and the group cannot be deleted while the
// configuration names it. Every one of those refusals is individually
// correct, which is what makes the state so hard to get out of.
//
// Two conditions, and both matter:
//
//   - The row's source is neither `pelican` nor the configured source.
//     Local memberships are this server's own. Rows from the ACTIVE
//     provider are left alone even when stale, because stale there
//     means "this account has not signed in lately", and the
//     share-owner clamp deliberately reads those rows so a share does
//     not die while its owner is away.
//   - The row is past the TTL. Immediately after a source change the
//     old rows are still fresh, so this leaves them a grace period in
//     which the account can sign in through the new source and have
//     them re-stamped, rather than cutting access off at the moment
//     the configuration changes.
func RetractOrphanedMirroredMemberships(db *gorm.DB) (int64, error) {
	if db == nil {
		return 0, nil
	}
	// The TTL is what "stale" means everywhere else. When it is
	// disabled, mirrored rows never grant anything, but they are still
	// read by the restricting guard — which is the half that locks an
	// account — so fall back to a short grace rather than skipping.
	grace := MirroredMembershipTTL()
	if grace <= 0 {
		grace = time.Hour
	}
	cutoff := time.Now().Add(-grace)

	active := ConfiguredGroupSource()
	q := db.Where("source <> ?", GroupSourcePelican).
		Where("asserted_at IS NULL OR asserted_at < ?", cutoff)
	if active.IsAsserted() {
		q = q.Where("source <> ?", active)
	}
	res := q.Delete(&GroupMember{})
	if res.Error != nil {
		return 0, res.Error
	}
	if res.RowsAffected > 0 {
		log.Infof("Retracted %d mirrored group membership(s) from a group source that is no longer configured; "+
			"the current source is %q", res.RowsAffected, active)
	}
	return res.RowsAffected, nil
}

// LaunchPeriodicOrphanedMembershipSweep runs the sweep at startup and
// then on a ticker. Startup alone is not enough: right after a source
// change the orphaned rows are still fresh, so the pass that matters is
// the one an hour or a TTL later, on a server nobody is going to
// restart again.
func LaunchPeriodicOrphanedMembershipSweep(ctx context.Context, egrp *errgroup.Group) {
	egrp.Go(func() error {
		sweep := func() {
			if _, err := RetractOrphanedMirroredMemberships(ServerDatabase); err != nil && ctx.Err() == nil {
				log.Warnf("Failed to retract orphaned mirrored group memberships: %v", err)
			}
		}
		sweep()
		ticker := time.NewTicker(orphanedMembershipSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sweep()
			case <-ctx.Done():
				log.Debug("Orphaned-membership sweep has shut down")
				return nil
			}
		}
	})
}
